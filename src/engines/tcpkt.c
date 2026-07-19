#include "engines/tcpkt.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

uint16_t tcpkt_checksum(const void *data, size_t len) {
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)p;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// TCP pseudo-header checksum
static uint16_t tcp_checksum(uint32_t src, uint32_t dst,
                             const void *tcp_seg, size_t tcp_len) {
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t len;
    } __attribute__((packed)) pseudo;

    pseudo.src   = src;
    pseudo.dst   = dst;
    pseudo.zero  = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len   = htons((uint16_t)tcp_len);

    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)&pseudo;
    for (size_t i = 0; i < sizeof(pseudo) / 2; i++) sum += p[i];

    p = (const uint16_t *)tcp_seg;
    size_t rem = tcp_len;
    while (rem > 1) {
        sum += *p++;
        rem -= 2;
    }
    if (rem == 1) sum += *(const uint8_t *)p;

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static void fill_ip(struct iphdr *ip, uint32_t src, uint32_t dst, uint16_t total_len) {
    ip->ihl     = 5;
    ip->version = 4;
    ip->tos     = 0;
    ip->tot_len = htons(total_len);
    ip->id      = 0;
    ip->frag_off= htons(0x4000); // DF
    ip->ttl     = 64;
    ip->protocol= IPPROTO_TCP;
    ip->check   = 0;
    ip->saddr   = src;
    ip->daddr   = dst;
    ip->check   = tcpkt_checksum(ip, sizeof(*ip));
}

int tcpkt_build_syn(uint8_t *buf, size_t cap,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dst_ip, uint16_t dst_port,
                    uint32_t seq) {
    size_t ip_len = sizeof(struct iphdr);
    size_t tcp_len = sizeof(struct tcphdr) + 4; // +4 for MSS option
    size_t total = ip_len + tcp_len;
    if (cap < total) return -1;

    memset(buf, 0, total);
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + ip_len);

    fill_ip(ip, src_ip, dst_ip, (uint16_t)total);

    tcp->source  = htons(src_port);
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(seq);
    tcp->ack_seq = 0;
    tcp->doff    = (sizeof(struct tcphdr) + 4) / 4; // 6 (24 bytes)
    tcp->syn     = 1;
    tcp->window  = htons(65535);
    tcp->check   = 0;
    tcp->urg_ptr = 0;

    // MSS option: kind=2, len=4, mss=1460
    uint8_t *opts = buf + ip_len + sizeof(struct tcphdr);
    opts[0] = 2; opts[1] = 4;
    opts[2] = (1460 >> 8) & 0xFF;
    opts[3] = 1460 & 0xFF;

    tcp->check = tcp_checksum(src_ip, dst_ip, tcp, tcp_len);
    return (int)total;
}

int tcpkt_build_ack(uint8_t *buf, size_t cap,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dst_ip, uint16_t dst_port,
                    uint32_t seq, uint32_t ack,
                    const uint8_t *payload, size_t payload_len,
                    int psh) {
    size_t ip_len = sizeof(struct iphdr);
    size_t tcp_hdr = sizeof(struct tcphdr);
    size_t total = ip_len + tcp_hdr + payload_len;
    if (cap < total) return -1;

    memset(buf, 0, ip_len + tcp_hdr);
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + ip_len);

    fill_ip(ip, src_ip, dst_ip, (uint16_t)total);

    tcp->source  = htons(src_port);
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff    = tcp_hdr / 4;
    tcp->ack     = 1;
    if (psh) tcp->psh = 1;
    tcp->window  = htons(65535);

    if (payload_len > 0 && payload) {
        memcpy(buf + ip_len + tcp_hdr, payload, payload_len);
    }

    tcp->check = tcp_checksum(src_ip, dst_ip, tcp, tcp_hdr + payload_len);
    return (int)total;
}

int tcpkt_build_rst(uint8_t *buf, size_t cap,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dst_ip, uint16_t dst_port,
                    uint32_t seq, uint32_t ack) {
    size_t ip_len = sizeof(struct iphdr);
    size_t tcp_hdr = sizeof(struct tcphdr);
    size_t total = ip_len + tcp_hdr;
    if (cap < total) return -1;

    memset(buf, 0, total);
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + ip_len);

    fill_ip(ip, src_ip, dst_ip, (uint16_t)total);

    tcp->source  = htons(src_port);
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff    = tcp_hdr / 4;
    tcp->rst     = 1;
    tcp->ack     = 1;
    tcp->window  = 0;

    tcp->check = tcp_checksum(src_ip, dst_ip, tcp, tcp_hdr);
    return (int)total;
}

int tcpkt_get_local_ip(uint32_t *out_ip, char *ifname, size_t ifname_len) {
    // Parse default route from /proc/net/route
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;

    char line[256], best_iface[IF_NAMESIZE] = {0};
    int found = 0;
    // Skip header
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    while (fgets(line, sizeof(line), f)) {
        char iface[IF_NAMESIZE];
        unsigned long dest, gw, flags;
        // %15s matches IFNAMSIZ-1 to prevent stack overflow if /proc is
        // ever tampered with. Linux kernel enforces 15-byte iface names, so
        // this is defence-in-depth rather than a live vulnerability.
        if (sscanf(line, "%15s %lx %lx %lx", iface, &dest, &gw, &flags) < 4) continue;
        if (dest == 0 && (flags & 0x2)) { // UG = gateway
            strncpy(best_iface, iface, IF_NAMESIZE - 1);
            found = 1;
            break;
        }
    }
    fclose(f);
    if (!found) return -1;

    // Get IP of that interface
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, best_iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *out_ip = sin->sin_addr.s_addr; // network byte order
    if (ifname && ifname_len > 0) {
        strncpy(ifname, best_iface, ifname_len - 1);
        ifname[ifname_len - 1] = '\0';
    }
    return 0;
}
