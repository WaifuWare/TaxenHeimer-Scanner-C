/*
 * SYN prescan engine — blast SYNs, collect SYN-ACKs, push responsive IPs.
 *
 * Single-threaded (called from one prescan thread). No userspace TCP state
 * machine — just SYN → SYN-ACK → RST. Much simpler than rawscan.c.
 *
 * Port range: 50000-66383 (16384 slots), non-overlapping with rawscan (40000).
 * Requires CAP_NET_RAW.
 */

#define _GNU_SOURCE
#include "rawnet/synblast.h"
#include "rawnet/tcpkt.h"
#include "scanner/hitqueue.h"
#include "core/settings.h"
#include "core/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <poll.h>
#include <linux/filter.h>

// PACKET_IGNORE_OUTGOING: stop AF_PACKET from receiving our own outgoing SYNs.
// Available since Linux 6.2. Without it, our TX floods the RX buffer.
#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif

// ─── Configuration ───────────────────────────────────────────────────────────

#define SYNBLAST_TABLE   16384          // max IPs per chunk
#define SYNBLAST_PORT    50000          // source port base
#define SYN_RX_TIMEOUT   500           // ms to drain SYN-ACKs after last SYN
#define TX_BURST         512           // SYNs per burst before draining RX
#define RX_BATCH         32            // recvmmsg batch size

// ─── Per-slot state (minimal — no TCP data exchange) ─────────────────────────

typedef struct {
    uint32_t dst_ip;     // network byte order, 0 = unused
    uint32_t our_seq;    // for SYN-ACK validation
} syn_entry_t;

// ─── Globals ─────────────────────────────────────────────────────────────────

static syn_entry_t *entries  = NULL;
static int          tx_fd    = -1;
static int          rx_fd    = -1;
static uint32_t     local_ip = 0;
static int          if_index = 0;

static uint8_t      syn_template[64];
static int          syn_template_len = 0;

static volatile sig_atomic_t *g_interrupt = NULL;

// Diagnostic counters
static uint64_t g_syns_sent = 0;
static uint64_t g_syns_failed = 0;    // sendto errors
static uint64_t g_rx_packets = 0;     // total packets from recvmmsg
static uint64_t g_synacks_recv = 0;   // validated SYN-ACKs

// ─── Helpers ─────────────────────────────────────────────────────────────────

static inline int blast_interrupted(void) {
    return g_interrupt && *g_interrupt;
}

void synblast_set_interrupt(volatile sig_atomic_t *flag) {
    g_interrupt = flag;
}

static inline uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

// ─── Packet TX ───────────────────────────────────────────────────────────────

// Patch SYN template for target and send. Same approach as rawscan.c.
static int syn_send(uint32_t dst_ip_net, uint16_t src_port, uint32_t seq) {
    uint8_t pkt[64];
    memcpy(pkt, syn_template, (size_t)syn_template_len);

    struct iphdr *ip = (struct iphdr *)pkt;
    ip->daddr = dst_ip_net;
    ip->check = 0;
    ip->check = tcpkt_checksum(ip, sizeof(struct iphdr));

    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    tcp->source = htons(src_port);
    tcp->seq    = htonl(seq);
    tcp->check  = 0;

    // Recompute TCP checksum
    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } __attribute__((packed)) pseudo = {
        ip->saddr, ip->daddr, 0, IPPROTO_TCP,
        htons((uint16_t)(syn_template_len - (int)sizeof(struct iphdr)))
    };
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)&pseudo;
    for (int i = 0; i < 6; i++) sum += p[i];
    size_t tcp_len = (size_t)syn_template_len - sizeof(struct iphdr);
    p = (const uint16_t *)tcp;
    size_t rem = tcp_len;
    while (rem > 1) { sum += *p++; rem -= 2; }
    if (rem == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    tcp->check = (uint16_t)~sum;

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = dst_ip_net;
    int ret = (int)sendto(tx_fd, pkt, (size_t)syn_template_len, 0,
                          (struct sockaddr *)&dst, sizeof(dst));
    if (ret < 0) g_syns_failed++;
    return ret;
}

// Send RST to clean up remote half-open connection
static void send_rst(uint32_t dst_ip_net, uint16_t src_port,
                     uint32_t seq, uint32_t ack) {
    uint8_t buf[64];
    int n = tcpkt_build_rst(buf, sizeof(buf),
                            local_ip, src_port,
                            dst_ip_net, MINECRAFT_PORT,
                            seq, ack);
    if (n > 0) {
        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = dst_ip_net;
        sendto(tx_fd, buf, (size_t)n, 0,
               (struct sockaddr *)&dst, sizeof(dst));
    }
}

// ─── RX processing ───────────────────────────────────────────────────────────

// Drain RX socket for SYN-ACKs. Marks responded bitmap.
// Returns number of new responses found this call.
static int drain_rx(uint8_t *responded, int chunk_size) {
    int found = 0;

    // recvmmsg buffers
    struct mmsghdr msgs[RX_BATCH];
    struct iovec   iovs[RX_BATCH];
    uint8_t        bufs[RX_BATCH][128];  // SYN-ACK is small, 128 bytes enough
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < RX_BATCH; i++) {
        iovs[i].iov_base = bufs[i];
        iovs[i].iov_len  = sizeof(bufs[i]);
        msgs[i].msg_hdr.msg_iov    = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    while (!blast_interrupted()) {
        int n = recvmmsg(rx_fd, msgs, RX_BATCH, MSG_DONTWAIT, NULL);
        if (n <= 0) break;
        g_rx_packets += (uint64_t)n;

        for (int m = 0; m < n; m++) {
            int pkt_len = (int)msgs[m].msg_len;
            uint8_t *pkt = bufs[m];

            if (pkt_len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;

            const struct iphdr *ip = (const struct iphdr *)pkt;
            if (ip->protocol != IPPROTO_TCP) continue;
            if (ip->daddr != local_ip) continue;

            int ip_hdr_len = ip->ihl * 4;
            if (pkt_len < ip_hdr_len + (int)sizeof(struct tcphdr)) continue;

            const struct tcphdr *tcp = (const struct tcphdr *)(pkt + ip_hdr_len);
            uint16_t dst_port = ntohs(tcp->dest);

            // Check port is in our range for this chunk
            if (dst_port < SYNBLAST_PORT || dst_port >= SYNBLAST_PORT + chunk_size) continue;
            int idx = dst_port - SYNBLAST_PORT;

            // Must be SYN-ACK
            if (!tcp->syn || !tcp->ack) continue;

            // Validate source IP matches what we sent to
            if (entries[idx].dst_ip == 0 || entries[idx].dst_ip != ip->saddr) continue;

            // Validate ACK = our_seq + 1
            uint32_t their_ack = ntohl(tcp->ack_seq);
            if (their_ack != entries[idx].our_seq + 1) continue;

            // Send RST to clean up remote half-open connection
            uint32_t their_seq = ntohl(tcp->seq);
            send_rst(ip->saddr, dst_port, their_ack, their_seq + 1);

            if (!responded[idx]) {
                responded[idx] = 1;
                found++;
            }
        }
    }

    return found;
}

// ─── Init / shutdown ─────────────────────────────────────────────────────────

int synblast_init(void) {
    char ifname[IF_NAMESIZE] = {0};
    if (tcpkt_get_local_ip(&local_ip, ifname, sizeof(ifname)) < 0) {
        log_error("synblast: cannot detect local IP");
        return -1;
    }
    char ipstr[16];
    inet_ntop(AF_INET, &local_ip, ipstr, sizeof(ipstr));
    log_info("synblast: local IP %s on %s", ipstr, ifname);

    if_index = (int)if_nametoindex(ifname);
    if (if_index == 0) {
        log_error("synblast: cannot resolve interface index for %s", ifname);
        return -1;
    }

    // TX: raw IP socket with IP_HDRINCL
    tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (tx_fd < 0) {
        log_error("synblast: raw TX socket failed: %s (need CAP_NET_RAW)", strerror(errno));
        return -1;
    }
    int one = 1;
    setsockopt(tx_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(tx_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    // RX: AF_PACKET to see all incoming IP packets
    rx_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (rx_fd < 0) {
        log_error("synblast: raw RX socket failed: %s", strerror(errno));
        close(tx_fd); tx_fd = -1;
        return -1;
    }
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(rx_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex  = if_index;
    if (bind(rx_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        log_error("synblast: bind RX to %s failed: %s", ifname, strerror(errno));
        close(tx_fd); close(rx_fd);
        tx_fd = rx_fd = -1;
        return -1;
    }

    // Stop receiving our own outgoing packets (Linux 6.2+).
    // Without this, every SYN we send also lands in our RX buffer,
    // flooding it and causing real SYN-ACKs to be dropped.
    int ign = 1;
    if (setsockopt(rx_fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ign, sizeof(ign)) < 0) {
        log_warn("synblast: PACKET_IGNORE_OUTGOING not supported (kernel < 6.2), "
                 "RX buffer may fill with outgoing SYNs");
    }

    // BPF filter: accept only TCP packets with dest port in our range.
    // On SOCK_DGRAM, data starts at IP header (link-layer stripped).
    //
    // Offsets: IP protocol = byte 9, IP header length = 4*(byte[0]&0xF),
    //          TCP dest port = IHL + 2 (2 bytes, big-endian).
    struct sock_filter bpf_code[] = {
        // Load IP protocol (byte 9)
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
        // If not TCP (6), reject
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 6),
        // Load IP header length into X: X = 4 * (ip[0] & 0xF)
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
        // Load TCP dest port (at offset X + 2)
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 2),
        // If dest port < SYNBLAST_PORT, reject
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, SYNBLAST_PORT, 0, 3),
        // If dest port >= SYNBLAST_PORT + SYNBLAST_TABLE, reject
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, SYNBLAST_PORT + SYNBLAST_TABLE, 2, 0),
        // Accept
        BPF_STMT(BPF_RET | BPF_K, 0xFFFF),
        // Reject (shared target for all fail paths)
        BPF_STMT(BPF_RET | BPF_K, 0),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    struct sock_fprog bpf_prog = {
        .len = sizeof(bpf_code) / sizeof(bpf_code[0]),
        .filter = bpf_code,
    };
    if (setsockopt(rx_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog)) < 0) {
        log_warn("synblast: BPF filter attach failed: %s (RX may be noisy)", strerror(errno));
    }

    // Allocate entry table
    entries = calloc(SYNBLAST_TABLE, sizeof(syn_entry_t));
    if (!entries) {
        close(tx_fd); close(rx_fd);
        tx_fd = rx_fd = -1;
        return -1;
    }

    // Build SYN template
    syn_template_len = tcpkt_build_syn(syn_template, sizeof(syn_template),
                                        local_ip, SYNBLAST_PORT,
                                        0x01010101, MINECRAFT_PORT, 0);
    if (syn_template_len <= 0) {
        log_error("synblast: failed to build SYN template");
        free(entries); entries = NULL;
        close(tx_fd); close(rx_fd);
        tx_fd = rx_fd = -1;
        return -1;
    }

    log_info("synblast: initialized (%d slots, ports %d-%d, SYN template %d bytes)",
             SYNBLAST_TABLE, SYNBLAST_PORT, SYNBLAST_PORT + SYNBLAST_TABLE - 1,
             syn_template_len);
    return 0;
}

void synblast_get_stats(uint64_t *syns_sent, uint64_t *syns_failed,
                        uint64_t *rx_packets, uint64_t *synacks_recv) {
    if (syns_sent) *syns_sent = g_syns_sent;
    if (syns_failed) *syns_failed = g_syns_failed;
    if (rx_packets) *rx_packets = g_rx_packets;
    if (synacks_recv) *synacks_recv = g_synacks_recv;
}

void synblast_shutdown(void) {
    if (tx_fd >= 0) { close(tx_fd); tx_fd = -1; }
    if (rx_fd >= 0) { close(rx_fd); rx_fd = -1; }
    free(entries); entries = NULL;
}

// ─── Main prescan function ──────────────────────────────────────────────────

int synblast_prescan(char ips[][16], int count, hit_queue_t *queue) {
    if (!entries || tx_fd < 0 || rx_fd < 0) return -1;

    int total_hits = 0;

    // Process in chunks of SYNBLAST_TABLE
    for (int start = 0; start < count && !blast_interrupted(); start += SYNBLAST_TABLE) {
        int chunk = count - start;
        if (chunk > SYNBLAST_TABLE) chunk = SYNBLAST_TABLE;

        // Reset entries for this chunk
        memset(entries, 0, sizeof(syn_entry_t) * (size_t)chunk);

        // Responded bitmap
        uint8_t *responded = calloc((size_t)chunk, 1);
        if (!responded) continue;

        // Pre-parse IPs to network byte order
        uint32_t *ip_addrs = malloc(sizeof(uint32_t) * (size_t)chunk);
        if (!ip_addrs) { free(responded); continue; }
        for (int i = 0; i < chunk; i++) {
            struct in_addr a;
            inet_pton(AF_INET, ips[start + i], &a);
            ip_addrs[i] = a.s_addr;
        }

        // ── TX phase: send SYNs in bursts, drain RX between bursts ──
        for (int i = 0; i < chunk && !blast_interrupted(); ) {
            int burst_end = i + TX_BURST;
            if (burst_end > chunk) burst_end = chunk;

            for (; i < burst_end; i++) {
                uint32_t seq = (uint32_t)mono_ms() ^ ((uint32_t)i << 16);
                entries[i].dst_ip  = ip_addrs[i];
                entries[i].our_seq = seq;
                syn_send(ip_addrs[i], (uint16_t)(SYNBLAST_PORT + i), seq);
                g_syns_sent++;
            }

            // Drain early SYN-ACKs between TX bursts to avoid RX buffer overflow
            int drained = drain_rx(responded, chunk);
            g_synacks_recv += (uint64_t)drained;
            total_hits += drained;
        }

        // ── RX phase: wait for remaining SYN-ACKs ──
        // Cache mono_ms between poll() returns — it only needs to advance
        // after a wake-up, so one clock_gettime per poll iteration instead
        // of three (prior code called it in the while cond, remaining calc,
        // and the loop bottom).
        uint64_t now_ms = mono_ms();
        uint64_t deadline = now_ms + SYN_RX_TIMEOUT;
        while (now_ms < deadline && !blast_interrupted()) {
            struct pollfd pfd = { .fd = rx_fd, .events = POLLIN };
            long remaining = (long)(deadline - now_ms);
            if (remaining <= 0) break;
            int pr = poll(&pfd, 1, remaining > 50 ? 50 : (int)remaining);
            if (pr > 0) {
                int drained = drain_rx(responded, chunk);
                g_synacks_recv += (uint64_t)drained;
                total_hits += drained;
            }
            now_ms = mono_ms();
        }

        // ── Push responsive IPs to worker queue ──
        for (int i = 0; i < chunk && !blast_interrupted(); i++) {
            if (responded[i]) {
                hitqueue_push(queue, ips[start + i]);
            }
        }

        free(responded);
        free(ip_addrs);
    }

    return total_hits;
}
