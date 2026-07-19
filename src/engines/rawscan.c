/*
 * Raw socket scanner — userspace TCP/IP stack, optimized for throughput.
 *
 * Key optimizations over naive implementation:
 *   - Atomic in_flight counter (was O(TABLE_SIZE) scan per RX packet)
 *   - Lock-free freelist for slot allocation (was O(N) linear scan)
 *   - recvmmsg/sendmmsg to batch syscalls
 *   - Pre-built SYN template — patch 3 fields per IP, skip full construction
 *   - SIMD (AVX2/SSE2) for timeout expiry scan
 *   - Pre-parse IP strings to uint32 before main loop
 *   - Cache-line prefetch on conn lookup
 *
 * Requires: CAP_NET_RAW (or root), iptables RST suppression for source port range.
 */

#define _GNU_SOURCE
#include "engines/rawscan.h"
#include "engines/tcpkt.h"
#include "scanner/subnet_stats.h"
#include "protocol/packet.h"
#include "core/settings.h"
#include "core/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <stdatomic.h>
#include <immintrin.h>

// ─── Configuration ───────────────────────────────────────────────────────────

#define TABLE_SIZE    8192
#define PORT_BASE     40000
#define PORT_END      (PORT_BASE + TABLE_SIZE)
#define CONN_RX_CAP   8192
#define RX_BATCH      32       // recvmmsg batch size
#define TX_BATCH      64       // sendmmsg batch size

// ─── Connection state ────────────────────────────────────────────────────────

typedef enum {
    CS_FREE = 0,
    CS_SYN_SENT,
    CS_ESTABLISHED,
} conn_state_t;

typedef struct {
    uint8_t      state;       // conn_state_t — single byte for SIMD scanning
    uint8_t      mc_payload_len;
    uint16_t     timeout_ms;
    uint32_t     dst_ip;      // network byte order
    uint16_t     dst_port;    // host byte order
    uint16_t     _pad;
    uint32_t     our_seq;
    uint32_t     their_seq;
    uint32_t     our_next;
    uint64_t     deadline_ms; // monotonic ms
    char         ip_str[16];  // pre-formatted at connection start
    uint8_t      mc_payload[128]; // pre-built handshake+status
    int          rx_len;
    uint8_t      rx_buf[CONN_RX_CAP];
} conn_t;

// ─── Globals ─────────────────────────────────────────────────────────────────

static conn_t  *conns   = NULL;
static int      tx_fd   = -1;
static int      rx_fd   = -1;
static uint32_t local_ip = 0;
static int      if_index = 0;

// Atomic in-flight counter — no more O(N) counting
static atomic_int in_flight_count = 0;

// Lock-free freelist: stack of free slot indices
static int *freelist = NULL;
static atomic_int freelist_top = 0;

// Shadow state array — contiguous bytes, one per slot. Enables SIMD scanning.
// Kept in sync: set on state transitions, cleared on free.
static uint8_t *shadow_states __attribute__((aligned(32))) = NULL;

static volatile sig_atomic_t *g_rawscan_interrupt = NULL;

// ─── SYN template ────────────────────────────────────────────────────────────
static uint8_t syn_template[64];
static int     syn_template_len = 0;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static inline int raw_interrupted(void) {
    return g_rawscan_interrupt && *g_rawscan_interrupt;
}

void rawscan_set_interrupt(volatile sig_atomic_t *flag) {
    g_rawscan_interrupt = flag;
}

static inline uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

// ─── Freelist ────────────────────────────────────────────────────────────────

static inline int fl_pop(void) {
    int top = atomic_load_explicit(&freelist_top, memory_order_relaxed);
    while (top > 0) {
        if (atomic_compare_exchange_weak_explicit(&freelist_top, &top, top - 1,
                                                   memory_order_acquire,
                                                   memory_order_relaxed)) {
            return freelist[top - 1];
        }
    }
    return -1;
}

static inline void fl_push(int idx) {
    int top = atomic_fetch_add_explicit(&freelist_top, 1, memory_order_release);
    freelist[top] = idx;
}

static void conn_free(int idx) {
    conns[idx].state = CS_FREE;
    shadow_states[idx] = CS_FREE;
    conns[idx].rx_len = 0;
    fl_push(idx);
    atomic_fetch_sub_explicit(&in_flight_count, 1, memory_order_relaxed);
}

static inline void conn_set_state(int idx, uint8_t state) {
    conns[idx].state = state;
    shadow_states[idx] = state;
}

// ─── Packet helpers ──────────────────────────────────────────────────────────

static int build_mc_payload(uint8_t *buf, size_t cap, const char *ip, int port) {
    packet_t hs = {0};
    create_handshake_packet(&hs, ip, port, STATE_STATUS);
    packet_t sr = {0};
    create_status_request(&sr);
    if (hs.len + sr.len > cap) return -1;
    memcpy(buf, hs.data, hs.len);
    memcpy(buf + hs.len, sr.data, sr.len);
    return (int)(hs.len + sr.len);
}

static int try_parse_slp(conn_t *c, server_info_t *info) {
    if (c->rx_len <= 0) return 0;
    return parse_slp_frame(c->rx_buf, (size_t)c->rx_len, CONN_RX_CAP, info);
}

// ─── Raw send ────────────────────────────────────────────────────────────────

static int raw_send(const uint8_t *pkt, int len, uint32_t dst_ip) {
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = dst_ip;
    return (int)sendto(tx_fd, pkt, (size_t)len, 0,
                       (struct sockaddr *)&dst, sizeof(dst));
}

// Patch SYN template for a specific target. Much cheaper than full rebuild.
static int syn_patch_and_send(uint32_t dst_ip_net, uint16_t src_port, uint32_t seq) {
    uint8_t pkt[64];
    memcpy(pkt, syn_template, (size_t)syn_template_len);

    struct iphdr *ip = (struct iphdr *)pkt;
    ip->daddr = dst_ip_net;
    ip->check = 0;
    ip->check = tcpkt_checksum(ip, sizeof(struct iphdr));

    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    tcp->source = htons(src_port);
    tcp->seq = htonl(seq);
    tcp->check = 0;

    // Recompute TCP checksum (pseudo-header + tcp segment)
    struct {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t len;
    } __attribute__((packed)) pseudo = {
        ip->saddr, ip->daddr, 0, IPPROTO_TCP,
        htons((uint16_t)(syn_template_len - sizeof(struct iphdr)))
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

    return raw_send(pkt, syn_template_len, dst_ip_net);
}

// ─── RX processing ───────────────────────────────────────────────────────────

static void rx_process(const uint8_t *pkt, int pkt_len, scan_callback_t callback) {
    if (pkt_len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) return;

    const struct iphdr *ip = (const struct iphdr *)pkt;
    if (ip->protocol != IPPROTO_TCP) return;
    if (ip->daddr != local_ip) return;

    int ip_hdr_len = ip->ihl * 4;
    // ihl is a 4-bit field; attacker can send ihl<5 which puts the TCP header
    // inside the declared IP options region and confuses later offsets.
    if (ip_hdr_len < (int)sizeof(struct iphdr)) return;
    if (pkt_len < ip_hdr_len + (int)sizeof(struct tcphdr)) return;

    const struct tcphdr *tcp = (const struct tcphdr *)(pkt + ip_hdr_len);
    uint16_t dst_port = ntohs(tcp->dest);

    if (dst_port < PORT_BASE || dst_port >= PORT_END) return;
    int idx = dst_port - PORT_BASE;

    // Prefetch the connection entry while we decode the rest of the header
    __builtin_prefetch(&conns[idx], 1, 1);

    conn_t *c = &conns[idx];
    if (c->state == CS_FREE) return;
    if (ip->saddr != c->dst_ip) return;

    uint32_t their_seq = ntohl(tcp->seq);
    uint32_t their_ack = ntohl(tcp->ack_seq);
    int tcp_hdr_len = tcp->doff * 4;
    // A spoofed packet with doff=15 but short pkt_len would make data_off
    // exceed pkt_len, producing a negative data_len that, cast to size_t,
    // becomes a ~4 GB memcpy into c->rx_buf. Bound header length up-front.
    if (tcp_hdr_len < (int)sizeof(struct tcphdr)) return;
    int data_off = ip_hdr_len + tcp_hdr_len;
    if (data_off > pkt_len) return;
    int data_len = pkt_len - data_off;

    if (tcp->rst) {
        conn_free(idx);
        return;
    }

    if (c->state == CS_SYN_SENT && tcp->syn && tcp->ack) {
        if (their_ack != c->our_seq + 1) {
            conn_free(idx);
            return;
        }
        c->their_seq = their_seq + 1;
        c->our_seq += 1;

        // MC payload was pre-built at connection start — send it now
        uint8_t txbuf[256];
        int n = tcpkt_build_ack(txbuf, sizeof(txbuf),
                                local_ip, (uint16_t)(PORT_BASE + idx),
                                c->dst_ip, c->dst_port,
                                c->our_seq, c->their_seq,
                                c->mc_payload, (size_t)c->mc_payload_len, 1);
        if (n > 0) raw_send(txbuf, n, c->dst_ip);

        c->our_next = c->our_seq + (uint32_t)c->mc_payload_len;
        conn_set_state(idx, CS_ESTABLISHED);
        c->deadline_ms = mono_ms() + (uint64_t)c->timeout_ms;
        return;
    }

    if (c->state == CS_ESTABLISHED && data_len > 0) {
        // Belt-and-suspenders: even after the bounds above, use size_t math
        // for the capacity check so a future refactor that loosens the entry
        // checks can't regress to a signed-overflow overflow.
        if ((size_t)c->rx_len + (size_t)data_len <= (size_t)CONN_RX_CAP) {
            memcpy(c->rx_buf + c->rx_len, pkt + data_off, (size_t)data_len);
            c->rx_len += data_len;
        }
        c->their_seq = their_seq + (uint32_t)data_len;

        uint8_t txbuf[64];
        int n = tcpkt_build_ack(txbuf, sizeof(txbuf),
                                local_ip, (uint16_t)(PORT_BASE + idx),
                                c->dst_ip, c->dst_port,
                                c->our_next, c->their_seq,
                                NULL, 0, 0);
        if (n > 0) raw_send(txbuf, n, c->dst_ip);

        server_info_t info;
        memset(&info, 0, sizeof(info));
        memcpy(info.ip, c->ip_str, 16);
        info.ip_u32 = ntohl(c->dst_ip);
        info.port = c->dst_port;

        int pr = try_parse_slp(c, &info);
        if (pr == 1) {
            uint8_t rst[64];
            int rn = tcpkt_build_rst(rst, sizeof(rst),
                                     local_ip, (uint16_t)(PORT_BASE + idx),
                                     c->dst_ip, c->dst_port,
                                     c->our_next, c->their_seq);
            if (rn > 0) raw_send(rst, rn, c->dst_ip);
            if (callback) callback(&info);
            conn_free(idx);
        } else if (pr == -1) {
            conn_free(idx);
        }
        return;
    }

    if (c->state == CS_ESTABLISHED && tcp->fin) {
        server_info_t info;
        memset(&info, 0, sizeof(info));
        memcpy(info.ip, c->ip_str, 16);
        info.ip_u32 = ntohl(c->dst_ip);
        info.port = c->dst_port;
        try_parse_slp(c, &info);
        if (info.success && callback) callback(&info);
        conn_free(idx);
    }
}

// ─── SIMD timeout scan ──────────────────────────────────────────────────────
// Scan shadow_states[] in 32-byte AVX2 chunks (or 16-byte SSE2 fallback)
// to find non-FREE slots. Only those indices touch the conn_t array.
// This avoids cache-polluting the 8 KB conn structs for dead slots.

#if defined(__AVX2__)
#define SIMD_WIDTH 32
static void expire_timeouts(uint64_t now, scan_callback_t callback) {
    const __m256i zero = _mm256_setzero_si256();
    for (int base = 0; base < TABLE_SIZE; base += SIMD_WIDTH) {
        __m256i chunk = _mm256_load_si256((const __m256i *)(shadow_states + base));
        __m256i cmp = _mm256_cmpeq_epi8(chunk, zero);
        uint32_t mask = ~(uint32_t)_mm256_movemask_epi8(cmp); // bits set = non-FREE
        while (mask) {
            int bit = __builtin_ctz(mask);
            mask &= mask - 1;
            int idx = base + bit;
            conn_t *c = &conns[idx];
            if (now >= c->deadline_ms) {
                server_info_t info;
                memset(&info, 0, sizeof(info));
                memcpy(info.ip, c->ip_str, 16);
                info.ip_u32 = ntohl(c->dst_ip);
                info.port = c->dst_port;
                info.success = false;
                if (callback) callback(&info);
                conn_free(idx);
            }
        }
    }
}
#elif defined(__SSE2__)
#define SIMD_WIDTH 16
static void expire_timeouts(uint64_t now, scan_callback_t callback) {
    const __m128i zero = _mm_setzero_si128();
    for (int base = 0; base < TABLE_SIZE; base += SIMD_WIDTH) {
        __m128i chunk = _mm_load_si128((const __m128i *)(shadow_states + base));
        __m128i cmp = _mm_cmpeq_epi8(chunk, zero);
        uint32_t mask = ~(uint32_t)_mm_movemask_epi8(cmp) & 0xFFFF;
        while (mask) {
            int bit = __builtin_ctz(mask);
            mask &= mask - 1;
            int idx = base + bit;
            conn_t *c = &conns[idx];
            if (now >= c->deadline_ms) {
                server_info_t info;
                memset(&info, 0, sizeof(info));
                memcpy(info.ip, c->ip_str, 16);
                info.ip_u32 = ntohl(c->dst_ip);
                info.port = c->dst_port;
                info.success = false;
                if (callback) callback(&info);
                conn_free(idx);
            }
        }
    }
}
#else
// Scalar fallback with prefetch
static void expire_timeouts(uint64_t now, scan_callback_t callback) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (shadow_states[i] == CS_FREE) continue;
        if (i + 8 < TABLE_SIZE) __builtin_prefetch(&conns[i + 4], 0, 0);
        conn_t *c = &conns[i];
        if (now >= c->deadline_ms) {
            server_info_t info;
            memset(&info, 0, sizeof(info));
            memcpy(info.ip, c->ip_str, 16);
            info.port = c->dst_port;
            info.success = false;
            if (callback) callback(&info);
            conn_free(i);
        }
    }
}
#endif

// ─── Init / shutdown ─────────────────────────────────────────────────────────

int rawscan_init(void) {
    char ifname[IF_NAMESIZE] = {0};
    if (tcpkt_get_local_ip(&local_ip, ifname, sizeof(ifname)) < 0) {
        log_error("rawscan: cannot detect local IP");
        return -1;
    }
    char ipstr[16];
    inet_ntop(AF_INET, &local_ip, ipstr, sizeof(ipstr));
    log_info("rawscan: local IP %s on %s", ipstr, ifname);

    if_index = (int)if_nametoindex(ifname);
    if (if_index == 0) {
        log_error("rawscan: cannot resolve interface index for %s", ifname);
        return -1;
    }

    tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (tx_fd < 0) {
        log_error("rawscan: cannot create raw TX socket: %s (need CAP_NET_RAW)", strerror(errno));
        return -1;
    }
    int one = 1;
    setsockopt(tx_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // Increase TX buffer for burst sends
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(tx_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    rx_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (rx_fd < 0) {
        log_error("rawscan: cannot create raw RX socket: %s", strerror(errno));
        close(tx_fd); tx_fd = -1;
        return -1;
    }

    // Increase RX buffer to reduce drops under load
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(rx_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex  = if_index;
    if (bind(rx_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        log_error("rawscan: bind RX to %s failed: %s", ifname, strerror(errno));
        close(tx_fd); close(rx_fd);
        tx_fd = rx_fd = -1;
        return -1;
    }

    // Allocate connection table + SIMD shadow state array (32-byte aligned)
    conns = (conn_t *)calloc(TABLE_SIZE, sizeof(conn_t));
    if (!conns) { close(tx_fd); close(rx_fd); tx_fd = rx_fd = -1; return -1; }
    shadow_states = (uint8_t *)aligned_alloc(32, (size_t)TABLE_SIZE);
    if (!shadow_states) { free(conns); close(tx_fd); close(rx_fd); tx_fd = rx_fd = -1; return -1; }
    memset(shadow_states, CS_FREE, (size_t)TABLE_SIZE);

    // Initialize freelist — all slots free
    freelist = (int *)malloc(sizeof(int) * TABLE_SIZE);
    if (!freelist) { free(conns); free(shadow_states); close(tx_fd); close(rx_fd); tx_fd = rx_fd = -1; return -1; }
    for (int i = 0; i < TABLE_SIZE; i++) freelist[i] = i;
    atomic_store(&freelist_top, TABLE_SIZE);
    atomic_store(&in_flight_count, 0);

    // Build SYN template: fixed src_ip, placeholder dst/port/seq
    syn_template_len = tcpkt_build_syn(syn_template, sizeof(syn_template),
                                        local_ip, PORT_BASE,
                                        0x01010101, MINECRAFT_PORT, 0);
    if (syn_template_len <= 0) {
        log_error("rawscan: failed to build SYN template");
        free(conns); free(freelist);
        close(tx_fd); close(rx_fd);
        tx_fd = rx_fd = -1;
        return -1;
    }

    log_info("rawscan: initialized (%d slots, ports %d-%d, SYN template %d bytes)",
             TABLE_SIZE, PORT_BASE, PORT_END - 1, syn_template_len);
    return 0;
}

void rawscan_shutdown(void) {
    if (tx_fd >= 0) { close(tx_fd); tx_fd = -1; }
    if (rx_fd >= 0) { close(rx_fd); rx_fd = -1; }
    free(conns); conns = NULL;
    free(shadow_states); shadow_states = NULL;
    free(freelist); freelist = NULL;
}

// ─── Main batch loop ─────────────────────────────────────────────────────────

int rawscan_batch(char ips[][16], int count, scan_callback_t callback) {
    if (!conns || tx_fd < 0 || rx_fd < 0) return -1;

    // Pre-parse all IP strings to uint32 (network byte order)
    uint32_t *ip_addrs = (uint32_t *)malloc(sizeof(uint32_t) * (size_t)count);
    if (!ip_addrs) return -1;
    for (int i = 0; i < count; i++) {
        struct in_addr a;
        inet_pton(AF_INET, ips[i], &a);
        ip_addrs[i] = a.s_addr;
    }

    int next_ip = 0;

    // recvmmsg buffers
    struct mmsghdr rx_msgs[RX_BATCH];
    struct iovec   rx_iovs[RX_BATCH];
    uint8_t        rx_bufs[RX_BATCH][2048];
    memset(rx_msgs, 0, sizeof(rx_msgs));
    for (int i = 0; i < RX_BATCH; i++) {
        rx_iovs[i].iov_base = rx_bufs[i];
        rx_iovs[i].iov_len  = sizeof(rx_bufs[i]);
        rx_msgs[i].msg_hdr.msg_iov    = &rx_iovs[i];
        rx_msgs[i].msg_hdr.msg_iovlen = 1;
    }

    while ((next_ip < count || atomic_load(&in_flight_count) > 0) && !raw_interrupted()) {
        // ── TX phase: fill free slots with SYNs ──
        int sent = 0;
        // Cache a single clock sample for this TX burst — every connection
        // sent in the same batch shares the same monotonic "now", which is
        // what the TX→ACK deadline actually cares about. Saves TX_BATCH-1
        // clock_gettime syscalls (x2: seq + deadline) per burst.
        uint64_t tx_now = 0;
        while (next_ip < count && sent < TX_BATCH && !raw_interrupted()) {
            int idx = fl_pop();
            if (idx < 0) break;
            if (sent == 0) tx_now = mono_ms();

            conn_t *c = &conns[idx];
            uint32_t dst = ip_addrs[next_ip];
            c->dst_ip    = dst;
            c->dst_port  = MINECRAFT_PORT;
            c->our_seq   = (uint32_t)tx_now ^ ((uint32_t)idx << 16);
            c->rx_len    = 0;
            c->timeout_ms = (uint16_t)subnet_stats_get_timeout(ntohl(dst));
            c->deadline_ms = tx_now + (uint64_t)c->timeout_ms;

            // Pre-format IP string + MC payload at connection start
            inet_ntop(AF_INET, &dst, c->ip_str, sizeof(c->ip_str));
            int mc_len = build_mc_payload(c->mc_payload, sizeof(c->mc_payload),
                                          c->ip_str, MINECRAFT_PORT);
            c->mc_payload_len = mc_len > 0 ? (uint8_t)mc_len : 0;

            conn_set_state(idx, CS_SYN_SENT);
            atomic_fetch_add_explicit(&in_flight_count, 1, memory_order_relaxed);

            syn_patch_and_send(dst, (uint16_t)(PORT_BASE + idx), c->our_seq);
            sent++;
            next_ip++;
        }

        if (atomic_load(&in_flight_count) == 0) break;

        // ── RX phase: batch receive ──
        struct pollfd pfd = { .fd = rx_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 1);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            int n = recvmmsg(rx_fd, rx_msgs, RX_BATCH, MSG_DONTWAIT, NULL);
            for (int i = 0; i < n; i++) {
                rx_process(rx_bufs[i], (int)rx_msgs[i].msg_len, callback);
            }
        }

        // ── Expire timed-out connections ──
        expire_timeouts(mono_ms(), callback);
    }

    // Drain remaining on interrupt
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (shadow_states[i] != CS_FREE) {
            server_info_t info;
            memset(&info, 0, sizeof(info));
            memcpy(info.ip, conns[i].ip_str, 16);
            info.ip_u32 = ntohl(conns[i].dst_ip);
            info.port = conns[i].dst_port;
            info.success = false;
            if (callback) callback(&info);
            conns[i].state = CS_FREE;
            shadow_states[i] = CS_FREE;
            conns[i].rx_len = 0;
        }
    }
    atomic_store(&in_flight_count, 0);

    free(ip_addrs);
    return count;
}
