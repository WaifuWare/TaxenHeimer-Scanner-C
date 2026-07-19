/*
 * Bedrock (RakNet) Unconnected Ping scanner.
 *
 * Wire format:
 *   Ping (0x01): u8 id | i64 client_time | u8[16] magic | i64 client_guid
 *   Pong (0x1C): u8 id | i64 client_time | i64 server_guid | u8[16] magic
 *                | u16 strlen | char[strlen] info
 *
 * Info is semicolon-delimited:
 *   MCPE ; motd ; protocol ; version ; online ; max ; server_id ;
 *   motd_line2 ; gamemode ; gamemode_int ; port_v4 ; port_v6
 *
 * Scan loop: one UDP socket, blast pings for a batch, poll recvfrom with a
 * deadline, parse replies, fire callback. Non-responders get a failure
 * callback after the deadline elapses.
 */

#define _GNU_SOURCE
#include "engines/bedrock.h"
#include "core/settings.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// 16-byte RakNet "offline" magic
static const uint8_t RAKNET_MAGIC[16] = {
    0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
    0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78
};

#define BEDROCK_DEADLINE_MS 500
#define BEDROCK_RECV_BUF    2048
#define BEDROCK_TX_BATCH    64     // sendmmsg vlen — batches syscalls ~64×
#define BEDROCK_RX_BATCH    32     // recvmmsg vlen — drains up to 32 replies per call

static volatile sig_atomic_t *g_interrupt = NULL;
void bedrock_set_interrupt(volatile sig_atomic_t *flag) { g_interrupt = flag; }
static inline int br_interrupted(void) { return g_interrupt && *g_interrupt; }

static inline void wr_i64_be(uint8_t *p, int64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}

static inline int copy_safe(char *dst, size_t cap, const char *src, size_t len) {
    size_t n = len < cap - 1 ? len : cap - 1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (c < 0x20 && c != '\t') || c == 0x7F ? '?' : (char)c;
    }
    dst[n] = '\0';
    return (int)n;
}

// Split `str` (length n) by ';'. Return field count, pointers & lengths in out.
static int split_semicolons(const char *str, size_t n, const char **fields,
                            size_t *lens, int max_fields) {
    int count = 0;
    size_t start = 0;
    for (size_t i = 0; i <= n && count < max_fields; i++) {
        if (i == n || str[i] == ';') {
            fields[count] = str + start;
            lens[count] = i - start;
            count++;
            start = i + 1;
        }
    }
    return count;
}

static int parse_pong(const uint8_t *buf, size_t len, server_info_t *info) {
    // Minimum: 1 + 8 + 8 + 16 + 2 = 35
    if (len < 35 || buf[0] != 0x1C) return -1;
    if (memcmp(buf + 17, RAKNET_MAGIC, 16) != 0) return -1;

    // server_guid sits between client_time and the magic block (bytes 9..16).
    uint64_t guid = 0;
    for (int i = 0; i < 8; i++) guid = (guid << 8) | buf[9 + i];

    uint16_t slen = (uint16_t)((buf[33] << 8) | buf[34]);
    if ((size_t)35 + slen > len) return -1;
    const char *str = (const char *)(buf + 35);

    const char *fields[16];
    size_t flens[16];
    int nf = split_semicolons(str, slen, fields, flens, 16);
    if (nf < 6) return -1;

    info->bedrock = true;
    info->server_guid = guid;

    // MCPE ; motd ; protocol ; version ; online ; max ; server_id ;
    // motd2 ; gamemode ; gamemode_int ; port_v4 ; port_v6
    copy_safe(info->motd, sizeof(info->motd), fields[1], flens[1]);

    char tmp[32];
    size_t tn = flens[2] < sizeof(tmp) - 1 ? flens[2] : sizeof(tmp) - 1;
    memcpy(tmp, fields[2], tn); tmp[tn] = '\0';
    info->protocol = atoi(tmp);

    copy_safe(info->version, sizeof(info->version), fields[3], flens[3]);

    tn = flens[4] < sizeof(tmp) - 1 ? flens[4] : sizeof(tmp) - 1;
    memcpy(tmp, fields[4], tn); tmp[tn] = '\0';
    info->players.online = atoi(tmp);

    tn = flens[5] < sizeof(tmp) - 1 ? flens[5] : sizeof(tmp) - 1;
    memcpy(tmp, fields[5], tn); tmp[tn] = '\0';
    info->players.max = atoi(tmp);

    // Optional trailing fields — not every server sends them.
    if (nf > 7) copy_safe(info->motd2, sizeof(info->motd2), fields[7], flens[7]);
    if (nf > 8) copy_safe(info->gamemode, sizeof(info->gamemode), fields[8], flens[8]);
    if (nf > 10) {
        tn = flens[10] < sizeof(tmp) - 1 ? flens[10] : sizeof(tmp) - 1;
        memcpy(tmp, fields[10], tn); tmp[tn] = '\0';
        info->port_v4 = atoi(tmp);
    }
    if (nf > 11) {
        tn = flens[11] < sizeof(tmp) - 1 ? flens[11] : sizeof(tmp) - 1;
        memcpy(tmp, fields[11], tn); tmp[tn] = '\0';
        info->port_v6 = atoi(tmp);
    }

    info->players.sample_count = 0;
    info->success = true;
    return 0;
}

static long ts_diff_ms(const struct timespec *a, const struct timespec *b) {
    return (a->tv_sec - b->tv_sec) * 1000L + (a->tv_nsec - b->tv_nsec) / 1000000L;
}

// Drain state threaded through the two places we call recvmmsg: during
// the blast phase (to keep the kernel RX ring from overflowing) and
// during the post-blast deadline. Kept local to this TU — not part of
// the engine API.
typedef struct {
    int sock;
    struct mmsghdr *rx_msgs;
    uint8_t (*rx_buf)[BEDROCK_RECV_BUF];
    struct sockaddr_in *rx_addrs;
    uint32_t *ip_u32;
    int *responded;
    int count;
    scan_callback_t callback;
} drain_ctx_t;

// drain_rx pulls replies off the socket with recvmmsg until the queue
// drains (recvmmsg returns fewer than RX_BATCH). Each reply is parsed,
// matched back to its target by integer IP (much faster than the old
// per-reply strcmp scan), and dispatched via the callback. Returns
// once the RX ring is empty.
static void drain_rx(drain_ctx_t *c) {
    for (;;) {
        int n = recvmmsg(c->sock, c->rx_msgs, BEDROCK_RX_BATCH, 0, NULL);
        if (n <= 0) return;
        for (int k = 0; k < n; k++) {
            size_t rlen = (size_t)c->rx_msgs[k].msg_len;

            server_info_t info;
            memset(&info, 0, sizeof(info));
            if (parse_pong(c->rx_buf[k], rlen, &info) != 0) continue;

            uint32_t src_u32 = ntohl(c->rx_addrs[k].sin_addr.s_addr);
            inet_ntop(AF_INET, &c->rx_addrs[k].sin_addr, info.ip, sizeof(info.ip));
            info.port = BEDROCK_PORT;
            info.ip_u32 = src_u32;

            // Linear match against the pre-parsed uint32 target list.
            // int compare vs strcmp loop is ~20× cheaper per reply.
            for (int j = 0; j < c->count; j++) {
                if (!c->responded[j] && c->ip_u32[j] == src_u32) {
                    c->responded[j] = 1;
                    if (c->callback) c->callback(&info);
                    break;
                }
            }
        }
        if (n < BEDROCK_RX_BATCH) return;
    }
}

int bedrock_scan_batch(char ips[][16], int count, scan_callback_t callback) {
    if (count <= 0) return 0;

    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) return 0;

    // Larger kernel buffers so the TX ring absorbs a blast and the RX
    // ring absorbs the burst of replies without drops.
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int sndbuf = 2 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(sock, (struct sockaddr *)&local, sizeof(local));

    // Bedrock Unconnected Ping: id(1) + time(8) + magic(16) + client_guid(8) = 33B.
    // Template shared across all targets — sendmmsg points every iovec at this.
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t ctime = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
    uint8_t ping_full[33];
    ping_full[0] = 0x01;
    wr_i64_be(ping_full + 1, ctime);
    memcpy(ping_full + 9, RAKNET_MAGIC, 16);
    wr_i64_be(ping_full + 25, 0x0123456789ABCDEFLL);

    struct iovec tx_iov = { .iov_base = ping_full, .iov_len = sizeof(ping_full) };

    // Pre-parse IPs to uint32 + sockaddr once. inet_pton per IP was fine
    // in the old loop, but doing it once up-front lets reply matching
    // use integer compare instead of strcmp.
    struct sockaddr_in *addrs    = calloc((size_t)count, sizeof(*addrs));
    uint32_t           *ip_u32   = calloc((size_t)count, sizeof(*ip_u32));
    int                *responded = calloc((size_t)count, sizeof(*responded));
    if (!addrs || !ip_u32 || !responded) {
        free(addrs); free(ip_u32); free(responded);
        close(sock);
        return 0;
    }
    for (int i = 0; i < count; i++) {
        addrs[i].sin_family = AF_INET;
        addrs[i].sin_port   = htons(BEDROCK_PORT);
        if (inet_pton(AF_INET, ips[i], &addrs[i].sin_addr) != 1) {
            responded[i] = 1;  // skip malformed
            continue;
        }
        ip_u32[i] = ntohl(addrs[i].sin_addr.s_addr);
    }

    // RX batch — iovecs and headers point at per-slot buffers. Reused
    // across every drain call; recvmmsg updates msg_len and the
    // sockaddr in-place.
    static _Thread_local uint8_t       rx_buf[BEDROCK_RX_BATCH][BEDROCK_RECV_BUF];
    static _Thread_local struct iovec  rx_iov[BEDROCK_RX_BATCH];
    static _Thread_local struct mmsghdr rx_msgs[BEDROCK_RX_BATCH];
    static _Thread_local struct sockaddr_in rx_addrs[BEDROCK_RX_BATCH];
    for (int i = 0; i < BEDROCK_RX_BATCH; i++) {
        rx_iov[i].iov_base = rx_buf[i];
        rx_iov[i].iov_len  = BEDROCK_RECV_BUF;
        rx_msgs[i].msg_hdr.msg_iov        = &rx_iov[i];
        rx_msgs[i].msg_hdr.msg_iovlen     = 1;
        rx_msgs[i].msg_hdr.msg_name       = &rx_addrs[i];
        rx_msgs[i].msg_hdr.msg_namelen    = sizeof(rx_addrs[i]);
        rx_msgs[i].msg_hdr.msg_control    = NULL;
        rx_msgs[i].msg_hdr.msg_controllen = 0;
        rx_msgs[i].msg_hdr.msg_flags      = 0;
    }

    drain_ctx_t drain = {
        .sock      = sock,
        .rx_msgs   = rx_msgs,
        .rx_buf    = rx_buf,
        .rx_addrs  = rx_addrs,
        .ip_u32    = ip_u32,
        .responded = responded,
        .count     = count,
        .callback  = callback,
    };

    // Blast phase: sendmmsg in windows of TX_BATCH, drain RX between
    // windows so the kernel ring doesn't overflow while we're pushing.
    struct mmsghdr tx_msgs[BEDROCK_TX_BATCH];
    for (int i = 0; i < BEDROCK_TX_BATCH; i++) {
        tx_msgs[i].msg_hdr.msg_iov        = &tx_iov;
        tx_msgs[i].msg_hdr.msg_iovlen     = 1;
        tx_msgs[i].msg_hdr.msg_control    = NULL;
        tx_msgs[i].msg_hdr.msg_controllen = 0;
        tx_msgs[i].msg_hdr.msg_flags      = 0;
    }

    int i = 0;
    while (i < count && !br_interrupted()) {
        int end = i + BEDROCK_TX_BATCH;
        if (end > count) end = count;

        int tn = 0;
        for (int j = i; j < end; j++) {
            if (responded[j]) continue;  // malformed — skipped at parse
            tx_msgs[tn].msg_hdr.msg_name    = &addrs[j];
            tx_msgs[tn].msg_hdr.msg_namelen = sizeof(addrs[j]);
            tn++;
        }
        if (tn > 0) {
            // Drops on failure are acceptable — non-responders get a
            // failure callback later anyway. No per-message retry.
            (void)sendmmsg(sock, tx_msgs, (unsigned)tn, MSG_NOSIGNAL);
        }
        i = end;

        drain_rx(&drain);
    }

    // Post-blast: wait for stragglers until the deadline. poll gates
    // the drain so we don't busy-spin when the kernel buffer is empty.
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec  += BEDROCK_DEADLINE_MS / 1000;
    deadline.tv_nsec += (BEDROCK_DEADLINE_MS % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    while (!br_interrupted()) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long rem = ts_diff_ms(&deadline, &now);
        if (rem <= 0) break;
        if (rem > 100) rem = 100;

        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        int pr = poll(&pfd, 1, (int)rem);
        if (pr <= 0) continue;

        drain_rx(&drain);
    }

    // Failure callbacks for anyone that never replied.
    for (int j = 0; j < count; j++) {
        if (responded[j]) continue;
        server_info_t info;
        memset(&info, 0, sizeof(info));
        strncpy(info.ip, ips[j], sizeof(info.ip) - 1);
        info.port    = BEDROCK_PORT;
        info.success = false;
        info.ip_u32  = ip_u32[j];
        if (callback) callback(&info);
    }

    free(addrs);
    free(ip_u32);
    free(responded);
    close(sock);
    return count;
}
