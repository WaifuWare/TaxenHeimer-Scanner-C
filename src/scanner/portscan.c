/*
 * Kernel-based port prescan — non-blocking connect() with short timeout.
 *
 * Unlike synblast (raw SYN), this uses the kernel TCP stack, so it works
 * behind NAT. No CAP_NET_RAW required.
 *
 * Each IP gets a non-blocking connect(). If EPOLLOUT fires within the
 * timeout, the port is open → push IP to worker queue for full SLP.
 * Connections are RST'd on close (SO_LINGER) to skip TIME_WAIT.
 *
 * With 1024 concurrent probes and 100ms timeout: ~10-50k IPs/sec
 * depending on network conditions.
 */

#define _GNU_SOURCE
#include "scanner/portscan.h"
#include "scanner/hitqueue.h"
#include "core/settings.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

// ─── Configuration ───────────────────────────────────────────────────────────

#define PORTSCAN_CONCURRENT 1024       // simultaneous connect() probes
#define PORTSCAN_TIMEOUT_MS 300        // need SYN-ACK round-trip (covers most RTTs)

// Linux-specific: defer port allocation until connect()
#ifndef IP_BIND_ADDRESS_NO_PORT
#define IP_BIND_ADDRESS_NO_PORT 24
#endif

// ─── Slot state ──────────────────────────────────────────────────────────────

typedef struct {
    int  fd;
    char ip[16];
    struct timespec deadline;
} probe_slot_t;

// ─── Globals ─────────────────────────────────────────────────────────────────

static volatile sig_atomic_t *g_interrupt = NULL;
static uint64_t g_probed = 0;
static uint64_t g_open   = 0;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static inline int ps_interrupted(void) {
    return g_interrupt && *g_interrupt;
}

static inline long ts_diff_ms(const struct timespec *later,
                               const struct timespec *earlier) {
    return (later->tv_sec  - earlier->tv_sec)  * 1000L +
           (later->tv_nsec - earlier->tv_nsec) / 1000000L;
}

static void set_deadline(probe_slot_t *s) {
    clock_gettime(CLOCK_MONOTONIC, &s->deadline);
    s->deadline.tv_nsec += PORTSCAN_TIMEOUT_MS * 1000000L;
    if (s->deadline.tv_nsec >= 1000000000L) {
        s->deadline.tv_sec++;
        s->deadline.tv_nsec -= 1000000000L;
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

void portscan_init(void) {
    g_probed = 0;
    g_open   = 0;
}

void portscan_set_interrupt(volatile sig_atomic_t *flag) {
    g_interrupt = flag;
}

void portscan_get_stats(uint64_t *probed, uint64_t *open) {
    if (probed) *probed = g_probed;
    if (open)   *open   = g_open;
}

// ─── Main prescan function ──────────────────────────────────────────────────

int portscan_prescan(char ips[][16], int count, hit_queue_t *queue) {
    if (count <= 0) return 0;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) return -1;

    probe_slot_t *slots = calloc(PORTSCAN_CONCURRENT, sizeof(probe_slot_t));
    if (!slots) { close(epfd); return -1; }
    for (int i = 0; i < PORTSCAN_CONCURRENT; i++) slots[i].fd = -1;

    int next_ip    = 0;
    int in_flight  = 0;
    int total_open = 0;
    struct epoll_event events[256];

    while ((next_ip < count || in_flight > 0) && !ps_interrupted()) {
        // ── Fill empty slots with new connect() probes ──
        for (int i = 0; i < PORTSCAN_CONCURRENT && next_ip < count; i++) {
            if (slots[i].fd >= 0) continue;

            int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) { next_ip++; g_probed++; continue; }

            int one = 1;

            // Share source ports across destinations — avoids ephemeral exhaustion
            setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));

            // RST on close — skip TIME_WAIT, free port immediately
            struct linger lg = { .l_onoff = 1, .l_linger = 0 };
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

            // Disable Nagle (not strictly needed for connect-only, but cheap)
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port   = htons(MINECRAFT_PORT);
            inet_pton(AF_INET, ips[next_ip], &addr.sin_addr);

            strncpy(slots[i].ip, ips[next_ip], 15);
            slots[i].ip[15] = '\0';
            next_ip++;
            g_probed++;

            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
                errno != EINPROGRESS) {
                close(fd);
                continue;
            }

            slots[i].fd = fd;
            set_deadline(&slots[i]);

            struct epoll_event ev = {0};
            ev.events  = EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
            ev.data.u32 = (uint32_t)i;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                close(fd);
                slots[i].fd = -1;
                continue;
            }
            in_flight++;
        }

        if (in_flight == 0) break;

        // ── Compute wait from nearest deadline ──
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long min_wait = PORTSCAN_TIMEOUT_MS;
        for (int i = 0; i < PORTSCAN_CONCURRENT; i++) {
            if (slots[i].fd < 0) continue;
            long rem = ts_diff_ms(&slots[i].deadline, &now);
            if (rem < min_wait) min_wait = rem;
        }
        if (min_wait < 1) min_wait = 1;
        if (min_wait > 50) min_wait = 50;  // cap for responsive interrupt checks

        int n = epoll_wait(epfd, events, 256, (int)min_wait);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // ── Process events ──
        for (int i = 0; i < n; i++) {
            uint32_t idx = events[i].data.u32;
            if (idx >= (uint32_t)PORTSCAN_CONCURRENT) continue;
            probe_slot_t *s = &slots[idx];
            if (s->fd < 0) continue;

            int port_open = 0;

            if (events[i].events & EPOLLOUT) {
                int err = 0;
                socklen_t el = sizeof(err);
                if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 &&
                    err == 0) {
                    port_open = 1;
                }
            }

            if (port_open) {
                hitqueue_push(queue, s->ip);
                total_open++;
                g_open++;
            }

            epoll_ctl(epfd, EPOLL_CTL_DEL, s->fd, NULL);
            close(s->fd);
            s->fd = -1;
            in_flight--;
        }

        // ── Expire timed-out probes ──
        clock_gettime(CLOCK_MONOTONIC, &now);
        for (int i = 0; i < PORTSCAN_CONCURRENT; i++) {
            if (slots[i].fd < 0) continue;
            if (ts_diff_ms(&slots[i].deadline, &now) <= 0) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, slots[i].fd, NULL);
                close(slots[i].fd);
                slots[i].fd = -1;
                in_flight--;
            }
        }
    }

    // Cleanup remaining on interrupt
    for (int i = 0; i < PORTSCAN_CONCURRENT; i++) {
        if (slots[i].fd >= 0) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, slots[i].fd, NULL);
            close(slots[i].fd);
        }
    }
    free(slots);
    close(epfd);
    return total_open;
}
