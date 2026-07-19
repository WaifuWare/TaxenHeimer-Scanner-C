/*
 * io_uring SLP scanner — raw syscall implementation, no liburing dep.
 *
 * Each IP slot runs state machine:
 *   CONNECT → SEND(handshake+status) → RECV (loop until parseable) → CLOSE
 * SQEs carry user_data = (slot_idx << 4) | op_tag. CQE fan-in drives the
 * state machine, which queues the next op as a fresh SQE. Timeouts tracked
 * per-slot in userspace; CONNECT/SEND/RECV SQEs have no kernel timeout,
 * the scan loop expires stale slots after a bounded io_uring_enter wait.
 */

#define _GNU_SOURCE
#include "engines/iouring.h"
#include "scanner/subnet_stats.h"
#include "protocol/packet.h"
#include "core/settings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifndef IP_BIND_ADDRESS_NO_PORT
#define IP_BIND_ADDRESS_NO_PORT 24
#endif
#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT 18
#endif

#define IOU_ENTRIES       512
#define IOU_POOL          128
#define SLOT_RESP_CAP     32768

#define OP_CONNECT 1
#define OP_SEND    2
#define OP_RECV    3

// External parsers defined in scanner.c
int parse_varint_buf(const uint8_t *buf, size_t len, int32_t *out, int *consumed);
int parse_server_json_n(const char *json_buf, size_t json_len, server_info_t *info);
int parse_slp_frame(const uint8_t *buf, size_t len, size_t max_body_len, server_info_t *info);

// ─── Syscall wrappers ────────────────────────────────────────────────────────

static inline int sys_io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}
static inline int sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                                     unsigned flags, sigset_t *sig) {
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig, _NSIG / 8);
}

// ─── Ring state ──────────────────────────────────────────────────────────────

typedef struct {
    int ring_fd;

    // Submission queue
    unsigned *sq_head;
    unsigned *sq_tail;
    unsigned *sq_mask;
    unsigned *sq_array;
    struct io_uring_sqe *sqes;
    size_t sq_ring_sz;
    size_t sqe_sz;
    void *sq_ring_ptr;
    unsigned sq_entries;

    // Completion queue
    unsigned *cq_head;
    unsigned *cq_tail;
    unsigned *cq_mask;
    struct io_uring_cqe *cqes;
    size_t cq_ring_sz;
    void *cq_ring_ptr;
} iou_ring_t;

// One io_uring instance per worker thread. Rings aren't thread-safe:
// the SQ tail and CQ head are single-producer/single-consumer cursors,
// so sharing one ring across N scanner threads corrupts the ring state
// almost immediately. __thread gives each worker its own lazily-initialised
// ring; the probe ring created by iouring_init() just verifies kernel
// support and is torn down immediately.
static __thread iou_ring_t tl_ring;
static __thread int tl_ring_ready = 0;
static __thread unsigned tl_pending_submit = 0;  // SQEs queued since last enter
static int g_iouring_supported = 0;
static volatile sig_atomic_t *g_interrupt = NULL;

void iouring_set_interrupt(volatile sig_atomic_t *flag) { g_interrupt = flag; }

static inline int iou_interrupted(void) { return g_interrupt && *g_interrupt; }

// ─── Ring setup ──────────────────────────────────────────────────────────────

static int ring_setup(iou_ring_t *r, unsigned entries) {
    memset(r, 0, sizeof(*r));
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));

    int fd = sys_io_uring_setup(entries, &p);
    if (fd < 0) return -1;
    r->ring_fd = fd;
    r->sq_entries = p.sq_entries;

    size_t sring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);

    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        if (cring_sz > sring_sz) sring_sz = cring_sz;
        cring_sz = sring_sz;
    }

    void *sq_ptr = mmap(NULL, sring_sz, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
    if (sq_ptr == MAP_FAILED) { close(fd); return -1; }
    r->sq_ring_ptr = sq_ptr;
    r->sq_ring_sz = sring_sz;

    void *cq_ptr;
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        cq_ptr = sq_ptr;
    } else {
        cq_ptr = mmap(NULL, cring_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
        if (cq_ptr == MAP_FAILED) { munmap(sq_ptr, sring_sz); close(fd); return -1; }
    }
    r->cq_ring_ptr = cq_ptr;
    r->cq_ring_sz = cring_sz;

    r->sq_head = (unsigned *)((char *)sq_ptr + p.sq_off.head);
    r->sq_tail = (unsigned *)((char *)sq_ptr + p.sq_off.tail);
    r->sq_mask = (unsigned *)((char *)sq_ptr + p.sq_off.ring_mask);
    r->sq_array = (unsigned *)((char *)sq_ptr + p.sq_off.array);

    r->cq_head = (unsigned *)((char *)cq_ptr + p.cq_off.head);
    r->cq_tail = (unsigned *)((char *)cq_ptr + p.cq_off.tail);
    r->cq_mask = (unsigned *)((char *)cq_ptr + p.cq_off.ring_mask);
    r->cqes = (struct io_uring_cqe *)((char *)cq_ptr + p.cq_off.cqes);

    r->sqe_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    r->sqes = mmap(NULL, r->sqe_sz, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) {
        if (!(p.features & IORING_FEAT_SINGLE_MMAP))
            munmap(cq_ptr, cring_sz);
        munmap(sq_ptr, sring_sz);
        close(fd);
        return -1;
    }

    // Pre-populate sq_array to identity so we can write SQEs at tail & push.
    for (unsigned i = 0; i < p.sq_entries; i++) r->sq_array[i] = i;
    return 0;
}

static void ring_teardown(iou_ring_t *r) {
    if (!r->ring_fd) return;
    if (r->sqes && r->sqes != MAP_FAILED) munmap(r->sqes, r->sqe_sz);
    if (r->cq_ring_ptr && r->cq_ring_ptr != r->sq_ring_ptr)
        munmap(r->cq_ring_ptr, r->cq_ring_sz);
    if (r->sq_ring_ptr) munmap(r->sq_ring_ptr, r->sq_ring_sz);
    close(r->ring_fd);
    memset(r, 0, sizeof(*r));
}

static inline struct io_uring_sqe *ring_next_sqe(iou_ring_t *r) {
    unsigned head = __atomic_load_n(r->sq_head, __ATOMIC_ACQUIRE);
    unsigned tail = *r->sq_tail;
    if (tail - head >= r->sq_entries) return NULL;  // full
    return &r->sqes[tail & *r->sq_mask];
}

static inline void ring_submit_sqe(iou_ring_t *r) {
    unsigned tail = *r->sq_tail;
    __atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);
    tl_pending_submit++;
}

// ─── Slot state ──────────────────────────────────────────────────────────────

typedef enum {
    SL_EMPTY,
    SL_CONNECTING,
    SL_SENDING,
    SL_RECVING,
    SL_DONE,
} slot_state_t;

typedef struct {
    int fd;
    slot_state_t state;
    struct sockaddr_in addr;
    uint8_t out_buf[64];
    size_t  out_len;
    uint8_t *in_buf;
    size_t  in_len;
    struct timespec deadline;
    int timeout_ms;
    server_info_t info;
    uint32_t pending_ops;   // outstanding SQEs for this slot
    uint32_t gen;           // monotonic, bumped per slot_start via global
                            // counter so stale CQEs that arrive after a
                            // batch boundary never collide with a reused slot
} slot_t;

static uint32_t g_gen_counter = 0;

static long ts_diff_ms(const struct timespec *a, const struct timespec *b) {
    return (a->tv_sec - b->tv_sec) * 1000L + (a->tv_nsec - b->tv_nsec) / 1000000L;
}

static void slot_set_deadline(slot_t *s, int ms) {
    clock_gettime(CLOCK_MONOTONIC, &s->deadline);
    s->deadline.tv_sec += ms / 1000;
    s->deadline.tv_nsec += (ms % 1000) * 1000000L;
    if (s->deadline.tv_nsec >= 1000000000L) {
        s->deadline.tv_sec++;
        s->deadline.tv_nsec -= 1000000000L;
    }
}

// Prepare an SQE for CONNECT/SEND/RECV. Returns 0 on success, -1 if ring full.
static int submit_op(iou_ring_t *r, int op, int slot_idx, slot_t *s) {
    struct io_uring_sqe *sqe = ring_next_sqe(r);
    if (!sqe) return -1;
    memset(sqe, 0, sizeof(*sqe));
    // user_data: [gen:32][idx:24][op:8]. gen is a process-global monotonic
    // counter (u32) so stale CQEs arriving from a prior batch never collide
    // with a new slot at the same index.
    sqe->user_data = ((uint64_t)s->gen << 32) |
                     ((uint64_t)(slot_idx & 0xFFFFFF) << 8) |
                     (uint64_t)(op & 0xFF);
    sqe->fd = s->fd;
    switch (op) {
        case OP_CONNECT:
            sqe->opcode = IORING_OP_CONNECT;
            sqe->addr = (uint64_t)(uintptr_t)&s->addr;
            sqe->off  = sizeof(s->addr);
            break;
        case OP_SEND:
            sqe->opcode = IORING_OP_SEND;
            sqe->addr = (uint64_t)(uintptr_t)s->out_buf;
            sqe->len  = (unsigned)s->out_len;
            sqe->msg_flags = MSG_NOSIGNAL;
            break;
        case OP_RECV:
            sqe->opcode = IORING_OP_RECV;
            sqe->addr = (uint64_t)(uintptr_t)(s->in_buf + s->in_len);
            sqe->len  = (unsigned)(SLOT_RESP_CAP - s->in_len);
            break;
        default: return -1;
    }
    ring_submit_sqe(r);
    s->pending_ops++;
    return 0;
}

static int slot_start(slot_t *s, const char *ip, iou_ring_t *r, int idx) {
    memset(&s->info, 0, sizeof(s->info));
    strncpy(s->info.ip, ip, sizeof(s->info.ip) - 1);
    s->info.port = MINECRAFT_PORT;
    s->info.success = false;

    struct in_addr parsed;
    inet_pton(AF_INET, ip, &parsed);
    s->info.ip_u32 = ntohl(parsed.s_addr);
    s->timeout_ms = subnet_stats_get_timeout(s->info.ip_u32);
    s->in_len = 0;

    memset(&s->addr, 0, sizeof(s->addr));
    s->addr.sin_family = AF_INET;
    s->addr.sin_port = htons(MINECRAFT_PORT);
    s->addr.sin_addr.s_addr = htonl(s->info.ip_u32);

    packet_t hs = {0};
    create_handshake_packet(&hs, ip, MINECRAFT_PORT, STATE_STATUS);
    packet_t sr = {0};
    create_status_request(&sr);
    if (hs.len + sr.len > sizeof(s->out_buf)) return -1;
    memcpy(s->out_buf, hs.data, hs.len);
    memcpy(s->out_buf + hs.len, sr.data, sr.len);
    s->out_len = hs.len + sr.len;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(fd, (struct sockaddr *)&local, sizeof(local));
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    unsigned int ust = (unsigned int)s->timeout_ms;
    setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &ust, sizeof(ust));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    s->fd = fd;
    s->state = SL_CONNECTING;
    s->pending_ops = 0;
    s->gen = __atomic_add_fetch(&g_gen_counter, 1, __ATOMIC_RELAXED);
    slot_set_deadline(s, s->timeout_ms);

    if (submit_op(r, OP_CONNECT, idx, s) < 0) {
        close(fd);
        s->fd = -1;
        s->state = SL_EMPTY;
        return -1;
    }
    return 0;
}

static int slot_try_parse(slot_t *s) {
    return parse_slp_frame(s->in_buf, s->in_len, SLOT_RESP_CAP, &s->info);
}

static void slot_finalize(slot_t *s, scan_callback_t cb) {
    if (s->state == SL_EMPTY || s->state == SL_DONE) return;
    if (s->fd >= 0) { close(s->fd); s->fd = -1; }
    if (cb) cb(&s->info);
    s->state = SL_DONE;
}

// ─── Public API ──────────────────────────────────────────────────────────────

int iouring_init(void) {
    // Probe kernel support by setting up then tearing down a ring.
    iou_ring_t probe;
    if (ring_setup(&probe, IOU_ENTRIES) < 0) return -1;
    ring_teardown(&probe);
    g_iouring_supported = 1;
    return 0;
}

void iouring_shutdown(void) {
    // Per-thread rings leak at exit — the process is going away anyway, and
    // tracking them would need a global registry + lock. Fine for a CLI tool.
    g_iouring_supported = 0;
}

// Ensure this thread has a ring. Returns 0 on success, -1 on failure.
static int ensure_thread_ring(void) {
    if (tl_ring_ready) return 0;
    if (!g_iouring_supported) return -1;
    if (ring_setup(&tl_ring, IOU_ENTRIES) < 0) return -1;
    tl_ring_ready = 1;
    tl_pending_submit = 0;
    return 0;
}

int iouring_scan_batch(char ips[][16], int count, scan_callback_t callback) {
    if (count <= 0) return 0;
    if (ensure_thread_ring() < 0) return 0;

    tl_pending_submit = 0;

    slot_t *slots = calloc(IOU_POOL, sizeof(slot_t));
    if (!slots) return 0;
    for (int i = 0; i < IOU_POOL; i++) {
        slots[i].fd = -1;
        slots[i].state = SL_EMPTY;
        slots[i].in_buf = malloc(SLOT_RESP_CAP);
        if (!slots[i].in_buf) {
            for (int j = 0; j < i; j++) free(slots[j].in_buf);
            free(slots);
            return 0;
        }
    }

    int next_ip = 0;
    int in_flight = 0;

    while ((next_ip < count || in_flight > 0) && !iou_interrupted()) {
        // Fill empty slots
        for (int i = 0; i < IOU_POOL && next_ip < count; i++) {
            if (slots[i].state != SL_EMPTY && slots[i].state != SL_DONE) continue;
            if (slots[i].state == SL_DONE) { slots[i].state = SL_EMPTY; slots[i].in_len = 0; }
            if (slot_start(&slots[i], ips[next_ip], &tl_ring, i) == 0) {
                in_flight++;
            } else {
                memset(&slots[i].info, 0, sizeof(slots[i].info));
                strncpy(slots[i].info.ip, ips[next_ip], sizeof(slots[i].info.ip) - 1);
                slots[i].info.port = MINECRAFT_PORT;
                slots[i].info.success = false;
                if (callback) callback(&slots[i].info);
                slots[i].state = SL_EMPTY;
            }
            next_ip++;
        }

        if (in_flight == 0) break;

        // Enter ring. Submit every pending SQE (CONNECT from slot fills +
        // SEND/RECV follow-ups queued during the previous CQE reap) and
        // wait for ≥1 completion. Kernel returns the number of SQEs it
        // actually consumed; reset the counter either way since any
        // un-submitted entries will be picked up by the next enter.
        unsigned to_submit = tl_pending_submit;
        int ret = sys_io_uring_enter(tl_ring.ring_fd, to_submit, 1,
                                     IORING_ENTER_GETEVENTS, NULL);
        if (ret >= 0) {
            if ((unsigned)ret >= tl_pending_submit) tl_pending_submit = 0;
            else tl_pending_submit -= (unsigned)ret;
        } else if (errno != EINTR && errno != ETIME) {
            break;
        }

        // Reap completions
        unsigned head = *tl_ring.cq_head;
        unsigned tail = __atomic_load_n(tl_ring.cq_tail, __ATOMIC_ACQUIRE);
        while (head != tail) {
            struct io_uring_cqe *cqe = &tl_ring.cqes[head & *tl_ring.cq_mask];
            uint64_t ud = cqe->user_data;
            uint32_t gen = (uint32_t)(ud >> 32);
            int idx = (int)((ud >> 8) & 0xFFFFFF);
            int op  = (int)(ud & 0xFF);
            int res = cqe->res;

            if (idx >= 0 && idx < IOU_POOL) {
                slot_t *s = &slots[idx];
                // Stale CQE: slot was finalised + re-used before kernel drained
                // the canceled op. Drop silently — acting on it would either
                // double-close the new fd or spuriously advance the new op's
                // state machine.
                if (s->gen != gen) {
                    head++;
                    continue;
                }
                if (s->pending_ops > 0) s->pending_ops--;

                if (s->state == SL_DONE || s->state == SL_EMPTY) {
                    // Stale completion for a finalized slot — ignore
                } else if (res < 0) {
                    slot_finalize(s, callback);
                    in_flight--;
                } else {
                    switch (op) {
                        case OP_CONNECT:
                            s->state = SL_SENDING;
                            slot_set_deadline(s, s->timeout_ms);
                            if (submit_op(&tl_ring, OP_SEND, idx, s) < 0) {
                                slot_finalize(s, callback);
                                in_flight--;
                            }
                            break;
                        case OP_SEND:
                            if ((size_t)res < s->out_len) {
                                // Partial send — re-submit with remainder
                                memmove(s->out_buf, s->out_buf + res, s->out_len - (size_t)res);
                                s->out_len -= (size_t)res;
                                if (submit_op(&tl_ring, OP_SEND, idx, s) < 0) {
                                    slot_finalize(s, callback);
                                    in_flight--;
                                }
                            } else {
                                s->state = SL_RECVING;
                                slot_set_deadline(s, s->timeout_ms);
                                if (submit_op(&tl_ring, OP_RECV, idx, s) < 0) {
                                    slot_finalize(s, callback);
                                    in_flight--;
                                }
                            }
                            break;
                        case OP_RECV:
                            if (res == 0) {
                                slot_try_parse(s);
                                slot_finalize(s, callback);
                                in_flight--;
                            } else {
                                s->in_len += (size_t)res;
                                int pr = slot_try_parse(s);
                                if (pr == 1 || pr == -1) {
                                    slot_finalize(s, callback);
                                    in_flight--;
                                } else if (s->in_len >= SLOT_RESP_CAP) {
                                    slot_finalize(s, callback);
                                    in_flight--;
                                } else {
                                    if (submit_op(&tl_ring, OP_RECV, idx, s) < 0) {
                                        slot_finalize(s, callback);
                                        in_flight--;
                                    }
                                }
                            }
                            break;
                    }
                }
            }
            head++;
        }
        __atomic_store_n(tl_ring.cq_head, head, __ATOMIC_RELEASE);

        // Expire slots past deadline
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        for (int i = 0; i < IOU_POOL; i++) {
            slot_t *s = &slots[i];
            if (s->state == SL_EMPTY || s->state == SL_DONE) continue;
            if (ts_diff_ms(&s->deadline, &now) <= 0) {
                slot_finalize(s, callback);
                in_flight--;
            }
        }
    }

    // Drain remaining
    for (int i = 0; i < IOU_POOL; i++) {
        if (slots[i].state != SL_EMPTY && slots[i].state != SL_DONE) {
            slot_finalize(&slots[i], callback);
        }
        if (slots[i].fd >= 0) close(slots[i].fd);
        free(slots[i].in_buf);
    }
    free(slots);
    return count;
}
