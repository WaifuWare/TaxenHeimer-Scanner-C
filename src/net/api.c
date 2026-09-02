/*
 * API reporting implementation — Unix domain socket IPC to Go backend
 */

#include "net/api.h"
#include "core/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <arpa/inet.h>

// API concurrency limiting
static pthread_mutex_t api_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  api_cond = PTHREAD_COND_INITIALIZER;
static int api_concurrent = 0;
static bool api_available = true;

// Batch queue
#define BATCH_SIZE 256              // Hard cap — immediate dispatch when reached
#define BATCH_MIN_FLUSH 32          // Age-based flush requires at least this many
#define BATCH_MAX_AGE_MS 15000      // Flush partial batches after this long
#define FLUSHER_TICK_MS 1000        // How often the background thread wakes

typedef struct {
    server_info_t servers[BATCH_SIZE];
    int count;
    struct timespec first_added;
} batch_t;

static batch_t current_batch = {0};
static pthread_mutex_t batch_lock = PTHREAD_MUTEX_INITIALIZER;

// Background flusher
static pthread_t flusher_thread;
static pthread_cond_t flusher_cond = PTHREAD_COND_INITIALIZER;
static bool flusher_running = false;
static bool flusher_stop = false;

static void dispatch_current_batch_locked(void);  // forward decl

static long ms_since(const struct timespec *ts) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - ts->tv_sec) * 1000L +
           (now.tv_nsec - ts->tv_nsec) / 1000000L;
}

static void *flusher_thread_func(void *arg) {
    (void)arg;
    pthread_mutex_lock(&batch_lock);
    while (!flusher_stop) {
        // Timed wait — wakes on signal (shutdown) or after FLUSHER_TICK_MS.
        struct timespec abstime;
        clock_gettime(CLOCK_REALTIME, &abstime);
        abstime.tv_nsec += FLUSHER_TICK_MS * 1000000L;
        if (abstime.tv_nsec >= 1000000000L) {
            abstime.tv_sec++;
            abstime.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&flusher_cond, &batch_lock, &abstime);

        if (flusher_stop) break;
        // Flush when: batch is full enough, OR any batch has aged past max
        if (current_batch.count > 0 &&
            (current_batch.count >= BATCH_MIN_FLUSH ||
             ms_since(&current_batch.first_added) >= BATCH_MAX_AGE_MS)) {
            dispatch_current_batch_locked();
        }
    }
    pthread_mutex_unlock(&batch_lock);
    return NULL;
}

// Initialize API client
int api_init(void) {
    flusher_stop = false;
    if (pthread_create(&flusher_thread, NULL, flusher_thread_func, NULL) == 0) {
        flusher_running = true;
    } else {
        log_error("Failed to start API flusher thread");
    }
    return 0;
}

// Cleanup API client — signals flusher to wake immediately.
void api_cleanup(void) {
    if (!flusher_running) return;
    pthread_mutex_lock(&batch_lock);
    flusher_stop = true;
    pthread_cond_signal(&flusher_cond);
    pthread_mutex_unlock(&batch_lock);
    pthread_join(flusher_thread, NULL);
    flusher_running = false;
}

// Check if API is available
bool api_is_available(void) {
    return api_available;
}

// Acquire API slot (rate limiting) — blocks on condvar, no busy polling.
static void api_acquire_slot(void) {
    pthread_mutex_lock(&api_lock);
    while (api_concurrent >= MAX_CONCURRENT_API) {
        pthread_cond_wait(&api_cond, &api_lock);
    }
    api_concurrent++;
    pthread_mutex_unlock(&api_lock);
}

// Release API slot
static void api_release_slot(void) {
    pthread_mutex_lock(&api_lock);
    if (api_concurrent > 0) {
        api_concurrent--;
    }
    pthread_cond_signal(&api_cond);
    pthread_mutex_unlock(&api_lock);
}

// Determine software from version string
static void determine_software(const char *version_str, char *version_out,
                               char *software_out, size_t max_len) {
    const char *space = strchr(version_str, ' ');

    if (space) {
        size_t version_len = space - version_str;
        if (version_len >= max_len) version_len = max_len - 1;
        memcpy(version_out, version_str, version_len);
        version_out[version_len] = '\0';

        strncpy(software_out, space + 1, max_len - 1);
        software_out[max_len - 1] = '\0';
    } else {
        strncpy(version_out, version_str, max_len - 1);
        version_out[max_len - 1] = '\0';
        strncpy(software_out, "Vanilla", max_len - 1);
    }
}

// Read exactly n bytes from fd
static int read_all(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

// Send one framed batch over the IPC socket.
// Protocol: uint32 BE length + JSON body; reply is int32 BE success count (or -1).
// Returns the server-reported success count on success, or -1 on transport failure.
static int ipc_send_batch(const char *json_str, size_t json_len) {
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        log_error("IPC socket() failed: %s (fd exhaustion?)", strerror(errno));
        return -1;
    }

    struct timeval tv_io;
    tv_io.tv_sec = IPC_IO_TIMEOUT_MS / 1000;
    tv_io.tv_usec = (IPC_IO_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &tv_io, sizeof(tv_io));
    setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv_io, sizeof(tv_io));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("IPC connect(%s) failed: %s", IPC_SOCKET_PATH, strerror(errno));
        close(sfd);
        return -1;
    }

    uint32_t len_be = htonl((uint32_t)json_len);
    struct iovec iov[2];
    iov[0].iov_base = &len_be;
    iov[0].iov_len  = sizeof(len_be);
    iov[1].iov_base = (void *)json_str;
    iov[1].iov_len  = json_len;

    // Retry writev with advancing iov pointers until the frame is fully sent.
    // Handles any short-write case (including one split across the length
    // prefix boundary, which wasn't safe in the prior code's fallback).
    size_t iov_idx = 0;
    while (iov_idx < 2) {
        ssize_t w = writev(sfd, iov + iov_idx, 2 - (int)iov_idx);
        if (w < 0) {
            if (errno == EINTR) continue;
            log_error("IPC writev failed: %s", strerror(errno));
            close(sfd);
            return -1;
        }
        if (w == 0) {
            log_error("IPC writev returned 0");
            close(sfd);
            return -1;
        }
        size_t to_consume = (size_t)w;
        while (to_consume > 0 && iov_idx < 2) {
            if (to_consume >= iov[iov_idx].iov_len) {
                to_consume -= iov[iov_idx].iov_len;
                iov_idx++;
            } else {
                iov[iov_idx].iov_base = (uint8_t *)iov[iov_idx].iov_base + to_consume;
                iov[iov_idx].iov_len  -= to_consume;
                to_consume = 0;
            }
        }
    }

    uint32_t ack_be = 0;
    if (read_all(sfd, &ack_be, sizeof(ack_be)) < 0) {
        log_error("IPC read ack failed: %s", strerror(errno));
        close(sfd);
        return -1;
    }

    close(sfd);
    return (int)(int32_t)ntohl(ack_be);
}

// ── Manual JSON builder ──────────────────────────────────────────────────────
//
// The batch payload shape is fixed: `{"servers":[{...},{...},...]}`. cJSON
// allocates an object/array/string node per field — for a full 256-server
// batch that's ~2 KB of malloc calls before the first byte is serialised.
// A direct builder writes into a single growing buffer with inline JSON
// escaping. Measured ~8-10x faster per batch build + no heap fragmentation.

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    int    oom;
} jb_t;

static int jb_reserve(jb_t *b, size_t extra) {
    if (b->oom) return 0;
    if (b->len + extra + 1 <= b->cap) return 1;
    size_t need = b->len + extra + 1;
    size_t new_cap = b->cap ? b->cap : 4096;
    while (new_cap < need) {
        if (new_cap > ((size_t)-1) / 2) { b->oom = 1; return 0; }
        new_cap *= 2;
    }
    char *nb = realloc(b->buf, new_cap);
    if (!nb) { b->oom = 1; return 0; }
    b->buf = nb;
    b->cap = new_cap;
    return 1;
}

static void jb_putc(jb_t *b, char c) {
    if (jb_reserve(b, 1)) b->buf[b->len++] = c;
}

static void jb_raw(jb_t *b, const char *s, size_t n) {
    if (jb_reserve(b, n)) { memcpy(b->buf + b->len, s, n); b->len += n; }
}

static void jb_literal(jb_t *b, const char *s) {
    jb_raw(b, s, strlen(s));
}

// JSON-escape a C string into the builder. Must match RFC 8259 for any byte
// the backend might receive — control bytes below 0x20 need \uXXXX form,
// plus \" and \\. Non-ASCII (0x80-0xFF) is passed through so UTF-8 MOTDs
// travel intact.
static void jb_str(jb_t *b, const char *s) {
    if (!s) { jb_literal(b, "\"\""); return; }
    jb_putc(b, '"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c == '"')       jb_raw(b, "\\\"", 2);
        else if (c == '\\') jb_raw(b, "\\\\", 2);
        else if (c == '\b') jb_raw(b, "\\b", 2);
        else if (c == '\f') jb_raw(b, "\\f", 2);
        else if (c == '\n') jb_raw(b, "\\n", 2);
        else if (c == '\r') jb_raw(b, "\\r", 2);
        else if (c == '\t') jb_raw(b, "\\t", 2);
        else if (c < 0x20) {
            char tmp[8];
            int n = snprintf(tmp, sizeof(tmp), "\\u%04x", c);
            if (n > 0) jb_raw(b, tmp, (size_t)n);
        } else {
            jb_putc(b, (char)c);
        }
    }
    jb_putc(b, '"');
}

static void jb_int(jb_t *b, long v) {
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%ld", v);
    if (n > 0) jb_raw(b, tmp, (size_t)n);
}

// Build JSON from a batch and send over IPC. Returns accepted count or -1.
static int send_batch_ipc(const batch_t *batch) {
    // Pre-size with an estimate: roughly 512 B per server payload is generous
    // for typical SLPs. Reservations still grow if the guess is short.
    jb_t jb = {0};
    jb_reserve(&jb, 32 + (size_t)batch->count * 512);
    if (jb.oom) return -1;

    // Edition derived from the first server — every engine only emits its
    // own kind per batch, but we assert homogeneity below and scream to
    // the log if the invariant breaks (should be impossible today since
    // one engine is active per run).
    bool batch_bedrock = batch->count > 0 && batch->servers[0].bedrock;
    for (int i = 1; i < batch->count; i++) {
        if (batch->servers[i].bedrock != batch_bedrock) {
            log_error("IPC batch mixes java+bedrock — serialising as %s anyway",
                      batch_bedrock ? "bedrock" : "java");
            break;
        }
    }

    jb_literal(&jb, "{\"edition\":");
    jb_str(&jb, batch_bedrock ? "bedrock" : "java");
    jb_literal(&jb, ",\"servers\":[");
    for (int i = 0; i < batch->count; i++) {
        const server_info_t *s = &batch->servers[i];
        char version[256], software[256];
        determine_software(s->version, version, software, sizeof(version));

        if (i > 0) jb_putc(&jb, ',');
        jb_literal(&jb, "{\"ip\":");
        jb_str(&jb, s->ip);
        jb_literal(&jb, ",\"port\":");
        jb_int(&jb, s->port);
        jb_literal(&jb, ",\"edition\":");
        jb_str(&jb, s->bedrock ? "bedrock" : "java");
        jb_literal(&jb, ",\"motd\":");
        jb_str(&jb, s->motd[0] ? s->motd : "");
        jb_literal(&jb, ",\"version\":");
        jb_str(&jb, version);
        jb_literal(&jb, ",\"software\":");
        jb_str(&jb, software);
        jb_literal(&jb, ",\"protocol\":");
        jb_int(&jb, s->protocol);
        jb_literal(&jb, ",\"players_online\":");
        jb_int(&jb, s->players.online);
        jb_literal(&jb, ",\"players_max\":");
        jb_int(&jb, s->players.max);
        jb_literal(&jb, ",\"players_sample\":[");
        for (int j = 0; j < s->players.sample_count; j++) {
            if (j > 0) jb_putc(&jb, ',');
            jb_literal(&jb, "{\"name\":");
            jb_str(&jb, s->players.sample[j].name);
            jb_literal(&jb, ",\"id\":");
            jb_str(&jb, s->players.sample[j].id);
            jb_putc(&jb, '}');
        }
        jb_literal(&jb, "]");
        if (s->mod_info.mod_loader[0]) {
            jb_literal(&jb, ",\"mod_loader\":");
            jb_str(&jb, s->mod_info.mod_loader);
            jb_literal(&jb, ",\"mod_count\":");
            jb_int(&jb, s->mod_info.mod_count_total);
            jb_literal(&jb, ",\"mods\":[");
            for (int j = 0; j < s->mod_info.mod_count; j++) {
                if (j > 0) jb_putc(&jb, ',');
                jb_str(&jb, s->mod_info.mods[j]);
            }
            jb_literal(&jb, "]");
        }
        if (s->bedrock) {
            jb_literal(&jb, ",\"motd2\":");
            jb_str(&jb, s->motd2);
            jb_literal(&jb, ",\"gamemode\":");
            jb_str(&jb, s->gamemode);
            jb_literal(&jb, ",\"port_v4\":");
            jb_int(&jb, s->port_v4);
            jb_literal(&jb, ",\"port_v6\":");
            jb_int(&jb, s->port_v6);
            jb_literal(&jb, ",\"server_guid\":");
            jb_int(&jb, (long)s->server_guid);
        }
        jb_putc(&jb, '}');
    }
    jb_literal(&jb, "]}");

    if (jb.oom) {
        free(jb.buf);
        log_error("IPC batch build OOM");
        return -1;
    }
    // Guarantee NUL terminator for safety (not strictly needed since we pass
    // length to ipc_send_batch).
    if (jb_reserve(&jb, 0)) jb.buf[jb.len] = '\0';

    int accepted = ipc_send_batch(jb.buf, jb.len);
    if (accepted < 0) {
        log_error("IPC batch send failed (%d servers dropped)", batch->count);
    } else {
        log_info("Batch sent: %d/%d servers accepted", accepted, batch->count);
    }

    free(jb.buf);
    return accepted;
}

// Wrapper for background thread dispatch
static void *api_batch_thread(void *arg) {
    batch_t *batch = (batch_t *)arg;
    send_batch_ipc(batch);
    free(batch);
    api_release_slot();
    return NULL;
}

// Spawn a background thread to send `current_batch` and reset it.
// Caller must hold batch_lock. Does nothing if the batch is empty.
static void dispatch_current_batch_locked(void) {
    if (current_batch.count == 0) return;

    api_acquire_slot();
    batch_t *batch = malloc(sizeof(batch_t));
    if (!batch) {
        api_release_slot();
        return;
    }
    *batch = current_batch;
    current_batch.count = 0;
    memset(&current_batch.first_added, 0, sizeof(current_batch.first_added));

    pthread_t thread;
    if (pthread_create(&thread, NULL, api_batch_thread, batch) != 0) {
        api_release_slot();
        free(batch);
    } else {
        pthread_detach(thread);
    }
}

// Report server to API (batched)
int api_report_server(const server_info_t *info) {
    if (!info->success) return -1;
    if (info->version[0] == '\0') return -1;

    pthread_mutex_lock(&batch_lock);

    if (current_batch.count < BATCH_SIZE) {
        if (current_batch.count == 0) {
            clock_gettime(CLOCK_MONOTONIC, &current_batch.first_added);
        }
        current_batch.servers[current_batch.count] = *info;
        current_batch.count++;

        if (current_batch.count >= BATCH_SIZE) {
            dispatch_current_batch_locked();
        }
    }

    pthread_mutex_unlock(&batch_lock);
    return 0;
}

// Flush pending batch synchronously (call on shutdown).
// Sends inline — no detached thread, no race with program exit.
// Retries once on failure (Go backend may still be shutting down from same SIGINT).
void api_flush_batch(void) {
    pthread_mutex_lock(&batch_lock);
    if (current_batch.count == 0) {
        pthread_mutex_unlock(&batch_lock);
        return;
    }
    // Copy batch and clear, then release lock before blocking IPC send
    batch_t batch_copy = current_batch;
    current_batch.count = 0;
    memset(&current_batch.first_added, 0, sizeof(current_batch.first_added));
    pthread_mutex_unlock(&batch_lock);

    log_info("Flushing %d servers synchronously...", batch_copy.count);
    int accepted = send_batch_ipc(&batch_copy);

    if (accepted < 0) {
        // Retry once after short delay — backend may not have finished processing
        usleep(500 * 1000);
        log_info("Retrying flush...");
        accepted = send_batch_ipc(&batch_copy);
    }

    // Print to stderr so it survives TUI alt-screen cleanup
    if (accepted >= 0) {
        fprintf(stderr, "[flush] %d/%d servers sent to backend\n",
                accepted, batch_copy.count);
    } else {
        fprintf(stderr, "[flush] FAILED to send %d servers — backend unreachable\n",
                batch_copy.count);
    }
}

// Block until all in-flight batch threads finish sending.
void api_wait_pending(void) {
    pthread_mutex_lock(&api_lock);
    while (api_concurrent > 0) {
        // Use timed wait to avoid hanging forever if a send is stuck
        struct timespec abstime;
        clock_gettime(CLOCK_REALTIME, &abstime);
        abstime.tv_sec += 5;
        int rc = pthread_cond_timedwait(&api_cond, &api_lock, &abstime);
        if (rc != 0) break; // timeout — don't wait forever
    }
    pthread_mutex_unlock(&api_lock);
}
