/*
 * API reporting implementation — Unix domain socket IPC to Go backend
 */

#include "net/api.h"
#include "core/log.h"
#include "cJSON.h"

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
        if (current_batch.count >= BATCH_MIN_FLUSH &&
            ms_since(&current_batch.first_added) >= BATCH_MAX_AGE_MS) {
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

// Write exactly n bytes to fd (handles short writes)
static int write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
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
    if (sfd < 0) return -1;

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

    size_t total_expected = sizeof(len_be) + json_len;
    ssize_t w = writev(sfd, iov, 2);
    if (w < 0) {
        log_error("IPC writev failed: %s", strerror(errno));
        close(sfd);
        return -1;
    }
    if ((size_t)w < total_expected) {
        // Short writev — finish the body with write_all
        size_t remaining = total_expected - (size_t)w;
        size_t body_written = (size_t)w >= sizeof(len_be) ? (size_t)w - sizeof(len_be) : 0;
        if ((size_t)w < sizeof(len_be)) {
            // length prefix was partially written; fall back to length re-send is awkward.
            // In practice a socket write on a just-connected stream socket won't split a 4-byte prefix.
            log_error("IPC writev short on length prefix");
            close(sfd);
            return -1;
        }
        if (write_all(sfd, json_str + body_written, remaining) < 0) {
            log_error("IPC write_all failed: %s", strerror(errno));
            close(sfd);
            return -1;
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

// Build JSON from a batch and send over IPC. Returns accepted count or -1.
static int send_batch_ipc(const batch_t *batch) {
    cJSON *root = cJSON_CreateObject();
    cJSON *servers_array = cJSON_CreateArray();

    for (int i = 0; i < batch->count; i++) {
        char version[256], software[256];
        determine_software(batch->servers[i].version, version, software, sizeof(version));

        cJSON *server = cJSON_CreateObject();
        cJSON_AddStringToObject(server, "ip", batch->servers[i].ip);
        cJSON_AddNumberToObject(server, "port", batch->servers[i].port);
        cJSON_AddStringToObject(server, "motd", batch->servers[i].motd[0] ? batch->servers[i].motd : "");
        cJSON_AddStringToObject(server, "version", version);
        cJSON_AddStringToObject(server, "software", software);
        cJSON_AddNumberToObject(server, "protocol", batch->servers[i].protocol);
        cJSON_AddNumberToObject(server, "players_online", batch->servers[i].players.online);
        cJSON_AddNumberToObject(server, "players_max", batch->servers[i].players.max);

        cJSON *sample = cJSON_CreateArray();
        for (int j = 0; j < batch->servers[i].players.sample_count; j++) {
            cJSON *player = cJSON_CreateObject();
            cJSON_AddStringToObject(player, "name", batch->servers[i].players.sample[j].name);
            cJSON_AddStringToObject(player, "id", batch->servers[i].players.sample[j].id);
            cJSON_AddItemToArray(sample, player);
        }
        cJSON_AddItemToObject(server, "players_sample", sample);

        cJSON_AddItemToArray(servers_array, server);
    }

    cJSON_AddItemToObject(root, "servers", servers_array);
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_str) {
        return -1;
    }

    int accepted = ipc_send_batch(json_str, strlen(json_str));
    if (accepted < 0) {
        log_error("IPC batch send failed (%d servers dropped)", batch->count);
    } else {
        log_info("Batch sent: %d/%d servers accepted", accepted, batch->count);
    }

    free(json_str);
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
    send_batch_ipc(&batch_copy);
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
