/*
 * Scanner implementation
 */

#include "scanner.h"
#include "packet.h"
#include "../libs/cJSON/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>

// Linux-specific sockopts — define if headers lag
#ifndef IP_BIND_ADDRESS_NO_PORT
#define IP_BIND_ADDRESS_NO_PORT 24
#endif
#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT 18
#endif
#ifndef TCP_QUICKACK
#define TCP_QUICKACK 12
#endif

// Helper: Read varint with timeout (poll — no FD_SETSIZE ceiling)
static int read_varint_timeout(int sockfd, int32_t *value, int timeout_ms) {
    struct pollfd pfd = { .fd = sockfd, .events = POLLIN };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) return -1;
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;

    // Opportunistically flush pending ACK — reset each call (kernel clears it)
    int one = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));

    return read_varint(sockfd, value);
}

// Parse a Minecraft SLP JSON response into server_info_t. Sets info->success=true.
static int parse_server_json(const char *json_buf, server_info_t *info) {
    cJSON *json = cJSON_Parse(json_buf);
    if (!json) return 0;

    cJSON *desc_obj = cJSON_GetObjectItem(json, "description");
    if (desc_obj) {
        const char *motd_src = NULL;
        if (cJSON_IsString(desc_obj)) {
            motd_src = desc_obj->valuestring;
        } else if (cJSON_IsObject(desc_obj)) {
            cJSON *text = cJSON_GetObjectItem(desc_obj, "text");
            if (cJSON_IsString(text)) motd_src = text->valuestring;
        }
        if (motd_src) {
            size_t motd_len = strlen(motd_src);
            if (motd_len > 0 && motd_len < sizeof(info->motd)) {
                memcpy(info->motd, motd_src, motd_len);
                info->motd[motd_len] = '\0';
            }
        }
    }

    cJSON *version_obj = cJSON_GetObjectItem(json, "version");
    if (version_obj) {
        cJSON *name = cJSON_GetObjectItem(version_obj, "name");
        if (cJSON_IsString(name) && name->valuestring) {
            size_t version_len = strlen(name->valuestring);
            if (version_len > 0 && version_len < sizeof(info->version)) {
                memcpy(info->version, name->valuestring, version_len);
                info->version[version_len] = '\0';
            }
        }
        cJSON *protocol = cJSON_GetObjectItem(version_obj, "protocol");
        if (cJSON_IsNumber(protocol) && protocol->valueint > 0 && protocol->valueint < 1000) {
            info->protocol = protocol->valueint;
        }
    }

    cJSON *players_obj = cJSON_GetObjectItem(json, "players");
    if (players_obj) {
        cJSON *online = cJSON_GetObjectItem(players_obj, "online");
        if (cJSON_IsNumber(online) && online->valueint >= 0 && online->valueint < 1000000) {
            info->players.online = online->valueint;
        }
        cJSON *max = cJSON_GetObjectItem(players_obj, "max");
        if (cJSON_IsNumber(max) && max->valueint >= 0 && max->valueint < 1000000) {
            info->players.max = max->valueint;
        }
        cJSON *sample = cJSON_GetObjectItem(players_obj, "sample");
        if (cJSON_IsArray(sample)) {
            info->players.sample_count = 0;
            cJSON *player_item = NULL;
            cJSON_ArrayForEach(player_item, sample) {
                if (info->players.sample_count >= 10) break;
                cJSON *name = cJSON_GetObjectItem(player_item, "name");
                cJSON *id = cJSON_GetObjectItem(player_item, "id");
                if (cJSON_IsString(name) && name->valuestring) {
                    size_t name_len = strlen(name->valuestring);
                    if (name_len > 0 && name_len < sizeof(info->players.sample[0].name)) {
                        char *dst = info->players.sample[info->players.sample_count].name;
                        memcpy(dst, name->valuestring, name_len);
                        dst[name_len] = '\0';
                    }
                }
                if (cJSON_IsString(id) && id->valuestring) {
                    size_t id_len = strlen(id->valuestring);
                    if (id_len > 0 && id_len < sizeof(info->players.sample[0].id)) {
                        char *dst = info->players.sample[info->players.sample_count].id;
                        memcpy(dst, id->valuestring, id_len);
                        dst[id_len] = '\0';
                    }
                }
                info->players.sample_count++;
            }
        }
    }

    cJSON_Delete(json);
    info->success = true;
    return 1;
}

// Parse a varint from a byte buffer.
// Returns: 1 = parsed ok, 0 = need more bytes, -1 = malformed.
static int parse_varint_buf(const uint8_t *buf, size_t len, int32_t *out, int *consumed) {
    int32_t result = 0;
    int num_read = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = buf[i];
        result |= (int32_t)(b & 0x7F) << (7 * num_read);
        num_read++;
        if (!(b & 0x80)) {
            *out = result;
            *consumed = num_read;
            return 1;
        }
        if (num_read >= 5) return -1;
    }
    return 0;
}

// Scan a single IP address
int scan_ip(const char *ip, int port, server_info_t *info) {
    int sockfd = -1;
    struct sockaddr_in addr;
    struct timeval timeout;
    int ret = -1;
    
    // Initialize info
    memset(info, 0, sizeof(server_info_t));
    strncpy(info->ip, ip, sizeof(info->ip) - 1);
    info->port = port;
    info->success = false;
    
    // Create socket non-blocking + cloexec in one syscall (Linux 2.6.27+)
    sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sockfd < 0) {
        goto cleanup;
    }

    int one = 1;

    // Defer ephemeral port selection until connect() — share source ports across
    // distinct 4-tuples, sidesteps ephemeral exhaustion when scanning many IPs.
    setsockopt(sockfd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));

    // bind(port=0) is required for IP_BIND_ADDRESS_NO_PORT to take effect
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    bind(sockfd, (struct sockaddr *)&local, sizeof(local));  // best-effort

    // RST on close — skip TIME_WAIT, free local port immediately
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    // Kernel-enforced total connection timeout (ms)
    unsigned int usr_timeout = SOCKET_TIMEOUT_MS;
    setsockopt(sockfd, IPPROTO_TCP, TCP_USER_TIMEOUT, &usr_timeout, sizeof(usr_timeout));

    // Disable Nagle — small packets (handshake, status req) go out immediately
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    // Connect
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) {
            goto cleanup;
        }

        // Wait for connect with poll — no FD_SETSIZE limit
        struct pollfd pfd = { .fd = sockfd, .events = POLLOUT };
        int pr = poll(&pfd, 1, SOCKET_TIMEOUT_MS);
        if (pr <= 0) goto cleanup;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) goto cleanup;

        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            goto cleanup;
        }
    }

    // Clear O_NONBLOCK for the read phase — recv becomes blocking, bounded by
    // TCP_USER_TIMEOUT + SO_RCVTIMEO (belt and suspenders).
    fcntl(sockfd, F_SETFL, 0);

    // recv/send timeout
    timeout.tv_sec = SOCKET_TIMEOUT_MS / 1000;
    timeout.tv_usec = (SOCKET_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Force immediate ACKs on incoming data — kernel resets this per-recv
    setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
    
    // Start timing right after connection is established
    
    // Send handshake
    packet_t handshake = {0};
    create_handshake_packet(&handshake, ip, port, STATE_STATUS);
    if (send(sockfd, handshake.data, handshake.len, 0) < 0) {
        goto cleanup;
    }
    
    // Send status request
    packet_t status_req = {0};
    create_status_request(&status_req);
    
    if (send(sockfd, status_req.data, status_req.len, 0) < 0) {
        goto cleanup;
    }
    
    // Read response
    int32_t pkt_len, pkt_id;
    if (read_varint_timeout(sockfd, &pkt_len, SOCKET_TIMEOUT_MS) < 0) goto cleanup;
    if (read_varint_timeout(sockfd, &pkt_id, SOCKET_TIMEOUT_MS) < 0) goto cleanup;
    
    // Read JSON length and data
    int32_t json_len;
    if (read_varint_timeout(sockfd, &json_len, SOCKET_TIMEOUT_MS) < 0) goto cleanup;
    
    if (json_len > 0 && json_len < MAX_PACKET_SIZE) {
        char json_buf[MAX_PACKET_SIZE];
        ssize_t total = 0;
        while (total < json_len) {
            // SO_RCVTIMEO already enforces per-recv timeout
            ssize_t n = recv(sockfd, json_buf + total, json_len - total, 0);
            if (n <= 0) goto cleanup;
            total += n;
        }
        
        // End timing after receiving complete JSON
        
        json_buf[json_len] = '\0';

        if (parse_server_json(json_buf, info)) {
            ret = 0;
        }
    }
    
cleanup:
    if (sockfd >= 0) close(sockfd);
    return ret;
}

// Scan a batch of IPs
int scan_batch(char ips[][16], int count, server_info_t *results) {
    int found = 0;
    
    for (int i = 0; i < count; i++) {
        if (scan_ip(ips[i], MINECRAFT_PORT, &results[i]) == 0) {
            found++;
        }
    }
    
    return found;
}

// Shutdown flag wired by main — async loops poll it to abort promptly.
static volatile sig_atomic_t *g_interrupt_flag = NULL;

void scanner_set_interrupt_flag(volatile sig_atomic_t *flag) {
    g_interrupt_flag = flag;
}

static inline int scanner_interrupted(void) {
    return g_interrupt_flag && *g_interrupt_flag;
}

// ─── Async epoll-driven batch scanner ────────────────────────────────────────

// Max response buffer per slot. Covers typical SLP JSON including player sample.
#define SLOT_RESP_CAP 32768

typedef enum {
    SL_EMPTY,
    SL_CONNECTING,
    SL_WRITING,
    SL_READING,
    SL_FINISHED,   // terminal — callback already fired, awaits GC
} slot_state_t;

typedef struct {
    int fd;
    slot_state_t state;

    // Outgoing buffer: handshake + status request concatenated
    uint8_t out_buf[64];
    size_t out_len;
    size_t out_pos;

    // Incoming buffer
    uint8_t *in_buf;
    size_t in_len;

    struct timespec deadline;
    server_info_t info;
} slot_t;

static long ts_diff_ms(const struct timespec *later, const struct timespec *earlier) {
    return (later->tv_sec - earlier->tv_sec) * 1000L +
           (later->tv_nsec - earlier->tv_nsec) / 1000000L;
}

static void set_deadline(slot_t *s, int ms) {
    clock_gettime(CLOCK_MONOTONIC, &s->deadline);
    s->deadline.tv_sec += ms / 1000;
    s->deadline.tv_nsec += (ms % 1000) * 1000000L;
    if (s->deadline.tv_nsec >= 1000000000L) {
        s->deadline.tv_sec++;
        s->deadline.tv_nsec -= 1000000000L;
    }
}

// Mark slot finished, invoke callback, close fd, remove from epoll.
static void slot_finalize(slot_t *s, int epfd, scan_callback_t callback) {
    if (s->state == SL_EMPTY || s->state == SL_FINISHED) return;
    if (s->fd >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, s->fd, NULL);
        close(s->fd);
        s->fd = -1;
    }
    if (callback) callback(&s->info);
    s->state = SL_FINISHED;
}

// Start a new connection in this slot. Returns 0 on success, -1 on immediate failure.
static int slot_start(slot_t *s, const char *ip, int port, int epfd, uint32_t slot_idx) {
    memset(&s->info, 0, sizeof(s->info));
    strncpy(s->info.ip, ip, sizeof(s->info.ip) - 1);
    s->info.port = port;
    s->info.success = false;

    s->out_len = 0;
    s->out_pos = 0;
    s->in_len = 0;

    // Build handshake + status request into out_buf
    packet_t hs = {0};
    create_handshake_packet(&hs, ip, port, STATE_STATUS);
    packet_t sr = {0};
    create_status_request(&sr);
    if (hs.len + sr.len > sizeof(s->out_buf)) return -1;
    memcpy(s->out_buf, hs.data, hs.len);
    memcpy(s->out_buf + hs.len, sr.data, sr.len);
    s->out_len = hs.len + sr.len;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    bind(fd, (struct sockaddr *)&local, sizeof(local));

    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    unsigned int usr_timeout = SOCKET_TIMEOUT_MS;
    setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &usr_timeout, sizeof(usr_timeout));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    struct epoll_event ev = {0};
    ev.events = EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    ev.data.u32 = slot_idx;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(fd);
        return -1;
    }

    s->fd = fd;
    s->state = SL_CONNECTING;
    set_deadline(s, SOCKET_TIMEOUT_MS);
    return 0;
}

// Try to parse a complete SLP response from the slot's in_buf.
// Returns: 1 = parsed successfully (info filled), 0 = need more data, -1 = malformed.
static int slot_try_parse(slot_t *s) {
    if (s->in_len == 0) return 0;

    int32_t pkt_len;
    int consumed;
    int r = parse_varint_buf(s->in_buf, s->in_len, &pkt_len, &consumed);
    if (r <= 0) return r;
    if (pkt_len <= 0 || (size_t)pkt_len > SLOT_RESP_CAP) return -1;

    size_t header = (size_t)consumed;
    if (s->in_len < header + (size_t)pkt_len) return 0;  // body incomplete

    size_t body_start = header;
    size_t body_end = header + (size_t)pkt_len;
    size_t pos = body_start;

    int32_t pkt_id;
    r = parse_varint_buf(s->in_buf + pos, body_end - pos, &pkt_id, &consumed);
    if (r <= 0) return r < 0 ? -1 : 0;
    pos += consumed;
    if (pkt_id != 0x00) return -1;

    int32_t json_len;
    r = parse_varint_buf(s->in_buf + pos, body_end - pos, &json_len, &consumed);
    if (r <= 0) return r < 0 ? -1 : 0;
    pos += consumed;
    if (json_len <= 0 || (size_t)json_len > body_end - pos) return -1;

    char *tmp = malloc((size_t)json_len + 1);
    if (!tmp) return -1;
    memcpy(tmp, s->in_buf + pos, (size_t)json_len);
    tmp[json_len] = '\0';

    int ok = parse_server_json(tmp, &s->info);
    free(tmp);
    return ok ? 1 : -1;
}

// Advance a slot given an epoll event. Returns 1 if slot finalized this call.
static int slot_handle_event(slot_t *s, uint32_t events, int epfd, scan_callback_t cb) {
    if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        // On READING, HUP after full read is normal — try parse first
        if (s->state == SL_READING) {
            // fall through to drain+parse
        } else {
            int err = 0;
            socklen_t el = sizeof(err);
            getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &el);
            slot_finalize(s, epfd, cb);
            return 1;
        }
    }

    if (s->state == SL_CONNECTING && (events & EPOLLOUT)) {
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) {
            slot_finalize(s, epfd, cb);
            return 1;
        }
        s->state = SL_WRITING;
        set_deadline(s, SOCKET_TIMEOUT_MS);
    }

    if (s->state == SL_WRITING && (events & EPOLLOUT)) {
        while (s->out_pos < s->out_len) {
            ssize_t w = send(s->fd, s->out_buf + s->out_pos, s->out_len - s->out_pos, MSG_NOSIGNAL);
            if (w > 0) {
                s->out_pos += (size_t)w;
            } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            } else {
                slot_finalize(s, epfd, cb);
                return 1;
            }
        }
        if (s->out_pos >= s->out_len) {
            s->state = SL_READING;
            struct epoll_event ev = {0};
            ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
            ev.data.u32 = (uint32_t)(s - (slot_t *)NULL);  // placeholder overwritten below
            // The caller's epoll stored slot_idx in data.u32 originally; reuse it by
            // passing through events. We rebuild from the current event's data.
            // Simpler: re-register with same idx via a dedicated arg (handled by caller).
            // Workaround: use EPOLL_CTL_MOD with the slot's index baked into an
            // auxiliary table. For simplicity we store slot_idx in ev.data.u32 via
            // the outer loop's re-mod step after return.
            // → Just request MOD here with the idx reconstructed from the original
            //   event (events already delivered). We'll rely on caller to MOD.
            (void)ev;
            int one = 1;
            setsockopt(s->fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
            return 2;  // signal "needs EPOLL_CTL_MOD to EPOLLIN"
        }
    }

    if (s->state == SL_READING && (events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP))) {
        while (1) {
            if (s->in_len >= SLOT_RESP_CAP) {
                slot_finalize(s, epfd, cb);
                return 1;
            }
            ssize_t n = recv(s->fd, s->in_buf + s->in_len, SLOT_RESP_CAP - s->in_len, 0);
            if (n > 0) {
                s->in_len += (size_t)n;
                int one = 1;
                setsockopt(s->fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
            } else if (n == 0) {
                // peer closed — try final parse
                int r = slot_try_parse(s);
                (void)r;
                slot_finalize(s, epfd, cb);
                return 1;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                slot_finalize(s, epfd, cb);
                return 1;
            }
        }

        int r = slot_try_parse(s);
        if (r == 1 || r == -1) {
            slot_finalize(s, epfd, cb);
            return 1;
        }
        // r == 0: need more bytes, keep reading
    }

    return 0;
}

// Initialize socket pool (stub)
void scanner_init_pool(void) {
}

// Cleanup socket pool (stub)
void scanner_cleanup_pool(void) {
}

// Scan batch concurrently with callback using a single epoll loop.
int scan_batch_async(char ips[][16], int count, scan_callback_t callback) {
    if (count <= 0) return 0;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        // Fallback: serial scan
        for (int i = 0; i < count; i++) {
            server_info_t info;
            scan_ip(ips[i], MINECRAFT_PORT, &info);
            if (callback) callback(&info);
        }
        return count;
    }

    const int POOL = MAX_CONCURRENT_SCANS;
    slot_t *slots = calloc(POOL, sizeof(slot_t));
    if (!slots) { close(epfd); return 0; }
    for (int i = 0; i < POOL; i++) {
        slots[i].fd = -1;
        slots[i].state = SL_EMPTY;
        slots[i].in_buf = malloc(SLOT_RESP_CAP);
        if (!slots[i].in_buf) {
            for (int j = 0; j < i; j++) free(slots[j].in_buf);
            free(slots);
            close(epfd);
            return 0;
        }
    }

    int next_ip = 0;
    int in_flight = 0;
    struct epoll_event events[POOL];

    while (next_ip < count || in_flight > 0) {
        if (scanner_interrupted()) {
            // Abandon remaining IPs and tear down in-flight sockets fast.
            for (int i = 0; i < POOL; i++) {
                slot_t *s = &slots[i];
                if (s->state != SL_EMPTY && s->state != SL_FINISHED) {
                    slot_finalize(s, epfd, callback);
                }
            }
            in_flight = 0;
            break;
        }

        // Fill empty slots
        for (int i = 0; i < POOL && next_ip < count; i++) {
            if (slots[i].state != SL_EMPTY && slots[i].state != SL_FINISHED) continue;
            if (slots[i].state == SL_FINISHED) slots[i].state = SL_EMPTY;
            if (slot_start(&slots[i], ips[next_ip], MINECRAFT_PORT, epfd, (uint32_t)i) == 0) {
                in_flight++;
            } else {
                // Immediate failure: emit callback with failure, count it
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

        // Compute wait duration from nearest deadline
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long min_wait = SOCKET_TIMEOUT_MS;
        for (int i = 0; i < POOL; i++) {
            if (slots[i].state == SL_EMPTY || slots[i].state == SL_FINISHED) continue;
            long rem = ts_diff_ms(&slots[i].deadline, &now);
            if (rem < min_wait) min_wait = rem;
        }
        if (min_wait < 1) min_wait = 1;
        if (min_wait > SOCKET_TIMEOUT_MS) min_wait = SOCKET_TIMEOUT_MS;
        if (min_wait > 100) min_wait = 100;  // Cap so interrupt flag polls often

        int n = epoll_wait(epfd, events, POOL, (int)min_wait);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            uint32_t idx = events[i].data.u32;
            if (idx >= (uint32_t)POOL) continue;
            slot_t *s = &slots[idx];
            if (s->state == SL_EMPTY || s->state == SL_FINISHED) continue;

            int r = slot_handle_event(s, events[i].events, epfd, callback);
            if (r == 1) {
                in_flight--;
            } else if (r == 2) {
                // Transitioned to READING — MOD epoll interest to EPOLLIN
                struct epoll_event ev = {0};
                ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
                ev.data.u32 = idx;
                epoll_ctl(epfd, EPOLL_CTL_MOD, s->fd, &ev);
            }
        }

        // Expire slots past deadline
        clock_gettime(CLOCK_MONOTONIC, &now);
        for (int i = 0; i < POOL; i++) {
            slot_t *s = &slots[i];
            if (s->state == SL_EMPTY || s->state == SL_FINISHED) continue;
            if (ts_diff_ms(&s->deadline, &now) <= 0) {
                slot_finalize(s, epfd, callback);
                in_flight--;
            }
        }
    }

    for (int i = 0; i < POOL; i++) {
        if (slots[i].fd >= 0) close(slots[i].fd);
        free(slots[i].in_buf);
    }
    free(slots);
    close(epfd);

    return count;
}
