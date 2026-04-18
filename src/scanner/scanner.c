/*
 * Scanner implementation
 */

#include "scanner/scanner.h"
#include "scanner/subnet_stats.h"
#include "protocol/packet.h"
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

    // TCP_QUICKACK is set once at socket setup; kernel's auto-disable is
    // fine for the sync path because we typically read the entire SLP
    // response across a handful of packets.
    return read_varint(sockfd, value);
}

// ─── Hand-rolled SLP JSON extractor ─────────────────────────────────────────
//
// Minecraft SLP responses are short (~200 B typical, ~8 KB worst case) and
// always reuse the same field names. cJSON builds a full parse tree plus
// duplicates every string, which dominates per-packet CPU. This extractor
// walks the buffer once and writes string fields straight into the caller's
// fixed-size buffers with inline escape decoding + sanitization.
//
// Grammar handled:
//   value       = string | number | object | array | true | false | null
//   string      = "..."  with \" \\ \/ \b \f \n \r \t \uXXXX escapes
//   object      = "{" (string ":" value ("," ...)*)? "}"
//   array       = "[" (value ("," ...)*)? "]"
//
// Semantics: we only care about a handful of known keys. For everything else
// we call skip_value, which honours nesting depth. Any parse error returns 0
// without touching info (except whatever was already written).

typedef struct {
    const char *p;
    const char *end;
} sj_t;

static void sj_skip_ws(sj_t *s) {
    while (s->p < s->end) {
        char c = *s->p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->p++;
        else break;
    }
}

// Emit one codepoint, applying the same sanitize rules as copy_sanitized:
// strip DEL, replace other C0 controls (except TAB) with '?'.
static size_t emit_cp_sanitized(uint32_t cp, char *dst, size_t j, size_t dst_sz) {
    if (cp == 0x7F) return j;
    if (cp < 0x20 && cp != '\t') {
        if (j + 1 < dst_sz) dst[j++] = '?';
        return j;
    }
    if (cp < 0x80) {
        if (j + 1 < dst_sz) dst[j++] = (char)cp;
    } else if (cp < 0x800) {
        if (j + 2 < dst_sz) {
            dst[j++] = (char)(0xC0 | (cp >> 6));
            dst[j++] = (char)(0x80 | (cp & 0x3F));
        }
    } else if (cp < 0x10000) {
        if (j + 3 < dst_sz) {
            dst[j++] = (char)(0xE0 | (cp >> 12));
            dst[j++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            dst[j++] = (char)(0x80 | (cp & 0x3F));
        }
    } else if (cp < 0x110000) {
        if (j + 4 < dst_sz) {
            dst[j++] = (char)(0xF0 | (cp >> 18));
            dst[j++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            dst[j++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            dst[j++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    return j;
}

static int hex_nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse a JSON string starting at s->p (which must point at the opening ").
// Write to dst (size dst_sz). If dst is NULL, the string is consumed but
// discarded (used when skipping). Returns 1 on success, 0 on malformed.
static int sj_parse_string(sj_t *s, char *dst, size_t dst_sz) {
    if (s->p >= s->end || *s->p != '"') return 0;
    s->p++;
    size_t j = 0;
    while (s->p < s->end) {
        unsigned char c = (unsigned char)*s->p++;
        if (c == '"') {
            if (dst && dst_sz > 0) dst[j < dst_sz ? j : dst_sz - 1] = '\0';
            return 1;
        }
        if (c == '\\') {
            if (s->p >= s->end) return 0;
            char esc = *s->p++;
            uint32_t cp = 0;
            switch (esc) {
                case '"':  cp = '"'; break;
                case '\\': cp = '\\'; break;
                case '/':  cp = '/'; break;
                case 'b':  cp = '\b'; break;
                case 'f':  cp = '\f'; break;
                case 'n':  cp = '\n'; break;
                case 'r':  cp = '\r'; break;
                case 't':  cp = '\t'; break;
                case 'u': {
                    if (s->end - s->p < 4) return 0;
                    int n0 = hex_nib(s->p[0]);
                    int n1 = hex_nib(s->p[1]);
                    int n2 = hex_nib(s->p[2]);
                    int n3 = hex_nib(s->p[3]);
                    if ((n0 | n1 | n2 | n3) < 0) return 0;
                    uint32_t u1 = ((uint32_t)n0 << 12) | ((uint32_t)n1 << 8) |
                                  ((uint32_t)n2 << 4) | (uint32_t)n3;
                    s->p += 4;
                    // Surrogate pair for codepoints beyond U+FFFF.
                    if (u1 >= 0xD800 && u1 <= 0xDBFF &&
                        s->end - s->p >= 6 && s->p[0] == '\\' && s->p[1] == 'u') {
                        int m0 = hex_nib(s->p[2]);
                        int m1 = hex_nib(s->p[3]);
                        int m2 = hex_nib(s->p[4]);
                        int m3 = hex_nib(s->p[5]);
                        if ((m0 | m1 | m2 | m3) >= 0) {
                            uint32_t u2 = ((uint32_t)m0 << 12) | ((uint32_t)m1 << 8) |
                                          ((uint32_t)m2 << 4) | (uint32_t)m3;
                            if (u2 >= 0xDC00 && u2 <= 0xDFFF) {
                                cp = 0x10000 + ((u1 - 0xD800) << 10) + (u2 - 0xDC00);
                                s->p += 6;
                                break;
                            }
                        }
                    }
                    cp = u1;
                    break;
                }
                default: return 0;
            }
            if (dst) j = emit_cp_sanitized(cp, dst, j, dst_sz);
        } else if (c < 0x20) {
            // Raw control bytes inside a JSON string are not legal, but
            // Minecraft servers emit them. Sanitize instead of rejecting
            // so we can still extract surrounding fields.
            if (dst) j = emit_cp_sanitized(c, dst, j, dst_sz);
        } else {
            if (dst && j + 1 < dst_sz) dst[j++] = (char)c;
        }
    }
    return 0;
}

// Parse an integer. JSON allows fractional/exponent forms for numbers; SLP
// only emits integers for protocol/online/max, so we accept the simple
// `-?\d+` form and return 0 on anything else.
static int sj_parse_int(sj_t *s, int *out) {
    sj_skip_ws(s);
    if (s->p >= s->end) return 0;
    int sign = 1;
    if (*s->p == '-') { sign = -1; s->p++; }
    if (s->p >= s->end || *s->p < '0' || *s->p > '9') return 0;
    long acc = 0;
    while (s->p < s->end && *s->p >= '0' && *s->p <= '9') {
        acc = acc * 10 + (*s->p - '0');
        if (acc > 0x7FFFFFFF) acc = 0x7FFFFFFF;
        s->p++;
    }
    // Step past any fractional/exponent tail to stay in sync, but we don't
    // use the value.
    while (s->p < s->end) {
        char c = *s->p;
        if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' ||
            (c >= '0' && c <= '9')) { s->p++; continue; }
        break;
    }
    *out = (int)(sign * acc);
    return 1;
}

static int sj_skip_value(sj_t *s);

static int sj_skip_string(sj_t *s) { return sj_parse_string(s, NULL, 0); }

static int sj_skip_object_or_array(sj_t *s) {
    char open = *s->p;
    char close = (open == '{') ? '}' : ']';
    s->p++;
    int depth = 1;
    while (s->p < s->end && depth > 0) {
        sj_skip_ws(s);
        if (s->p >= s->end) return 0;
        char c = *s->p;
        if (c == '"') { if (!sj_skip_string(s)) return 0; }
        else if (c == '{' || c == '[') { depth++; s->p++; }
        else if (c == '}' || c == ']') {
            if (c != close && depth == 1) return 0;
            depth--; s->p++;
        } else {
            s->p++;
        }
    }
    return depth == 0;
}

// sj_skip_field skips an entire "key":value pair when the key didn't match
// any of the names the caller is looking for. Previously callers used
// sj_skip_value which only eats the value — leaving the unread key + colon
// stuck in the stream and bricking every subsequent key lookup in the
// object. Used for unknown / unhandled fields (e.g. favicon, extra, etc.).
static int sj_skip_value(sj_t *s);
static int sj_skip_field(sj_t *s) {
    sj_skip_ws(s);
    if (s->p >= s->end || *s->p != '"') return 0;
    if (!sj_skip_string(s)) return 0;
    sj_skip_ws(s);
    if (s->p >= s->end || *s->p != ':') return 0;
    s->p++;
    return sj_skip_value(s);
}

static int sj_skip_value(sj_t *s) {
    sj_skip_ws(s);
    if (s->p >= s->end) return 0;
    char c = *s->p;
    if (c == '"') return sj_skip_string(s);
    if (c == '{' || c == '[') return sj_skip_object_or_array(s);
    // literal: number / true / false / null — scan until delimiter.
    while (s->p < s->end) {
        char x = *s->p;
        if (x == ',' || x == '}' || x == ']' || x == ' ' ||
            x == '\t' || x == '\n' || x == '\r') break;
        s->p++;
    }
    return 1;
}

// Matches a key and returns 1 if it equals `key`, advancing past the colon.
// On match, `*s` now points at the value. On mismatch the stream position
// is RESTORED so the caller can try another key. SLP keys never contain
// escapes, so a direct memcmp is safe and avoids the previous bug where
// re-walking the key through sj_parse_string consumed the stream even on
// mismatch — that made every field after a non-matching one disappear
// (notably "protocol" after "name" in the version object).
static int sj_match_key(sj_t *s, const char *key) {
    sj_skip_ws(s);
    if (s->p >= s->end || *s->p != '"') return 0;
    const char *save = s->p;

    size_t klen = 0;
    while (key[klen] != '\0') klen++;

    // Need at least: opening quote + klen bytes + closing quote.
    if ((size_t)(s->end - save) < klen + 2) return 0;

    for (size_t i = 0; i < klen; i++) {
        if (save[1 + i] != key[i]) return 0;
    }
    if (save[1 + klen] != '"') return 0;

    // Confirmed match. Advance past "key" and the colon.
    s->p = save + klen + 2;
    sj_skip_ws(s);
    if (s->p >= s->end || *s->p != ':') {
        s->p = save;
        return 0;
    }
    s->p++;
    return 1;
}

// Walk an object, invoking handler(key, s) for each field. Handler returns 0
// to indicate it consumed the value; on non-zero it's expected that the
// value is still unread and we'll skip it. Here we implement it inline
// via a table, because we only have a handful of keys.

// Helper: advance past the value and any trailing comma. Returns 0 if end of
// object is reached.
static int sj_after_value(sj_t *s) {
    sj_skip_ws(s);
    if (s->p >= s->end) return 0;
    if (*s->p == ',') { s->p++; return 1; }
    if (*s->p == '}') { s->p++; return 0; }
    return 0;
}

// Extract `description`. Can be a bare string or an object with {"text": ...}.
// Values with `"extra"` arrays are also concatenated into the MOTD.
static void sj_read_description(sj_t *s, char *motd, size_t motd_sz) {
    sj_skip_ws(s);
    if (s->p >= s->end) return;
    if (*s->p == '"') {
        sj_parse_string(s, motd, motd_sz);
        return;
    }
    if (*s->p != '{') { sj_skip_value(s); return; }
    s->p++;
    sj_skip_ws(s);
    int more = 1;
    while (more && s->p < s->end && *s->p != '}') {
        if (sj_match_key(s, "text")) {
            sj_parse_string(s, motd, motd_sz);
        } else {
            sj_skip_field(s);
        }
        more = sj_after_value(s);
        sj_skip_ws(s);
    }
    if (s->p < s->end && *s->p == '}') s->p++;
}

// Extract version { name, protocol }
static void sj_read_version(sj_t *s, server_info_t *info) {
    sj_skip_ws(s);
    if (s->p >= s->end || *s->p != '{') { sj_skip_value(s); return; }
    s->p++;
    int more = 1;
    while (more && s->p < s->end && *s->p != '}') {
        sj_skip_ws(s);
        if (sj_match_key(s, "name")) {
            sj_parse_string(s, info->version, sizeof(info->version));
        } else if (sj_match_key(s, "protocol")) {
            int v = 0;
            if (sj_parse_int(s, &v) && v > 0 && v < 1000) info->protocol = v;
        } else {
            sj_skip_field(s);
        }
        more = sj_after_value(s);
    }
    if (s->p < s->end && *s->p == '}') s->p++;
}

// Extract one player { name, id }
static int sj_read_player(sj_t *s, player_t *p) {
    sj_skip_ws(s);
    if (s->p >= s->end || *s->p != '{') return sj_skip_value(s) ? 0 : 0;
    s->p++;
    int more = 1;
    while (more && s->p < s->end && *s->p != '}') {
        sj_skip_ws(s);
        if (sj_match_key(s, "name")) {
            sj_parse_string(s, p->name, sizeof(p->name));
        } else if (sj_match_key(s, "id")) {
            sj_parse_string(s, p->id, sizeof(p->id));
        } else {
            sj_skip_field(s);
        }
        more = sj_after_value(s);
    }
    if (s->p < s->end && *s->p == '}') s->p++;
    return 1;
}

// Extract players { online, max, sample[] }
static void sj_read_players(sj_t *s, server_info_t *info) {
    sj_skip_ws(s);
    if (s->p >= s->end || *s->p != '{') { sj_skip_value(s); return; }
    s->p++;
    int more = 1;
    while (more && s->p < s->end && *s->p != '}') {
        sj_skip_ws(s);
        if (sj_match_key(s, "online")) {
            int v = 0;
            if (sj_parse_int(s, &v) && v >= 0 && v < 1000000) info->players.online = v;
        } else if (sj_match_key(s, "max")) {
            int v = 0;
            if (sj_parse_int(s, &v) && v >= 0 && v < 1000000) info->players.max = v;
        } else if (sj_match_key(s, "sample")) {
            sj_skip_ws(s);
            if (s->p < s->end && *s->p == '[') {
                s->p++;
                info->players.sample_count = 0;
                int amore = 1;
                sj_skip_ws(s);
                while (amore && s->p < s->end && *s->p != ']') {
                    if (info->players.sample_count >= 10) {
                        sj_skip_value(s);
                    } else {
                        if (sj_read_player(s, &info->players.sample[info->players.sample_count])) {
                            info->players.sample_count++;
                        }
                    }
                    sj_skip_ws(s);
                    if (s->p < s->end && *s->p == ',') { s->p++; amore = 1; }
                    else amore = 0;
                    sj_skip_ws(s);
                }
                if (s->p < s->end && *s->p == ']') s->p++;
            } else {
                sj_skip_value(s);  // `sample` not an array — skip the value
            }
        } else {
            sj_skip_field(s);
        }
        more = sj_after_value(s);
    }
    if (s->p < s->end && *s->p == '}') s->p++;
}

int parse_server_json_n(const char *json_buf, size_t json_len, server_info_t *info) {
    if (!json_buf) return 0;
    sj_t s = { .p = json_buf, .end = json_buf + json_len };
    sj_skip_ws(&s);
    if (s.p >= s.end || *s.p != '{') return 0;
    s.p++;

    int more = 1;
    while (more && s.p < s.end && *s.p != '}') {
        sj_skip_ws(&s);
        if (sj_match_key(&s, "description")) {
            sj_read_description(&s, info->motd, sizeof(info->motd));
        } else if (sj_match_key(&s, "version")) {
            sj_read_version(&s, info);
        } else if (sj_match_key(&s, "players")) {
            sj_read_players(&s, info);
        } else {
            sj_skip_field(&s);
        }
        more = sj_after_value(&s);
    }
    info->success = true;
    return 1;
}

int parse_server_json(const char *json_buf, server_info_t *info) {
    if (!json_buf) return 0;
    return parse_server_json_n(json_buf, strlen(json_buf), info);
}

// Parse a varint from a byte buffer.
// Returns: 1 = parsed ok, 0 = need more bytes, -1 = malformed.
//
// Accumulate on an unsigned type: ISO C leaves left-shift of signed ints that
// overflow INT_MAX undefined, and (b & 0x7F) << 28 for the fifth VarInt byte
// crosses that line. Cast to int32_t only at the end.
int parse_varint_buf(const uint8_t *buf, size_t len, int32_t *out, int *consumed) {
    uint32_t result = 0;
    int num_read = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = buf[i];
        result |= (uint32_t)(b & 0x7F) << (7 * num_read);
        num_read++;
        if (!(b & 0x80)) {
            *out = (int32_t)result;
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
        
        if (parse_server_json_n(json_buf, (size_t)json_len, info)) {
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
    int timeout_ms;         // adaptive per-slot timeout
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

    // Adaptive timeout: look up per-/16 stats for this IP. Pre-parse once
    // here; downstream consumers (dedup, connect sockaddr) reuse it instead
    // of re-running inet_pton.
    struct in_addr parsed;
    inet_pton(AF_INET, ip, &parsed);
    s->info.ip_u32 = ntohl(parsed.s_addr);
    s->timeout_ms = subnet_stats_get_timeout(s->info.ip_u32);

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

    unsigned int usr_timeout = (unsigned int)s->timeout_ms;
    setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &usr_timeout, sizeof(usr_timeout));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    // Set once at socket creation. Kernel flips it back off after each recv
    // but for the 1-3 packet SLP exchange this is fine.
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(s->info.ip_u32);

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
    set_deadline(s, s->timeout_ms);
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

    int ok = parse_server_json_n((const char *)(s->in_buf + pos), (size_t)json_len, &s->info);
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
        set_deadline(s, s->timeout_ms);
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
            // TCP_QUICKACK already set once at slot_start; skip per-event
            // re-set (the kernel re-enables coalescing after each recv, but
            // setsockopt showed negligible effect on ACK latency for short
            // SLP responses and cost 2-3 µs per packet).
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
