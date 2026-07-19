/*
 * Utility functions implementation
 */

#include "util/utils.h"
#include "engines/tcpkt.h"
#include "core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>

static inline char *write_u8(char *p, uint8_t v) {
    if (v >= 100) {
        *p++ = '0' + (v / 100);
        *p++ = '0' + ((v / 10) % 10);
        *p++ = '0' + (v % 10);
    } else if (v >= 10) {
        *p++ = '0' + (v / 10);
        *p++ = '0' + (v % 10);
    } else {
        *p++ = '0' + v;
    }
    return p;
}

// Convert int32 to IP string (manual digit conversion, no sprintf)
void int_to_ip(uint32_t ip, char *buf) {
    char *p = buf;
    p = write_u8(p, (ip >> 24) & 0xFF); *p++ = '.';
    p = write_u8(p, (ip >> 16) & 0xFF); *p++ = '.';
    p = write_u8(p, (ip >> 8)  & 0xFF); *p++ = '.';
    p = write_u8(p, ip & 0xFF);
    *p = '\0';
}

// Convert IP string to int32
uint32_t ip_to_int(const char *ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

// Check if IP is valid (not private/reserved/special-use). Returns false for
// any address the scanner must never probe. Each branch covers an IANA-
// assigned range that isn't a legitimate Minecraft target and that generates
// abuse complaints or hits internal infrastructure when scanned. Keep all of
// these in sync with ranges.c / Go backend's isPublicUnicastIP.
bool check_valid_ip(uint32_t ip) {
    uint8_t a = (ip >> 24) & 0xFF;

    // 0.0.0.0/8 — "this network"
    if (a == 0) return false;
    // 10.0.0.0/8 — RFC1918
    if (a == 10) return false;
    // 127.0.0.0/8 — loopback
    if (a == 127) return false;
    // 100.64.0.0/10 — CGNAT
    if ((ip & 0xFFC00000) == 0x64400000) return false;
    // 169.254.0.0/16 — link-local
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return false;
    // 172.16.0.0/12 — RFC1918
    if ((ip & 0xFFF00000) == 0xAC100000) return false;
    // 192.0.0.0/24 — IETF protocol assignments
    if ((ip & 0xFFFFFF00) == 0xC0000000) return false;
    // 192.0.2.0/24 — TEST-NET-1
    if ((ip & 0xFFFFFF00) == 0xC0000200) return false;
    // 192.168.0.0/16 — RFC1918
    if ((ip & 0xFFFF0000) == 0xC0A80000) return false;
    // 198.18.0.0/15 — benchmark
    if ((ip & 0xFFFE0000) == 0xC6120000) return false;
    // 198.51.100.0/24 — TEST-NET-2
    if ((ip & 0xFFFFFF00) == 0xC6336400) return false;
    // 203.0.113.0/24 — TEST-NET-3
    if ((ip & 0xFFFFFF00) == 0xCB007100) return false;
    // 224.0.0.0/4 — multicast; 240.0.0.0/4 — reserved; includes 255.255.255.255
    if (a >= 224) return false;

    return true;
}

// Fetch the externally-visible IP from an HTTP echo service. Some ISPs
// assign a public-looking address to customer equipment (e.g. 100.x, but
// not always — some use real APNIC/RIPE space) while still NAT'ing
// upstream. In that case the local interface IP passes check_valid_ip()
// but SYN-ACKs still never come back. The only reliable detector is an
// external round trip: ask a third party what IP our packets leave with.
//
// Returns 0 on success (out filled with host-order uint32), -1 on error.
// Caller should treat error as "don't know — skip external-vs-local
// comparison" rather than "machine is NAT'd".
static int fetch_external_ip(uint32_t *out_ip) {
    // api.ipify.org — plaintext, tiny, stable, HTTP on port 80 so no TLS.
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("api.ipify.org", "80", &hints, &res) != 0 || !res) {
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    struct timeval tv = { .tv_sec = 4, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);

    static const char req[] =
        "GET / HTTP/1.0\r\n"
        "Host: api.ipify.org\r\n"
        "User-Agent: taxenheimer/1.0\r\n"
        "Connection: close\r\n\r\n";
    if (send(fd, req, sizeof(req) - 1, MSG_NOSIGNAL) < 0) {
        close(fd); return -1;
    }

    char buf[1024];
    size_t total = 0;
    for (;;) {
        if (total >= sizeof(buf) - 1) break;
        ssize_t n = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';

    // Response is "HTTP/1.0 200 OK\r\n...\r\n\r\n<ip>". Skip headers.
    char *body = strstr(buf, "\r\n\r\n");
    if (!body) return -1;
    body += 4;
    // Strip trailing whitespace; IP ends at first non-[0-9.] char.
    char ip_str[16] = {0};
    size_t j = 0;
    for (size_t i = 0; body[i] && j < sizeof(ip_str) - 1; i++) {
        if (isdigit((unsigned char)body[i]) || body[i] == '.') {
            ip_str[j++] = body[i];
        } else {
            break;
        }
    }
    if (j == 0) return -1;

    uint32_t parsed = ip_to_int(ip_str);
    if (parsed == 0) return -1;
    *out_ip = parsed;
    return 0;
}

int check_public_local_ip(const char *mode_name) {
    uint32_t local_ip = 0;
    char ifname[IF_NAMESIZE] = {0};
    if (tcpkt_get_local_ip(&local_ip, ifname, sizeof(ifname)) < 0) {
        log_error("%s: cannot resolve local IP on default route", mode_name);
        return -1;
    }

    char local_str[16];
    int_to_ip(local_ip, local_str);

    // Stage 1: cheap local check — catches RFC1918, CGNAT, loopback, etc.
    if (!check_valid_ip(local_ip)) {
        log_error("%s: local IP %s on %s is not publicly routable",
                  mode_name, local_str, ifname);
        log_error("%s mode crafts SYNs via raw socket, bypassing kernel TCP. "
                  "Behind NAT the gateway drops returning SYN-ACKs (no "
                  "conntrack entry), so the scanner finds zero hosts.",
                  mode_name);
        log_error("Use EPOLL (default), -H (hybrid), -u (iouring), or -b "
                  "(bedrock) behind NAT. %s needs a host with a public IP.",
                  mode_name);
        return -1;
    }

    // Stage 2: external round trip — catches ISPs that hand out public
    // IP space to customer equipment and NAT upstream anyway.
    uint32_t external_ip = 0;
    if (fetch_external_ip(&external_ip) < 0) {
        log_warn("%s: external IP probe failed (api.ipify.org unreachable); "
                 "proceeding based on local check only", mode_name);
        log_info("%s: local IP %s on %s passes RFC1918 check — OK",
                 mode_name, local_str, ifname);
        return 0;
    }

    char ext_str[16];
    int_to_ip(external_ip, ext_str);

    if (external_ip != local_ip) {
        log_error("%s: local IP %s on %s does NOT match external IP %s — "
                  "you are behind NAT", mode_name, local_str, ifname, ext_str);
        log_error("%s mode crafts SYNs via raw socket, bypassing kernel TCP. "
                  "NAT gateway will drop returning SYN-ACKs (no conntrack "
                  "entry), so the scanner finds zero hosts.", mode_name);
        log_error("Use EPOLL (default), -H (hybrid), -u (iouring), or -b "
                  "(bedrock) behind NAT. %s needs a host with a public IP "
                  "directly assigned to its NIC.", mode_name);
        return -1;
    }

    log_info("%s: local IP %s on %s == external IP %s — OK",
             mode_name, local_str, ifname, ext_str);
    return 0;
}
