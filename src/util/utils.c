/*
 * Utility functions implementation
 */

#include "util/utils.h"
#include <stdio.h>
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
