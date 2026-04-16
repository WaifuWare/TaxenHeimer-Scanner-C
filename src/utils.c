/*
 * Utility functions implementation
 */

#include "utils.h"
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

// Check if IP is valid (not private) - optimized with bit masking
bool check_valid_ip(uint32_t ip) {
    // Check 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
    if ((ip & 0xFF000000) == 0x0A000000) return false;
    
    // Check 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if ((ip & 0xFFF00000) == 0xAC100000) return false;
    
    // Check 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
    if ((ip & 0xFFFF0000) == 0xC0A80000) return false;
    
    // Check 169.254.0.0/16 (169.254.0.0 - 169.254.255.255)
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return false;
    
    return true;
}
