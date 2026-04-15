/*
 * Utility functions implementation
 */

#include "utils.h"
#include <stdio.h>
#include <arpa/inet.h>

// Convert int32 to IP string (optimized with bit shifting)
void int_to_ip(uint32_t ip, char *buf) {
    uint8_t *bytes = (uint8_t *)&ip;
    sprintf(buf, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1], bytes[0]);
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
