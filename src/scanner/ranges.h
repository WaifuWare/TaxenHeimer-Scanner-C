/*
 * Subnet ranges for scanning
 * Converted from ranges.nim
 */

#ifndef RANGES_H
#define RANGES_H

#include <stdint.h>

// Known Minecraft server subnet ranges
extern const int32_t KNOWN_RANGES[];
extern const int KNOWN_RANGES_COUNT;

// Build a heap-allocated array of every routable /16 subnet in the IPv4 space.
// Skips RFC1918, loopback, CGNAT, link-local, multicast, reserved, etc.
// Caller owns the memory — free() it after use.
// Returns NULL on allocation failure. Writes count to *out_count.
int32_t *ranges_build_full_ipv4(int *out_count);

#endif // RANGES_H
