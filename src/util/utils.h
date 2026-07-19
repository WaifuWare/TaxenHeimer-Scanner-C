/*
 * Utility functions for IP handling
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include "core/settings.h"

// IP conversion functions
void int_to_ip(uint32_t ip, char *buf);
uint32_t ip_to_int(const char *ip);

// IP validation
bool check_valid_ip(uint32_t ip);

// Resolve the source IP of the default route and verify it is globally
// routable. Raw-packet modes (XDP, SYNBLAST, RAW) craft SYNs directly,
// bypassing the kernel conntrack. Behind a NAT the returned SYN-ACKs get
// dropped at the gateway because no matching conntrack entry exists, so
// the scanner looks alive but finds zero hosts. This check bails out early
// with a clear log line instead of letting the user watch a silent scan.
//
// mode_name is only used in the log message (e.g. "XDP", "SYNBLAST").
// Returns 0 on public IP, -1 on private/CGNAT/loopback/error.
int check_public_local_ip(const char *mode_name);

#endif // UTILS_H
