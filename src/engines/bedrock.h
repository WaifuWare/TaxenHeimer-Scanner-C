/*
 * Minecraft Bedrock (RakNet) UDP scanner.
 *
 * Default port 19132. Stateless UDP protocol: send Unconnected Ping (0x01),
 * receive Unconnected Pong (0x1C) with a semicolon-delimited server info
 * string (MCPE;motd;protocol;version;online;max;...).
 *
 * Works anywhere — NAT, no public IP, no CAP_NET_RAW. UDP replies come back
 * via conntrack just like any other outbound UDP.
 */

#ifndef BEDROCK_H
#define BEDROCK_H

#include <signal.h>
#include "scanner/scanner.h"

#define BEDROCK_PORT 19132

void bedrock_set_interrupt(volatile sig_atomic_t *flag);

// Scan a batch of IPs via UDP Unconnected Ping. Callback invoked per IP.
// Non-responders fire callback with info->success = false.
int bedrock_scan_batch(char ips[][16], int count, scan_callback_t callback);

#endif
