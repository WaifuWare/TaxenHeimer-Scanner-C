#ifndef TCPKT_H
#define TCPKT_H

#include <stdint.h>
#include <stddef.h>

// Build a TCP SYN packet (IP + TCP headers). Returns total length.
// Caller provides buffer of at least 40 bytes.
int tcpkt_build_syn(uint8_t *buf, size_t cap,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dst_ip, uint16_t dst_port,
                    uint32_t seq);

// Build a TCP ACK packet with optional payload (IP + TCP + data).
int tcpkt_build_ack(uint8_t *buf, size_t cap,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dst_ip, uint16_t dst_port,
                    uint32_t seq, uint32_t ack,
                    const uint8_t *payload, size_t payload_len,
                    int psh);

// Build a TCP RST packet.
int tcpkt_build_rst(uint8_t *buf, size_t cap,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dst_ip, uint16_t dst_port,
                    uint32_t seq, uint32_t ack);

// Internet checksum (RFC 1071).
uint16_t tcpkt_checksum(const void *data, size_t len);

// Get local IP + interface for default route.
int tcpkt_get_local_ip(uint32_t *out_ip, char *ifname, size_t ifname_len);

#endif
