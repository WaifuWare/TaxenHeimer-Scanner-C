/*
 * Minecraft protocol packet handling
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "settings.h"

// Packet buffer structure
typedef struct {
    uint8_t data[MAX_PACKET_SIZE];
    size_t len;
} packet_t;

// Handshake states
typedef enum {
    STATE_STATUS = 1,
    STATE_LOGIN = 2,
    STATE_TRANSFER = 3
} handshake_state_t;

// VarInt operations
int write_varint(packet_t *pkt, int32_t value);
int read_varint(int sockfd, int32_t *value);

// Packet field writers
int write_string(packet_t *pkt, const char *str);
int write_short(packet_t *pkt, int16_t value);
int write_long(packet_t *pkt, int64_t value);
int write_bytes(packet_t *pkt, const uint8_t *data, size_t len);

// Packet constructors
int create_handshake_packet(packet_t *pkt, const char *addr, int port, handshake_state_t state);
int create_status_request(packet_t *pkt);
int create_login_start(packet_t *pkt, const char *username);

#endif // PACKET_H
