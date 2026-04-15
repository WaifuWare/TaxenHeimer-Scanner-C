/*
 * Minecraft protocol packet implementation
 */

#include "packet.h"
#include <string.h>
#include <sys/socket.h>

// Write VarInt to packet
int write_varint(packet_t *pkt, int32_t value) {
    if (pkt->len >= MAX_PACKET_SIZE - 5) return -1;
    
    uint32_t val = (uint32_t)value;
    for (int i = 0; i < 5; i++) {
        if ((val & ~0x7F) == 0) {
            pkt->data[pkt->len++] = (uint8_t)val;
            return 0;
        }
        pkt->data[pkt->len++] = (uint8_t)((val & 0x7F) | 0x80);
        val >>= 7;
    }
    return -1;
}

// Read VarInt from socket
int read_varint(int sockfd, int32_t *value) {
    int num_read = 0;
    int result = 0;
    uint8_t byte;
    
    while (1) {
        ssize_t n = recv(sockfd, &byte, 1, 0);
        if (n <= 0) return -1;
        
        result |= (byte & 0x7F) << (7 * num_read);
        num_read++;
        
        if (num_read > 5) return -1;
        if ((byte & 0x80) == 0) break;
    }
    
    *value = result;
    return 0;
}

// Write string to packet
int write_string(packet_t *pkt, const char *str) {
    size_t len = strlen(str);
    if (pkt->len + len + 5 > MAX_PACKET_SIZE) return -1;
    
    if (write_varint(pkt, len) < 0) return -1;
    memcpy(&pkt->data[pkt->len], str, len);
    pkt->len += len;
    return 0;
}

// Write short to packet
int write_short(packet_t *pkt, int16_t value) {
    if (pkt->len + 2 > MAX_PACKET_SIZE) return -1;
    
    pkt->data[pkt->len++] = (value >> 8) & 0xFF;
    pkt->data[pkt->len++] = value & 0xFF;
    return 0;
}

// Write long to packet
int write_long(packet_t *pkt, int64_t value) {
    if (pkt->len + 8 > MAX_PACKET_SIZE) return -1;
    
    for (int i = 7; i >= 0; i--) {
        pkt->data[pkt->len++] = (value >> (i * 8)) & 0xFF;
    }
    return 0;
}

// Write bytes to packet
int write_bytes(packet_t *pkt, const uint8_t *data, size_t len) {
    if (pkt->len + len > MAX_PACKET_SIZE) return -1;
    
    memcpy(&pkt->data[pkt->len], data, len);
    pkt->len += len;
    return 0;
}

// Create handshake packet
int create_handshake_packet(packet_t *pkt, const char *addr, int port, handshake_state_t state) {
    packet_t inner = {0};
    
    write_varint(&inner, 0x00);  // Packet ID
    write_varint(&inner, PROTOCOL_VERSION);
    write_string(&inner, addr);
    write_short(&inner, (int16_t)port);
    write_varint(&inner, (int)state);
    
    // Wrap with length prefix
    write_varint(pkt, inner.len);
    memcpy(&pkt->data[pkt->len], inner.data, inner.len);
    pkt->len += inner.len;
    
    return 0;
}

// Create status request packet
int create_status_request(packet_t *pkt) {
    write_varint(pkt, 1);  // Length
    pkt->data[pkt->len++] = 0x00;  // Packet ID
    return 0;
}

// Create login start packet
int create_login_start(packet_t *pkt, const char *username) {
    packet_t inner = {0};
    
    inner.data[inner.len++] = 0x00;  // Packet ID
    write_string(&inner, username);
    
    // Player UUID (16 zero bytes for offline/unknown UUID)
    for (int i = 0; i < 16; i++) {
        inner.data[inner.len++] = 0x00;
    }
    
    // Wrap with length prefix
    write_varint(pkt, inner.len);
    memcpy(&pkt->data[pkt->len], inner.data, inner.len);
    pkt->len += inner.len;
    
    return 0;
}
