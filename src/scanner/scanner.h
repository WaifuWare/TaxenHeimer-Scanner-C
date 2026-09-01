/*
 * Scanner core functionality
 */

#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "core/settings.h"

// Player information
typedef struct {
    char name[128];
    char id[64];
} player_t;

// Players information
typedef struct {
    int max;
    int online;
    player_t sample[10];  // Store up to 10 players
    int sample_count;
} players_t;

// Mod list, populated from the SLP response's `modinfo` (legacy Forge/FML,
// 1.7-1.12), `forgeData` (modern Forge, 1.13+), or `neoforgeData` (NeoForge)
// object. mod_loader is "" for unmodded servers. Fabric doesn't advertise a
// mod list in the standard SLP JSON, so it's never populated here.
#define MAX_MODS_CAPTURED 64
typedef struct {
    char mod_loader[16];              // "forge", "neoforge", "" if unmodded
    char mods[MAX_MODS_CAPTURED][48]; // mod IDs only — versions/markers dropped
    int mod_count;                    // number actually captured (<= MAX_MODS_CAPTURED)
    int mod_count_total;              // total advertised by the server
} mod_info_t;

// Server information structure. Default shape is the Java SLP payload. The
// bedrock fields are only populated by the RakNet engine (src/engines/
// bedrock.c); when bedrock=false the backend ignores them.
typedef struct {
    bool success;
    char ip[16];
    uint32_t ip_u32;   // host-order IP, pre-parsed to skip sscanf in dedup/stats.
    int port;
    char version[128];
    char motd[512];
    int protocol;
    players_t players;
    mod_info_t mod_info;

    // Bedrock / RakNet-only fields. Zero-initialised for Java hits.
    bool bedrock;
    char motd2[256];        // MCPE second MOTD line
    char gamemode[32];      // "Survival", "Creative", "Adventure", etc
    int  port_v4;           // server's canonical IPv4 port (often != scan port)
    int  port_v6;           // IPv6 port
    uint64_t server_guid;   // RakNet server GUID
} server_info_t;

// Scanner functions
int scan_ip(const char *ip, int port, server_info_t *info);
int scan_batch(char ips[][16], int count, server_info_t *results);

// Async scan with callback
typedef void (*scan_callback_t)(const server_info_t *info);
int scan_batch_async(char ips[][16], int count, scan_callback_t callback);

// Socket pool management
void scanner_init_pool(void);
void scanner_cleanup_pool(void);

// Shared parsers (used by both epoll scanner and rawnet)
int parse_server_json(const char *json_buf, server_info_t *info);
// Length-aware variant — avoids forcing callers to allocate a NUL-terminated
// copy of the SLP JSON body.
int parse_server_json_n(const char *json_buf, size_t json_len, server_info_t *info);
int parse_varint_buf(const uint8_t *buf, size_t len, int32_t *out, int *consumed);

// parse_slp_frame consumes a complete Minecraft Server List Ping response
// from buf[0..len]: VarInt pkt_len, VarInt pkt_id (must be 0), VarInt
// json_len, then the JSON status body. On success info is populated from
// the JSON and the function returns 1. Returns 0 when more bytes are
// needed (partial frame) and -1 on malformed input or pkt_len that
// exceeds max_body_len. max_body_len is the caller's response cap (e.g.
// SLOT_RESP_CAP / CONN_RX_CAP) — anything larger is treated as a framing
// error so a bad peer can't force a 32-bit-wide allocation attempt.
int parse_slp_frame(const uint8_t *buf, size_t len, size_t max_body_len, server_info_t *info);

// Wire an interrupt flag so async scan loops can abort promptly on shutdown.
#include <signal.h>
void scanner_set_interrupt_flag(volatile sig_atomic_t *flag);

#endif // SCANNER_H
