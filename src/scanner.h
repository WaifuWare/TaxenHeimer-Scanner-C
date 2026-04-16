/*
 * Scanner core functionality
 */

#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <stdbool.h>
#include "settings.h"

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

// Server information structure
typedef struct {
    bool success;
    char ip[16];
    int port;
    char version[128];
    char motd[512];
    int protocol;
    players_t players;
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

// Wire an interrupt flag so async scan loops can abort promptly on shutdown.
#include <signal.h>
void scanner_set_interrupt_flag(volatile sig_atomic_t *flag);

#endif // SCANNER_H
