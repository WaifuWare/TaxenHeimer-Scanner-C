/*
 * Async socket pool for concurrent scanning
 */

#ifndef SOCKET_POOL_H
#define SOCKET_POOL_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Socket pool configuration
#define SOCKET_POOL_SIZE 64

// Socket state
typedef enum {
    SOCK_IDLE,
    SOCK_CONNECTING,
    SOCK_CONNECTED,
    SOCK_READING,
    SOCK_ERROR
} socket_state_t;

// Socket in pool
typedef struct {
    int fd;
    socket_state_t state;
    char ip[16];
    int port;
    uint8_t buffer[8192];
    int buffer_len;
    int bytes_read;
    time_t connect_time;
} pooled_socket_t;

// Socket pool
typedef struct {
    pooled_socket_t sockets[SOCKET_POOL_SIZE];
    int active_count;
} socket_pool_t;

// Initialize socket pool
socket_pool_t *socket_pool_create(void);

// Destroy socket pool
void socket_pool_destroy(socket_pool_t *pool);

// Get available socket from pool
int socket_pool_acquire(socket_pool_t *pool, const char *ip, int port);

// Release socket back to pool
void socket_pool_release(socket_pool_t *pool, int sock_idx);

// Process all sockets with select()
int socket_pool_process(socket_pool_t *pool, int timeout_ms);

// Get socket by index
pooled_socket_t *socket_pool_get(socket_pool_t *pool, int idx);

// Get active socket count
int socket_pool_active_count(socket_pool_t *pool);

#endif // SOCKET_POOL_H
