/*
 * Async socket pool implementation with select() multiplexing
 */

#include "socket_pool.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

socket_pool_t *socket_pool_create(void) {
    socket_pool_t *pool = malloc(sizeof(socket_pool_t));
    if (!pool) return NULL;
    
    memset(pool, 0, sizeof(socket_pool_t));
    
    for (int i = 0; i < SOCKET_POOL_SIZE; i++) {
        pool->sockets[i].fd = -1;
        pool->sockets[i].state = SOCK_IDLE;
        pool->sockets[i].connect_time = 0;
    }
    
    return pool;
}

void socket_pool_destroy(socket_pool_t *pool) {
    if (!pool) return;
    
    for (int i = 0; i < SOCKET_POOL_SIZE; i++) {
        if (pool->sockets[i].fd >= 0) {
            close(pool->sockets[i].fd);
        }
    }
    
    free(pool);
}

int socket_pool_acquire(socket_pool_t *pool, const char *ip, int port) {
    if (!pool) return -1;
    
    // Find idle socket
    int idx = -1;
    for (int i = 0; i < SOCKET_POOL_SIZE; i++) {
        if (pool->sockets[i].state == SOCK_IDLE) {
            idx = i;
            break;
        }
    }
    
    if (idx == -1) return -1;  // Pool full
    
    pooled_socket_t *sock = &pool->sockets[idx];
    
    // Create socket
    sock->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock->fd < 0) {
        return -1;
    }
    
    // Set non-blocking
    int flags = fcntl(sock->fd, F_GETFL, 0);
    fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK);
    
    // Store connection info
    strncpy(sock->ip, ip, sizeof(sock->ip) - 1);
    sock->port = port;
    sock->state = SOCK_CONNECTING;
    sock->buffer_len = 0;
    sock->bytes_read = 0;
    sock->connect_time = time(NULL);
    
    // Initiate connection
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (connect(sock->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) {
            close(sock->fd);
            sock->fd = -1;
            sock->state = SOCK_ERROR;
            return -1;
        }
    }
    
    pool->active_count++;
    return idx;
}

void socket_pool_release(socket_pool_t *pool, int sock_idx) {
    if (!pool || sock_idx < 0 || sock_idx >= SOCKET_POOL_SIZE) return;
    
    pooled_socket_t *sock = &pool->sockets[sock_idx];
    
    if (sock->fd >= 0) {
        close(sock->fd);
        sock->fd = -1;
    }
    
    sock->state = SOCK_IDLE;
    sock->buffer_len = 0;
    sock->bytes_read = 0;
    
    if (pool->active_count > 0) {
        pool->active_count--;
    }
}

int socket_pool_process(socket_pool_t *pool, int timeout_ms) {
    if (!pool || pool->active_count == 0) return 0;
    
    fd_set readfds, writefds, exceptfds;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    
    int max_fd = -1;
    time_t now = time(NULL);
    
    // Build fd sets and check for timeouts
    for (int i = 0; i < SOCKET_POOL_SIZE; i++) {
        pooled_socket_t *sock = &pool->sockets[i];
        
        if (sock->fd < 0) continue;
        
        // Check connection timeout (2 seconds)
        if (sock->state == SOCK_CONNECTING && (now - sock->connect_time) > 2) {
            sock->state = SOCK_ERROR;
            close(sock->fd);
            sock->fd = -1;
            pool->active_count--;
            continue;
        }
        
        if (sock->state == SOCK_CONNECTING) {
            FD_SET(sock->fd, &writefds);
            FD_SET(sock->fd, &exceptfds);
        } else if (sock->state == SOCK_CONNECTED || sock->state == SOCK_READING) {
            FD_SET(sock->fd, &readfds);
        }
        
        if (sock->fd > max_fd) {
            max_fd = sock->fd;
        }
    }
    
    if (max_fd < 0) return 0;
    
    // Wait for events
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int ret = select(max_fd + 1, &readfds, &writefds, &exceptfds, &tv);
    if (ret <= 0) return ret;
    
    // Process ready sockets
    int processed = 0;
    for (int i = 0; i < SOCKET_POOL_SIZE; i++) {
        pooled_socket_t *sock = &pool->sockets[i];
        
        if (sock->fd < 0) continue;
        
        // Check for connection errors
        if (FD_ISSET(sock->fd, &exceptfds)) {
            sock->state = SOCK_ERROR;
            close(sock->fd);
            sock->fd = -1;
            pool->active_count--;
            processed++;
            continue;
        }
        
        // Check write ready (connection complete)
        if (FD_ISSET(sock->fd, &writefds) && sock->state == SOCK_CONNECTING) {
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &error, &len);
            
            if (error == 0) {
                sock->state = SOCK_CONNECTED;
                processed++;
            } else {
                sock->state = SOCK_ERROR;
                close(sock->fd);
                sock->fd = -1;
                pool->active_count--;
            }
        }
        
        // Check read ready
        if (FD_ISSET(sock->fd, &readfds) && sock->state == SOCK_CONNECTED) {
            sock->state = SOCK_READING;
            processed++;
        }
    }
    
    return processed;
}

pooled_socket_t *socket_pool_get(socket_pool_t *pool, int idx) {
    if (!pool || idx < 0 || idx >= SOCKET_POOL_SIZE) return NULL;
    return &pool->sockets[idx];
}

int socket_pool_active_count(socket_pool_t *pool) {
    if (!pool) return 0;
    return pool->active_count;
}
