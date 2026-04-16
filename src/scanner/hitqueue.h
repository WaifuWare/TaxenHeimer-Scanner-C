/*
 * Thread-safe ring buffer of responsive IPs.
 * Prescan thread pushes, worker threads pop.
 */

#ifndef HITQUEUE_H
#define HITQUEUE_H

#include <pthread.h>

#define HIT_QUEUE_CAP 32768

typedef struct hit_queue {
    char     ips[HIT_QUEUE_CAP][16];
    int      head;
    int      tail;
    int      count;
    int      shutdown;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} hit_queue_t;

void hitqueue_init(hit_queue_t *q);
void hitqueue_destroy(hit_queue_t *q);

// Push an IP string. Blocks if full. Returns 0 on success, -1 on shutdown.
int hitqueue_push(hit_queue_t *q, const char *ip);

// Pop up to `max` IPs into buf. Blocks until at least 1 available or shutdown.
// Returns number popped (0 on shutdown with empty queue).
int hitqueue_pop_batch(hit_queue_t *q, char buf[][16], int max);

// Signal shutdown to unblock all waiters.
void hitqueue_shutdown(hit_queue_t *q);

#endif
