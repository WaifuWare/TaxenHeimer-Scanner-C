/*
 * Thread-safe ring buffer for IPs that responded to SYN probes.
 */

#include "scanner/hitqueue.h"
#include <string.h>

void hitqueue_init(hit_queue_t *q) {
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->shutdown = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

void hitqueue_destroy(hit_queue_t *q) {
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
}

int hitqueue_push(hit_queue_t *q, const char *ip) {
    pthread_mutex_lock(&q->lock);
    while (q->count >= HIT_QUEUE_CAP && !q->shutdown) {
        pthread_cond_wait(&q->not_full, &q->lock);
    }
    if (q->shutdown) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    strncpy(q->ips[q->tail], ip, 15);
    q->ips[q->tail][15] = '\0';
    q->tail = (q->tail + 1) % HIT_QUEUE_CAP;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

int hitqueue_pop_batch(hit_queue_t *q, char buf[][16], int max) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !q->shutdown) {
        // Use timed wait so workers can check interrupt flag periodically
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100000000L;  // 100ms
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&q->not_empty, &q->lock, &ts);
    }
    if (q->count == 0 && q->shutdown) {
        pthread_mutex_unlock(&q->lock);
        return 0;
    }
    int n = 0;
    while (n < max && q->count > 0) {
        memcpy(buf[n], q->ips[q->head], 16);
        q->head = (q->head + 1) % HIT_QUEUE_CAP;
        q->count--;
        n++;
    }
    if (n > 0) pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return n;
}

void hitqueue_shutdown(hit_queue_t *q) {
    pthread_mutex_lock(&q->lock);
    q->shutdown = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->lock);
}
