/*
 * Centralized logging implementation
 */

#include "log.h"
#include "ui.h"
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>
#include <string.h>

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

void log_msg(log_level_t level, const char *fmt, ...) {
    pthread_mutex_lock(&log_lock);
    
    const char *level_str = "INFO";
    
    switch (level) {
        case LOG_INFO:
            level_str = "INFO";
            break;
        case LOG_WARNING:
            level_str = "WARN";
            break;
        case LOG_ERROR:
            level_str = "ERROR";
            break;
    }
    
    // Format the message
    char message[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    // Use UI logging to ensure proper placement in scroll region
    ui_log(level_str, message);
    
    pthread_mutex_unlock(&log_lock);
}
