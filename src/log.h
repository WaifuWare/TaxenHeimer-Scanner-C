/*
 * Centralized logging
 */

#ifndef LOG_H
#define LOG_H

typedef enum {
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} log_level_t;

// Log a message
void log_msg(log_level_t level, const char *fmt, ...);

// Convenience macros
#define log_info(fmt, ...) log_msg(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) log_msg(LOG_WARNING, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_msg(LOG_ERROR, fmt, ##__VA_ARGS__)

#endif // LOG_H
