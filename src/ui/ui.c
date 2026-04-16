/*
 * Terminal UI implementation
 */

#include "ui/ui.h"
#include "ui/stats.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>

// ANSI sequences
#define ESC "\033"
#define CSI "\033["
#define CLEAR_LINE CSI "2K\r"
#define HIDE_CURSOR CSI "?25l"
#define SHOW_CURSOR CSI "?25h"
#define ALT_SCREEN_ON CSI "?1049h"
#define ALT_SCREEN_OFF CSI "?1049l"

// ANSI color codes
#define COLOR_BLUE "\033[38;2;79;110;247m"
#define COLOR_YELLOW "\033[38;2;250;233;0m"
#define COLOR_GREEN "\033[38;2;34;197;94m"
#define COLOR_GRAY "\033[38;2;100;116;139m"
#define COLOR_DARK "\033[38;2;46;50;80m"
#define COLOR_RED "\033[38;2;239;68;68m"
#define COLOR_RESET "\033[0m"

static time_t ui_start_time = 0;
static pthread_mutex_t ui_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int ui_printing = 0;  // Flag to indicate active printing
static char ui_engine[16] = "EPOLL";  // scan engine label for header
static uint64_t ui_prescan_syns = 0;
static uint64_t ui_prescan_fails = 0;
static uint64_t ui_prescan_rxpkts = 0;
static uint64_t ui_prescan_acks = 0;

// Get terminal size
static void get_term_size(int *w, int *h) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *w = ws.ws_col;
        *h = ws.ws_row;
    } else {
        *w = 80;
        *h = 24;
    }
}



void ui_set_engine(const char *engine) {
    strncpy(ui_engine, engine, sizeof(ui_engine) - 1);
    ui_engine[sizeof(ui_engine) - 1] = '\0';
}

void ui_set_prescan_stats(uint64_t syns_sent, uint64_t syns_failed,
                          uint64_t rx_packets, uint64_t synacks_recv) {
    ui_prescan_syns = syns_sent;
    ui_prescan_fails = syns_failed;
    ui_prescan_rxpkts = rx_packets;
    ui_prescan_acks = synacks_recv;
}

void ui_init(void) {
    ui_start_time = time(NULL);
    printf("%s", ALT_SCREEN_ON);
    printf("%s", HIDE_CURSOR);
    printf("%s", CSI "?1000l");  // Disable mouse
    printf("%s", CSI "2J");      // Clear screen
    printf("%s", CSI "H");       // Move to home
    fflush(stdout);
}

void ui_shutdown(void) {
    int w, h;
    get_term_size(&w, &h);
    printf("%s", CSI "?1049l");  // Exit alt screen
    printf("%s", CSI "r");       // Reset scroll region
    printf("%s", SHOW_CURSOR);
    printf("%s", CSI "2J");
    printf("%s", CSI "H");
    fflush(stdout);
}

void ui_print_banner(void) {
    printf(COLOR_BLUE);
    printf("╔════════════════════════════════════════╗\n");
    printf("║      TaxenHeimer C Scanner v1.0        ║\n");
    printf("║    Minecraft Server Scanner in C       ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf(COLOR_RESET "\n");
}

void ui_print_config(int threads, int subnets, int port, int timeout_ms) {
    printf("Configuration:\n");
    printf("  " COLOR_GRAY "Threads:" COLOR_RESET "  %d\n", threads);
    printf("  " COLOR_GRAY "Subnets:" COLOR_RESET "  %d\n", subnets);
    printf("  " COLOR_GRAY "Port:" COLOR_RESET "     %d\n", port);
    printf("  " COLOR_GRAY "Timeout:" COLOR_RESET " %dms\n\n", timeout_ms);
    printf("Press " COLOR_YELLOW "Ctrl+C" COLOR_RESET " to stop\n\n");
}

void ui_print_server(const server_info_t *info) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[16];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    pthread_mutex_lock(&ui_lock);
    ui_printing = 1;
    
    // Move to end of scroll region and add newline to scroll
    printf(CSI "999;1H");  // Move to bottom-right
    printf("\n");
    
    // Print server info
    printf(COLOR_DARK "[%s]" COLOR_RESET " [" COLOR_BLUE "INFO" COLOR_RESET "] ", time_str);
    printf(COLOR_BLUE "ONLINE" COLOR_RESET " %s:%d | ", info->ip, info->port);
    printf("Version: " COLOR_YELLOW "%s" COLOR_RESET " | ", info->version[0] ? info->version : "?");
    printf("Protocol: %d\n", info->protocol);
    
    // Print MOTD
    if (info->motd[0]) {
        printf(COLOR_DARK "[%s]" COLOR_RESET " [" COLOR_BLUE "INFO" COLOR_RESET "] ", time_str);
        printf("MOTD: " COLOR_YELLOW "%s" COLOR_RESET "\n", info->motd);
    }
    
    // Print player info
    printf(COLOR_DARK "[%s]" COLOR_RESET " [" COLOR_BLUE "INFO" COLOR_RESET "] ", time_str);
    printf("Players: " COLOR_GREEN "%d/%d" COLOR_RESET, info->players.online, info->players.max);
    
    // Print player sample if available
    if (info->players.sample_count > 0) {
        printf(" | Sample: ");
        for (int i = 0; i < info->players.sample_count; i++) {
            if (i > 0) printf(", ");
            printf(COLOR_YELLOW "%s" COLOR_RESET, info->players.sample[i].name);
        }
    }
    printf("\n");
    
    fflush(stdout);
    ui_printing = 0;
    pthread_mutex_unlock(&ui_lock);
}

void ui_print_stats(void) {
    uint64_t scanned, found, errors;
    stats_get(&scanned, &found, &errors);
    double rate = stats_get_rate();
    
    printf("\r" COLOR_DARK);
    printf("Scanned: " COLOR_BLUE "%lu" COLOR_RESET " | ", scanned);
    printf("Found: " COLOR_GREEN "%lu" COLOR_RESET " | ", found);
    printf("Errors: " COLOR_GRAY "%lu" COLOR_RESET " | ", errors);
    printf("Speed: " COLOR_YELLOW "%.1f ip/s" COLOR_RESET, rate);
    printf(COLOR_RESET);
    fflush(stdout);
}

void ui_render_header(int current_subnet, int total_subnets, int host_offset, int host_total) {
    // Skip header update if a log is being printed
    if (ui_printing) return;

    uint64_t scanned, found, errors;
    stats_get(&scanned, &found, &errors);

    time_t elapsed = time(NULL) - ui_start_time;

    // Instantaneous rate: scanned delta divided by wall-clock delta between
    // refresh calls. Uses CLOCK_MONOTONIC so wall-clock jumps don't corrupt it.
    // Exponentially smoothed with alpha=0.4 to cut single-tick jitter while
    // still responding within ~2-3 refreshes to real rate changes.
    static struct timespec last_ts = {0, 0};
    static uint64_t last_scanned = 0;
    static double smoothed_rate = 0.0;

    struct timespec now_ts;
    clock_gettime(CLOCK_MONOTONIC, &now_ts);

    double rate = 0.0;
    if (last_ts.tv_sec != 0 || last_ts.tv_nsec != 0) {
        double dt = (double)(now_ts.tv_sec - last_ts.tv_sec)
                  + (double)(now_ts.tv_nsec - last_ts.tv_nsec) / 1e9;
        if (dt >= 0.05) {
            uint64_t d_scanned = scanned >= last_scanned ? (scanned - last_scanned) : 0;
            double instant = (double)d_scanned / dt;
            if (smoothed_rate == 0.0) {
                smoothed_rate = instant;
            } else {
                smoothed_rate = smoothed_rate * 0.6 + instant * 0.4;
            }
            rate = smoothed_rate;
            last_ts = now_ts;
            last_scanned = scanned;
        } else {
            // dt too small to trust — reuse previous smoothed value
            rate = smoothed_rate;
        }
    } else {
        // First sample — seed state, rate stays 0 for one tick
        last_ts = now_ts;
        last_scanned = scanned;
    }
    
    char elapsed_str[32];
    if (elapsed < 60) {
        snprintf(elapsed_str, sizeof(elapsed_str), "%lus", elapsed);
    } else if (elapsed < 3600) {
        snprintf(elapsed_str, sizeof(elapsed_str), "%.1fm", elapsed / 60.0);
    } else {
        snprintf(elapsed_str, sizeof(elapsed_str), "%.1fh", elapsed / 3600.0);
    }
    
    int w, h;
    get_term_size(&w, &h);
    if (w > 120) w = 120;
    
    pthread_mutex_lock(&ui_lock);
    
    // Set scroll region below header. Prescan modes add 1 extra row.
    int has_prescan = (strcmp(ui_engine, "HYBRID") == 0 || strcmp(ui_engine, "SYNBLAST") == 0);
    int header_lines = has_prescan ? 9 : 8;
    printf(CSI "%d;%dr", header_lines, h);
    
    // Draw header at top
    printf("%s", CSI "1;1H");  // Move to top-left
    
    // Separator
    for (int i = 0; i < w; i++) printf(COLOR_DARK "-" COLOR_RESET);
    printf("\n");
    
    // Title with engine badge
    const char *badge_color = COLOR_GRAY;
    if (strcmp(ui_engine, "HYBRID") == 0) badge_color = COLOR_GREEN;
    else if (strcmp(ui_engine, "RAW") == 0) badge_color = COLOR_YELLOW;
    printf(COLOR_BLUE "  TaxenHeimer" COLOR_RESET "  " COLOR_GRAY "Minecraft Scanner  v1.0" COLOR_RESET
           "  [%s%s" COLOR_RESET "]\n", badge_color, ui_engine);
    
    // Separator
    for (int i = 0; i < w; i++) printf(COLOR_DARK "-" COLOR_RESET);
    printf("\n");
    
    // Stats row 1
    printf("  " COLOR_GRAY "Scanned" COLOR_RESET " " COLOR_BLUE "%8lu" COLOR_RESET "   "
           COLOR_GRAY "Found" COLOR_RESET " " COLOR_GREEN "%8lu" COLOR_RESET "   "
           COLOR_GRAY "Errors" COLOR_RESET " " COLOR_RED "%8lu" COLOR_RESET "\n", 
           scanned, found, errors);
    
    // Stats row 2
    printf("  " COLOR_GRAY "Speed" COLOR_RESET " " COLOR_YELLOW "%8.1f ip/s" COLOR_RESET "   "
           COLOR_GRAY "Uptime" COLOR_RESET " " COLOR_YELLOW "%8s" COLOR_RESET "   "
           COLOR_GRAY "Subnet" COLOR_RESET " " COLOR_BLUE "%8d/%d" COLOR_RESET "\n",
           rate, elapsed_str, current_subnet, total_subnets);

    // Prescan stats
    if (strcmp(ui_engine, "HYBRID") == 0) {
        printf("  " COLOR_GRAY "Probed" COLOR_RESET " " COLOR_BLUE "%8lu" COLOR_RESET "   "
               COLOR_GRAY "Open" COLOR_RESET " " COLOR_GREEN "%8lu" COLOR_RESET "   "
               COLOR_GRAY "Hit%%" COLOR_RESET " " COLOR_YELLOW "%7.4f%%" COLOR_RESET "\n",
               ui_prescan_syns, ui_prescan_acks,
               ui_prescan_syns > 0 ? (double)ui_prescan_acks * 100.0 / (double)ui_prescan_syns : 0.0);
    } else if (strcmp(ui_engine, "SYNBLAST") == 0) {
        printf("  " COLOR_GRAY "SYNs" COLOR_RESET " " COLOR_BLUE "%8lu" COLOR_RESET
               "  " COLOR_GRAY "TX-err" COLOR_RESET " " COLOR_RED "%lu" COLOR_RESET
               "  " COLOR_GRAY "RX-pkts" COLOR_RESET " " COLOR_YELLOW "%lu" COLOR_RESET
               "  " COLOR_GRAY "SYN-ACKs" COLOR_RESET " " COLOR_GREEN "%lu" COLOR_RESET "\n",
               ui_prescan_syns, ui_prescan_fails, ui_prescan_rxpkts, ui_prescan_acks);
    }
    
    // Overall campaign progress: position across all subnets, not just current one.
    // done = current_subnet_idx * host_total + host_offset_within_current
    // total = total_subnets * host_total
    int bar_width = 32;
    long long done = 0;
    long long total = 0;
    if (total_subnets > 0 && host_total > 0) {
        long long off = host_offset;
        if (off < 0) off = 0;
        if (off > host_total) off = host_total;
        done  = (long long)current_subnet * host_total + off;
        total = (long long)total_subnets * host_total;
    }
    int filled = total > 0 ? (int)((done * bar_width) / total) : 0;
    if (filled > bar_width) filled = bar_width;
    double pctd = total > 0 ? ((double)done * 100.0 / (double)total) : 0.0;
    printf("  " COLOR_GRAY "Progress" COLOR_RESET " [");
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) printf(COLOR_BLUE "#" COLOR_RESET);
        else printf(COLOR_DARK "." COLOR_RESET);
    }
    printf("]  " COLOR_GRAY "%5.2f%%" COLOR_RESET CSI "K\n", pctd);
    
    // Separator
    for (int i = 0; i < w; i++) printf(COLOR_DARK "-" COLOR_RESET);
    printf("\n");
    
    // Move cursor to scroll region for logs
    printf(CSI "%d;1H", header_lines);
    fflush(stdout);
    
    pthread_mutex_unlock(&ui_lock);
}

void ui_print_summary(uint64_t scanned, uint64_t found, uint64_t errors) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[16];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    printf("\n\n");
    printf(COLOR_DARK "[%s]" COLOR_RESET " [" COLOR_BLUE "INFO" COLOR_RESET "] ", time_str);
    printf(COLOR_BLUE);
    printf("Scan Complete!\n");
    printf(COLOR_RESET);
    
    printf(COLOR_DARK "[%s]" COLOR_RESET " [" COLOR_BLUE "INFO" COLOR_RESET "] ", time_str);
    printf("Total scanned: " COLOR_BLUE "%lu" COLOR_RESET "\n", scanned);
    
    printf(COLOR_DARK "[%s]" COLOR_RESET " [" COLOR_BLUE "INFO" COLOR_RESET "] ", time_str);
    printf("Total found:   " COLOR_GREEN "%lu" COLOR_RESET "\n", found);
    
    printf(COLOR_DARK "[%s]" COLOR_RESET " [" COLOR_BLUE "INFO" COLOR_RESET "] ", time_str);
    printf("Total errors:  " COLOR_GRAY "%lu" COLOR_RESET "\n", errors);
    
    if (scanned > 0) {
        double success_rate = (double)found * 100.0 / scanned;
        printf(COLOR_DARK "[%s]" COLOR_RESET " [" COLOR_BLUE "INFO" COLOR_RESET "] ", time_str);
        printf("Success rate:  " COLOR_YELLOW "%.2f%%" COLOR_RESET "\n", success_rate);
    }
}

void ui_log(const char *level, const char *message) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[16];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    const char *color = COLOR_GRAY;
    if (strcmp(level, "INFO") == 0) color = COLOR_BLUE;
    else if (strcmp(level, "WARN") == 0 || strcmp(level, "WARNING") == 0) color = COLOR_YELLOW;
    else if (strcmp(level, "ERROR") == 0) color = COLOR_RED;

    pthread_mutex_lock(&ui_lock);
    ui_printing = 1;

    printf(CSI "999;1H");  // Move to bottom of scroll region
    printf("\n");
    printf(COLOR_DARK "[%s]" COLOR_RESET " [%s%s" COLOR_RESET "] %s\n",
           time_str, color, level, message);
    fflush(stdout);

    ui_printing = 0;
    pthread_mutex_unlock(&ui_lock);
}

void ui_print_shutdown_message(const char *message) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[16];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    
    pthread_mutex_lock(&ui_lock);
    ui_printing = 1;
    
    // Move to end of scroll region and add newline to scroll
    printf(CSI "999;1H");  // Move to bottom-right
    printf("\n");
    
    printf(COLOR_DARK "[%s]" COLOR_RESET " [" COLOR_YELLOW "WARN" COLOR_RESET "] %s\n", time_str, message);
    fflush(stdout);
    ui_printing = 0;
    pthread_mutex_unlock(&ui_lock);
}
