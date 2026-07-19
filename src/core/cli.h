/*
 * TaxenHeimer CLI parser
 *
 * Self-contained arg parser. Fill a cli_opts_t, validate it, print help.
 * Library-shaped so other entry points (future test harnesses, alternate
 * front-ends) can reuse it without dragging in main's scan plumbing.
 */

#ifndef TAXENHEIMER_CLI_H
#define TAXENHEIMER_CLI_H

#include <stdbool.h>

typedef struct {
    bool full;           // -f / --full
    bool raw;            // -r / --raw
    bool hybrid;         // -H / --hybrid
    bool synblast;       // -S / --synblast
    bool iouring;        // -u / --iouring
    bool bedrock;        // -b / --bedrock
    bool xdp;            // -X / --xdp
    bool log_only;       // -l / --log-only
    const char *ifname;  // -i / --iface
    int  queue_id;       // -q / --queue
} cli_opts_t;

typedef enum {
    CLI_OK        =  0,  // parse succeeded
    CLI_EXIT_OK   =  1,  // --help was shown, exit 0
    CLI_EXIT_FAIL = -1,  // parse error, exit non-zero
} cli_result_t;

void cli_opts_init(cli_opts_t *opts);

// Parse argv. On CLI_EXIT_OK caller should `return 0`. On CLI_EXIT_FAIL
// caller should `return 1`. Usage is printed to stdout (help) or stderr
// (errors) inside the parser.
cli_result_t cli_parse(int argc, char **argv, cli_opts_t *out);

void cli_print_usage(const char *prog);

#endif /* TAXENHEIMER_CLI_H */
