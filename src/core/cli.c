#include "core/cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cli_opts_init(cli_opts_t *opts) {
    opts->full      = false;
    opts->raw       = false;
    opts->hybrid    = false;
    opts->synblast  = false;
    opts->iouring   = false;
    opts->bedrock   = false;
    opts->xdp       = false;
    opts->log_only  = false;
    opts->ifname    = NULL;
    opts->queue_id  = 0;
}

void cli_print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -f, --full       Scan the entire routable IPv4 space (default: known /16s)\n");
    printf("  -r, --raw        Use raw sockets (bypass kernel TCP, needs CAP_NET_RAW)\n");
    printf("  -H, --hybrid     Fast connect prescan + kernel TCP SLP (works behind NAT)\n");
    printf("  -S, --synblast   Raw SYN prescan + kernel TCP SLP (needs public IP + CAP_NET_RAW)\n");
    printf("  -u, --iouring    io_uring async SLP scan (kernel 5.6+, works behind NAT)\n");
    printf("  -b, --bedrock    Bedrock UDP scan on port 19132 (works behind NAT)\n");
    printf("  -X, --xdp        XDP prescan + kernel TCP SLP (needs libbpf/libxdp + CAP_NET_ADMIN)\n");
    printf("  -i, --iface IF   NIC name for -X (e.g. eth0, required with --xdp)\n");
    printf("  -q, --queue N    NIC queue id for -X (default 0)\n");
    printf("  -l, --log-only   Disable TUI; emit plain timestamped log lines (auto when stdout is not a TTY)\n");
    printf("  -h, --help       Show this help\n");
}

static int arg_is(const char *arg, const char *short_form, const char *long_form) {
    return strcmp(arg, short_form) == 0 || strcmp(arg, long_form) == 0;
}

cli_result_t cli_parse(int argc, char **argv, cli_opts_t *out) {
    cli_opts_init(out);

    const char *prog = (argc > 0 && argv[0]) ? argv[0] : "scanner";

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (arg_is(a, "-f", "--full"))         out->full = true;
        else if (arg_is(a, "-r", "--raw"))     out->raw = true;
        else if (arg_is(a, "-H", "--hybrid"))  out->hybrid = true;
        else if (arg_is(a, "-S", "--synblast")) out->synblast = true;
        else if (arg_is(a, "-u", "--iouring")) out->iouring = true;
        else if (arg_is(a, "-b", "--bedrock")) out->bedrock = true;
        else if (arg_is(a, "-X", "--xdp"))     out->xdp = true;
        else if (arg_is(a, "-l", "--log-only")) out->log_only = true;
        else if (arg_is(a, "-i", "--iface")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: --iface requires an argument\n", prog);
                return CLI_EXIT_FAIL;
            }
            out->ifname = argv[++i];
        }
        else if (arg_is(a, "-q", "--queue")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: --queue requires an argument\n", prog);
                return CLI_EXIT_FAIL;
            }
            out->queue_id = atoi(argv[++i]);
        }
        else if (arg_is(a, "-h", "--help")) {
            cli_print_usage(prog);
            return CLI_EXIT_OK;
        }
        else {
            fprintf(stderr, "%s: unknown option '%s'\n", prog, a);
            cli_print_usage(prog);
            return CLI_EXIT_FAIL;
        }
    }

    // XDP requires an interface. Fail fast rather than deep in xdp_init().
    if (out->xdp && (!out->ifname || !*out->ifname)) {
        fprintf(stderr, "%s: --xdp requires --iface <name>\n", prog);
        return CLI_EXIT_FAIL;
    }

    return CLI_OK;
}
