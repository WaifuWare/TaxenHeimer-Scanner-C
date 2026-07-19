# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make                    # build → build/scanner (+ xdp_filter.bpf.o if deps present)
make clean && make      # full rebuild
make debug              # debug build (-g -O0)
make run                # build and run
make help               # show all targets

# Raw/synblast modes need CAP_NET_RAW (stripped by make, re-apply after each build):
sudo setcap cap_net_raw+ep build/scanner

# XDP mode also needs NET_ADMIN + BPF + PERFMON (verifier pointer-compare):
sudo setcap cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon+ep build/scanner

# XDP build deps (Fedora): sudo dnf install libbpf-devel libxdp-devel clang
```

Nix dev shell: `nix develop` provides clang, gdb, valgrind.

## Scan Modes

| Flag | Engine | Description |
|------|--------|-------------|
| (none) | EPOLL | Full SLP on every IP via kernel TCP |
| `-H` | HYBRID | Kernel connect prescan (1024 concurrent, 300ms) → SLP on hits. Works behind NAT |
| `-S` | SYNBLAST | Raw SYN prescan via AF_PACKET + BPF → SLP on hits. Needs public IP + CAP_NET_RAW |
| `-r` | RAW | Full userspace TCP via raw sockets. Needs CAP_NET_RAW |
| `-u` | IOURING | Async SLP via io_uring (raw syscalls, no liburing dep). Kernel 5.6+, works behind NAT, no caps |
| `-b` | BEDROCK | UDP Unconnected Ping on port 19132 (RakNet). Works behind NAT, no caps |
| `-X -i IF` | XDP | eBPF SYN-ACK filter + AF_XDP ring. 5-15× over synblast on native-XDP NIC. Needs libbpf-devel + libxdp-devel + clang + CAP_NET_ADMIN + CAP_BPF |

Range flags: `-k`/`--known` (default, 715 subnets), `-f`/`--full` (all routable IPv4).

## Architecture

### Data Flow

```
prescan thread (portscan or synblast)
  → hit queue (thread-safe ring buffer, 32K slots)
    → N worker threads (scan_batch_async → Minecraft SLP)
      → on_server_found callback
        → dedup check → UI print → API batch queue
          → IPC to Go backend (/tmp/taxenheimer.sock)
```

EPOLL/RAW/IOURING/BEDROCK modes skip the prescan — workers scan directly.

### Module Boundaries

- `src/core/` — main.c (thread pool, CLI, signal handling), config, logging, settings.h (all tunables)
- `src/scanner/` — default epoll-driven SLP scanner (also hosts shared parsers), IP ranges, dedup (64MB hash table), priority reorder, subnet stats, hit queue
- `src/engines/` — alternative scan mode engines: `portscan` (hybrid prescan), `iouring`, `bedrock`, `rawscan`, `synblast`, `tcpkt`
- `src/protocol/` — Minecraft VarInt codec, handshake/status packet construction
- `src/net/` — IPC batch reporter (framed JSON over Unix socket, bounded concurrency)
- `src/ui/` — TUI with engine badge, prescan stats row, progress bar, thread-safe logging
- `src/util/` — IP ↔ int conversion, private range filtering

### IPC Protocol

Framed JSON: `uint32 BE length + JSON body`. Reply: `int32 BE` accepted count. Batch queue flushes at 256 servers or 15s age. Retries on shutdown. Reports to stderr if flush fails.

## Key Patterns

- **Adding a module**: Create `.c`/`.h` in appropriate subdirectory. Add `.c` to `SOURCES` in Makefile.
- **Settings**: All tunables in `src/core/settings.h`. Compile-time constants.
- **Thread safety**: `subnet_lock` for subnet state, `stats.lock` for counters, `interrupted` as atomic flag. Hit queue uses mutex + condvar.
- **FD limit**: Raised to hard limit at startup (`setrlimit`). Hybrid mode needs ~2048+ FDs.
- **Prescan backends**: `portscan_prescan()` and `synblast_prescan()` share the same interface — both take `(char ips[][16], int count, hit_queue_t *queue)`.
- **.gitignore**: Uses `build/` not `scanner` (old pattern matched `src/scanner/` directory).

## Config Files

- `config.json` — auto-managed resume state (subnet index, host offset, scan mode). Delete to restart.
- `subnet_stats.json` — per-/16 hit counts for priority reorder. Delete to reset priorities.
