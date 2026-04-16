# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make                    # build → build/scanner
make clean && make      # full rebuild
make debug              # debug build (-g -O0)
make run                # build and run
make help               # show all targets

# Raw/synblast modes need CAP_NET_RAW (stripped by make, re-apply after each build):
sudo setcap cap_net_raw+ep build/scanner
```

Nix dev shell: `nix develop` provides clang, gdb, valgrind.

## Scan Modes

| Flag | Engine | Description |
|------|--------|-------------|
| (none) | EPOLL | Full SLP on every IP via kernel TCP |
| `-H` | HYBRID | Kernel connect prescan (1024 concurrent, 300ms) → SLP on hits. Works behind NAT |
| `-S` | SYNBLAST | Raw SYN prescan via AF_PACKET + BPF → SLP on hits. Needs public IP + CAP_NET_RAW |
| `-r` | RAW | Full userspace TCP via raw sockets. Needs CAP_NET_RAW |

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

EPOLL/RAW modes skip the prescan — workers scan directly.

### Module Boundaries

- `src/core/` — main.c (thread pool, CLI, signal handling), config, logging, settings.h (all tunables)
- `src/scanner/` — epoll-driven SLP scanner, IP ranges, dedup (64MB hash table), priority reorder, subnet stats, portscan prescan, hit queue
- `src/rawnet/` — raw socket scanner (rawscan), SYN prescan (synblast), TCP packet crafting (tcpkt)
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
