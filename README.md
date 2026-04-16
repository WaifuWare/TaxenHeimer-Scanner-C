# TaxenHeimer C Scanner

A high-performance Minecraft server scanner rewritten in C from the original Nim implementation.

## Features

- **Multi-threaded scanning** - 8 concurrent worker threads by default
- **Non-blocking socket pool** - Up to 128 concurrent connections per batch
- **Hybrid mode** - Fast connect prescan (1024 concurrent, 300ms timeout) filters open ports before full SLP. Works behind NAT.
- **Synblast mode** - Raw SYN prescan for maximum throughput on VPS/public IP (requires `CAP_NET_RAW`)
- **Raw socket mode** - Full kernel-bypass scanning via raw TCP SYN packets (requires `CAP_NET_RAW`)
- **Minecraft Server List Ping protocol** - Full VarInt-based implementation
- **Private IP filtering** - Skips RFC1918 and link-local ranges
- **Deduplication** - Tracks seen servers, only reports new or changed entries
- **Adaptive timeouts** - Per-/16 hit density adjusts socket timeouts dynamically
- **Subnet prioritization** - Reorders subnets by historical hit density (top 20% first)
- **Real-time TUI** - Live progress, rates, prescan stats, engine badge, and recent hits
- **Persistent state** - Resumes from last scanned position via `config.json`
- **IPC reporting** - Unix domain socket transport to Go backend with batch queuing and retry on shutdown
- **Bundled cJSON** - No external JSON dependency
- **Runtime tuning script** - `tune.sh` applies optimal sysctls for high-fanout scanning

## Scan Modes

| Flag | Engine | Method | Speed | Requirements |
|------|--------|--------|-------|-------------|
| (none) | `EPOLL` | Full SLP on every IP | ~2-10k IPs/sec | None |
| `-r` | `RAW` | Userspace TCP for everything | ~10-50k IPs/sec | `CAP_NET_RAW` |
| `-H` | `HYBRID` | Kernel connect prescan → SLP on hits | ~10-20k IPs/sec | None (works behind NAT) |
| `-S` | `SYNBLAST` | Raw SYN prescan → SLP on hits | ~100-500k IPs/sec | Public IP + `CAP_NET_RAW` |

**Hybrid** (`-H`) is recommended for most setups. It probes port 25565 with a fast 300ms non-blocking `connect()`, then only does full Minecraft SLP on the ~0.01% of IPs that respond. Works behind NAT since it uses the kernel TCP stack.

**Synblast** (`-S`) is for VPS/dedicated servers with a public IP. Blasts raw SYN packets and collects SYN-ACKs via AF_PACKET with BPF filtering. Does not work behind NAT (no conntrack entry for raw SYNs).

## Project Structure

```
TaxenHeimerC/
├── src/
│   ├── core/
│   │   ├── main.c          - Entry point, thread pool, signal handling
│   │   ├── config.c/h      - Persistent scan state (config.json)
│   │   ├── log.c/h         - Leveled logging
│   │   └── settings.h      - All tunables in one place
│   ├── scanner/
│   │   ├── scanner.c/h     - Core scanning logic (epoll-driven SLP)
│   │   ├── ranges.c/h      - Known /16 subnet ranges
│   │   ├── dedup.c/h       - Server deduplication (new/changed/unchanged)
│   │   ├── priority.c/h    - Subnet reordering by hit density
│   │   ├── subnet_stats.c/h - Per-/16 adaptive timeout tracking
│   │   ├── portscan.c/h    - Kernel connect prescan (hybrid mode)
│   │   └── hitqueue.c/h    - Thread-safe IP ring buffer (prescan → workers)
│   ├── rawnet/
│   │   ├── rawscan.c/h     - Raw socket scanner (kernel-bypass mode)
│   │   ├── synblast.c/h    - Raw SYN prescan with BPF filtering
│   │   └── tcpkt.c/h       - TCP packet crafting (SYN/ACK/RST)
│   ├── protocol/
│   │   └── packet.c/h      - Minecraft protocol packet handling
│   ├── net/
│   │   └── api.c/h         - IPC reporter to Go backend
│   ├── ui/
│   │   ├── ui.c/h          - Terminal UI with engine badge
│   │   └── stats.c/h       - Thread-safe statistics
│   └── util/
│       └── utils.c/h       - IP conversion and validation
├── libs/cJSON/              - Bundled cJSON parser
├── config.json              - Resume state (auto-generated)
├── subnet_stats.json        - Per-subnet hit counts (auto-generated)
├── tune.sh                  - Sysctl tuning script
├── flake.nix                - Nix flake for reproducible builds
├── Makefile
└── README.md
```

## Building

### Requirements

- GCC or Clang with C11 support (uses `gnu11` extensions)
- POSIX system (Linux, macOS, BSD)
- pthread
- Make

No external libraries needed. cJSON is vendored in `libs/cJSON/`.

### Compile

```bash
make
```

Build uses `-O3 -march=native -flto` plus hardening flags (`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, PIE, RELRO, NX).

**Note:** `make` rebuilds the binary, which strips `CAP_NET_RAW`. Re-apply after each build:
```bash
make && sudo setcap cap_net_raw+ep ./scanner
```

### Debug Build

```bash
make debug
```

### Clean

```bash
make clean
```

### Nix

```bash
nix develop   # enter dev shell
make
```

## Running

### Default (EPOLL)

```bash
./scanner
```

Press `Ctrl+C` to stop. Current position is saved to `config.json` and resumed on next run.

### Hybrid Mode (recommended)

Fast connect prescan, works behind NAT. No special capabilities needed.

```bash
./scanner --hybrid
```

### Synblast Mode (VPS only)

Raw SYN prescan for maximum throughput. Requires public IP and `CAP_NET_RAW`.

```bash
sudo setcap cap_net_raw+ep ./scanner
./scanner --synblast
```

### Raw Socket Mode

Full kernel-bypass scanning. Requires `CAP_NET_RAW`.

```bash
sudo setcap cap_net_raw+ep ./scanner
./scanner --raw
```

### Scan Range Options

```bash
./scanner --hybrid --known    # scan known Minecraft /16 subnets (default)
./scanner --hybrid --full     # scan entire routable IPv4 space
```

### Runtime Tuning

```bash
sudo ./tune.sh apply    # apply optimal sysctls (not persistent)
sudo ./tune.sh persist  # write to /etc/sysctl.d/99-taxenheimer.conf
sudo ./tune.sh show     # print current values
sudo ./tune.sh revert   # remove persistent config
```

## Configuration

All tunables live in `src/core/settings.h`. Edit and rebuild.

### Network
- `MINECRAFT_PORT` - Target port (default: 25565)
- `SOCKET_TIMEOUT_MS` - Connect/read timeout (default: 400ms)

### Scanning
- `NUM_THREADS` - Worker threads (default: 8)
- `SCAN_BATCH` - IPs per batch (default: 100)
- `IP_POOL` - IPs per thread iteration (default: 1000)
- `MAX_CONCURRENT_SCANS` - Simultaneous sockets per batch (default: 128)
- `RANGE_SCANNER_SUBNET` - Subnet size bits (default: 16)

### IPC
- `IPC_SOCKET_PATH` - Unix socket to Go backend (default: `/tmp/taxenheimer.sock`)
- `IPC_CONNECT_TIMEOUT_MS` - Connect timeout (default: 1000)
- `IPC_IO_TIMEOUT_MS` - Read/write timeout (default: 5000)
- `MAX_CONCURRENT_API` - Max parallel IPC senders (default: 20)

### Protocol
- `PROTOCOL_VERSION` - Minecraft protocol (default: 769 = 1.21.4)
- `MAX_PACKET_SIZE` - Packet buffer (default: 8192)

### Persistent State (`config.json`)

Auto-managed. Tracks `currentSubnetIdx`, `currentHostOffset`, `previousIP`, `scanMode`. Delete to restart from scratch.

## Architecture

### Components

1. **Core** (`src/core/`)
   - `main.c` - Thread pool, signal handler, subnet distribution, pass management. Raises FD limit at startup for high-concurrency modes.
   - `config.c/h` - Atomic read/write of `config.json` for resume.
   - `log.c/h` - Leveled logging.
   - `settings.h` - All compile-time tunables.

2. **Scanner** (`src/scanner/`)
   - `scanner.c/h` - Per-IP status ping, response parsing via cJSON. Epoll-driven async batch scanner.
   - `ranges.c/h` - 700+ pre-identified /16 subnets.
   - `dedup.c/h` - Hash-based deduplication. Tracks server state and reports only `NEW` or `CHANGED` entries with a bitmask of changed fields (version, MOTD, players, max players).
   - `priority.c/h` - Reorders subnets by hit density. Top 20% by density scanned first, rest shuffled. Persists stats to `subnet_stats.json`.
   - `subnet_stats.c/h` - 256 KB static array indexed by `(ip >> 16)`. Tracks scanned/hit counts per /16 and provides adaptive timeouts.
   - `portscan.c/h` - Kernel-based connect prescan for hybrid mode. 1024 concurrent non-blocking `connect()` probes with 300ms timeout. Pushes open ports to hit queue.
   - `hitqueue.c/h` - Thread-safe ring buffer (32K capacity) connecting prescan thread to worker threads.

3. **Raw Network** (`src/rawnet/`)
   - `rawscan.c/h` - Drop-in replacement for normal scanning using raw sockets. Requires `CAP_NET_RAW`.
   - `synblast.c/h` - Raw SYN prescan engine. Blasts SYNs via raw socket, collects SYN-ACKs on AF_PACKET with BPF filter (TCP + port range). Requires public IP + `CAP_NET_RAW`. Does not work behind NAT.
   - `tcpkt.c/h` - TCP packet construction (SYN, ACK, RST), RFC 1071 checksums, local IP/interface detection.

4. **Protocol** (`src/protocol/`)
   - `packet.c/h` - VarInt codec, handshake/status/login packet construction.

5. **Network** (`src/net/`)
   - `api.c/h` - Framed JSON over Unix domain socket to Go backend; bounded concurrency. Batches servers (256 cap, 15s age flush). Retries on shutdown with stderr diagnostics.

6. **UI** (`src/ui/`)
   - `ui.c/h` - Terminal rendering with engine badge (`EPOLL`/`RAW`/`HYBRID`/`SYNBLAST`), prescan stats row, progress bar.
   - `stats.c/h` - Mutex-protected counters, scan rate, hit count.

7. **Utilities** (`src/util/`)
   - `utils.c/h` - IP ↔ int conversion, private range check.

### Threading Model

**Default (EPOLL/RAW):** Each of `NUM_THREADS` workers strides through subnets and scans IPs directly.

**Hybrid/Synblast:** Producer-consumer architecture:
```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Prescan Thread  │────▶│  Hit Queue   │────▶│  N Worker Threads│
│  (portscan or    │     │  (ring buf)  │     │  (kernel TCP SLP)│
│   synblast)      │     │  32K slots   │     │  scan_batch_async│
└─────────────────┘     └──────────────┘     └─────────────────┘
```

1 prescan thread walks subnets and probes ports. Responsive IPs are pushed to a thread-safe ring buffer. 8 worker threads pull from the buffer and perform full Minecraft SLP.

### Protocol Implementation

Minecraft Server List Ping (SLP):

1. **Handshake (0x00)** - protocol version, server addr, port, next state (1=Status)
2. **Status Request (0x00)** - empty
3. **Status Response (0x00)** - JSON with version, players, MOTD, favicon

Responses parsed with bundled cJSON. Dedup module compares against previous state before forwarding to API.

### Performance

- **Memory**: ~5–15 MB (socket pool + buffers + 256 KB subnet stats table + 64 MB dedup table)
- **CPU**: Scales with `NUM_THREADS`
- **Throughput**:
  - EPOLL: ~2-10k IPs/sec
  - Hybrid: ~10-20k IPs/sec
  - Raw: ~10-50k IPs/sec
  - Synblast: ~100-500k IPs/sec (public IP only)

## IPC to Backend

Framed JSON messages over `IPC_SOCKET_PATH`. Protocol: `uint32 BE length + JSON body`; reply is `int32 BE` accepted count.

Go backend must be listening on the Unix socket. Scanner continues scanning if backend is down; reports are dropped past `MAX_CONCURRENT_API`. On shutdown, remaining batch is flushed synchronously with retry.

## Adding Custom Ranges

Edit `src/scanner/ranges.c`:

```c
const int32_t KNOWN_RANGES[] = {
    0x08080000,  // 8.8.0.0/16
    0x01010000,  // 1.1.0.0/16
};
```

IP to int32: `A.B.C.D/16 → (A << 24) | (B << 16)`

Example: `45.79.0.0/16` → `0x2D4F0000`

## Thread Safety

- `subnet_lock` - Subnet index + completion flags
- `stats.lock` - All counters
- `interrupted` - Atomic shutdown flag
- Config writes serialized through config module
- Dedup module uses internal locking
- Subnet stats array accessed atomically per /16 bucket
- Hit queue uses mutex + condvar for producer-consumer sync

## Troubleshooting

### "Cannot connect to IPC socket"
Start the Go backend first, or check `IPC_SOCKET_PATH` matches on both sides.

### "IPC socket() failed: fd exhaustion"
The scanner raises `RLIMIT_NOFILE` at startup, but if it still fails, increase the system limit:
```bash
ulimit -n 65536
```

### Hybrid mode shows `[EPOLL]` instead of `[HYBRID]`
Check the TUI log area for init errors. No special capabilities needed for hybrid — if it fails, report a bug.

### Synblast shows 0 SYN-ACKs
You're behind NAT. Synblast requires a public IP. Use `--hybrid` instead.

### High CPU usage
Lower `NUM_THREADS` or `MAX_CONCURRENT_SCANS`.

### Low scan rate
- Use `--hybrid` mode for 5-10x improvement
- Raise `SCAN_BATCH`, `IP_POOL`, `MAX_CONCURRENT_SCANS`
- Lower `SOCKET_TIMEOUT_MS` (risks missing slow servers)
- Run `sudo ./tune.sh apply` to optimize kernel parameters
- Check bandwidth and conntrack limits (`net.netfilter.nf_conntrack_max`)

### Raw/synblast mode not activating
```bash
sudo setcap cap_net_raw+ep ./scanner
# verify:
getcap ./scanner
# note: `make` strips capabilities — re-apply after each build
```

### Resume from start
```bash
rm config.json
```

### Reset subnet priorities
```bash
rm subnet_stats.json
```

### "Cannot find -lpthread"
```bash
# Debian/Ubuntu
sudo apt-get install libc6-dev
# Fedora/RHEL
sudo dnf install glibc-devel
```

## License

Same as original TaxenHeimer project.

## Credits

Rewritten in C from the original Nim implementation by taxmachine.

Original project: https://github.com/taxmachine/TaxenHeimer
