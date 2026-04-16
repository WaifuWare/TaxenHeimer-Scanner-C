# TaxenHeimer C Scanner

A high-performance Minecraft server scanner rewritten in C from the original Nim implementation.

## Features

- **Multi-threaded scanning** - 8 concurrent worker threads by default
- **Non-blocking socket pool** - Up to 128 concurrent connections per batch
- **Raw socket mode** - Optional kernel-bypass scanning via raw TCP SYN packets (requires `CAP_NET_RAW`)
- **Minecraft Server List Ping protocol** - Full VarInt-based implementation
- **Private IP filtering** - Skips RFC1918 and link-local ranges
- **Deduplication** - Tracks seen servers, only reports new or changed entries
- **Adaptive timeouts** - Per-/16 hit density adjusts socket timeouts dynamically
- **Subnet prioritization** - Reorders subnets by historical hit density (top 20% first)
- **Real-time TUI** - Live progress, rates, and recent hits
- **Persistent state** - Resumes from last scanned position via `config.json`
- **IPC reporting** - Unix domain socket transport to Go backend
- **Bundled cJSON** - No external JSON dependency
- **Runtime tuning script** - `tune.sh` applies optimal sysctls for high-fanout scanning

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
│   │   ├── scanner.c/h     - Core scanning logic
│   │   ├── ranges.c/h      - Known /16 subnet ranges
│   │   ├── dedup.c/h       - Server deduplication (new/changed/unchanged)
│   │   ├── priority.c/h    - Subnet reordering by hit density
│   │   └── subnet_stats.c/h - Per-/16 adaptive timeout tracking
│   ├── rawnet/
│   │   ├── rawscan.c/h     - Raw socket scanner (kernel-bypass mode)
│   │   └── tcpkt.c/h       - TCP packet crafting (SYN/ACK/RST)
│   ├── protocol/
│   │   └── packet.c/h      - Minecraft protocol packet handling
│   ├── net/
│   │   └── api.c/h         - IPC reporter to Go backend
│   ├── ui/
│   │   ├── ui.c/h          - Terminal UI
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

```bash
./scanner
```

Press `Ctrl+C` to stop. Current position is saved to `config.json` and resumed on next run.

### Raw Socket Mode

If the binary has `CAP_NET_RAW`, raw socket scanning activates automatically. This bypasses the kernel TCP stack for SYN scanning.

```bash
sudo setcap cap_net_raw+ep ./scanner
./scanner
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
   - `main.c` - Thread pool, signal handler, subnet distribution, pass management.
   - `config.c/h` - Atomic read/write of `config.json` for resume.
   - `log.c/h` - Leveled logging.
   - `settings.h` - All compile-time tunables.

2. **Scanner** (`src/scanner/`)
   - `scanner.c/h` - Per-IP status ping, response parsing via cJSON.
   - `ranges.c/h` - 700+ pre-identified /16 subnets.
   - `dedup.c/h` - Hash-based deduplication. Tracks server state and reports only `NEW` or `CHANGED` entries with a bitmask of changed fields (version, MOTD, players, max players).
   - `priority.c/h` - Reorders subnets by hit density. Top 20% by density scanned first, rest shuffled. Persists stats to `subnet_stats.json`.
   - `subnet_stats.c/h` - 256 KB static array indexed by `(ip >> 16)`. Tracks scanned/hit counts per /16 and provides adaptive timeouts.

3. **Raw Network** (`src/rawnet/`)
   - `rawscan.c/h` - Drop-in replacement for normal scanning using raw sockets. Requires `CAP_NET_RAW`.
   - `tcpkt.c/h` - TCP packet construction (SYN, ACK, RST), RFC 1071 checksums, local IP/interface detection.

4. **Protocol** (`src/protocol/`)
   - `packet.c/h` - VarInt codec, handshake/status/login packet construction.

5. **Network** (`src/net/`)
   - `api.c/h` - Framed JSON over Unix domain socket to Go backend; bounded concurrency.

6. **UI** (`src/ui/`)
   - `ui.c/h` - Terminal rendering.
   - `stats.c/h` - Mutex-protected counters, scan rate, hit count.

7. **Utilities** (`src/util/`)
   - `utils.c/h` - IP ↔ int conversion, private range check.

### Threading Model

Each of `NUM_THREADS` workers:
1. Gets a starting host offset (0 .. NUM_THREADS-1)
2. Strides by `NUM_THREADS` through current subnet
3. Advances to next subnet when all workers finish
4. Wraps to first subnet after full pass (subnets re-prioritized between passes)

Within a worker, up to `MAX_CONCURRENT_SCANS` non-blocking connects are in flight at once via the socket pool (or raw SYN packets in raw mode).

### Protocol Implementation

Minecraft Server List Ping (SLP):

1. **Handshake (0x00)** - protocol version, server addr, port, next state (1=Status)
2. **Status Request (0x00)** - empty
3. **Status Response (0x00)** - JSON with version, players, MOTD, favicon

Responses parsed with bundled cJSON. Dedup module compares against previous state before forwarding to API.

### Performance

- **Memory**: ~5–15 MB (socket pool + buffers + 256 KB subnet stats table)
- **CPU**: Scales with `NUM_THREADS`
- **Throughput**: ~2k–10k IPs/sec depending on network and timeouts

## IPC to Backend

Framed JSON messages over `IPC_SOCKET_PATH`. Go backend must be listening on that Unix socket before hits can be reported. Scanner continues scanning if backend is down; reports are dropped past `MAX_CONCURRENT_API`.

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

## Troubleshooting

### "Cannot connect to IPC socket"
Start the Go backend first, or check `IPC_SOCKET_PATH` matches on both sides.

### High CPU usage
Lower `NUM_THREADS` or `MAX_CONCURRENT_SCANS`.

### Low scan rate
- Raise `SCAN_BATCH`, `IP_POOL`, `MAX_CONCURRENT_SCANS`
- Lower `SOCKET_TIMEOUT_MS` (risks missing slow servers)
- Run `sudo ./tune.sh apply` to optimize kernel parameters
- Check bandwidth and conntrack limits (`net.netfilter.nf_conntrack_max`)

### Raw mode not activating
```bash
sudo setcap cap_net_raw+ep ./scanner
# verify:
getcap ./scanner
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
