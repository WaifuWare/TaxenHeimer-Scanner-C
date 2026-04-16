# TaxenHeimer C Scanner

A high-performance Minecraft server scanner rewritten in C from the original Nim implementation.

## Features

- **Multi-threaded scanning** - 16 concurrent threads by default
- **Non-blocking socket pool** - Up to 256 concurrent connections per batch
- **Minecraft Server List Ping protocol** - Full VarInt-based implementation
- **Private IP filtering** - Skips RFC1918 and link-local ranges
- **Real-time TUI** - Live progress, rates, and recent hits
- **Persistent state** - Resumes from last scanned position via `config.json`
- **IPC reporting** - Unix domain socket transport to Go backend
- **Bundled cJSON** - No external JSON dependency

## Project Structure

```
TaxenHeimerC/
├── src/
│   ├── main.c           - Entry point, thread pool, signal handling
│   ├── packet.c/h       - Minecraft protocol packet handling
│   ├── scanner.c/h      - Core scanning logic
│   ├── socket_pool.c/h  - Non-blocking connection pool
│   ├── utils.c/h        - IP conversion and validation
│   ├── stats.c/h        - Thread-safe statistics
│   ├── api.c/h          - IPC reporter to Go backend
│   ├── ranges.c/h       - Known /16 subnet ranges
│   ├── config.c/h       - Persistent scan state (config.json)
│   ├── log.c/h          - Logging
│   ├── ui.c/h           - Terminal UI
│   └── settings.h       - All tunables in one place
├── libs/cJSON/          - Bundled cJSON parser
├── config.json          - Resume state (auto-generated)
├── Makefile
└── README.md
```

## Building

### Requirements

- GCC or Clang with C11 support
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

## Running

```bash
./scanner
```

Press `Ctrl+C` to stop. Current position is saved to `config.json` and resumed on next run.

## Configuration

All tunables live in `src/settings.h`. Edit and rebuild.

### Network
- `MINECRAFT_PORT` - Target port (default: 25565)
- `SOCKET_TIMEOUT_MS` - Connect/read timeout (default: 400ms)

### Scanning
- `NUM_THREADS` - Worker threads (default: 16)
- `SCAN_BATCH` - IPs per batch (default: 200)
- `IP_POOL` - IPs per thread iteration (default: 3000)
- `MAX_CONCURRENT_SCANS` - Simultaneous sockets per batch (default: 256)
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

Auto-managed. Tracks `currentSubnetIdx`, `currentHostOffset`, `previousIP`. Delete to restart from scratch.

## Architecture

### Components

1. **Packet** (`packet.c/h`) - VarInt codec, handshake/status/login construction.
2. **Scanner** (`scanner.c/h`) - Per-IP status ping, response parsing via cJSON.
3. **Socket Pool** (`socket_pool.c/h`) - Non-blocking fd pool, `epoll`/`select`-driven concurrency within a batch.
4. **Utils** (`utils.c/h`) - IP ↔ int, private range check.
5. **Stats** (`stats.c/h`) - Mutex-protected counters, scan rate, hit count.
6. **API** (`api.c/h`) - Framed JSON over Unix domain socket to Go backend; bounded concurrency.
7. **Ranges** (`ranges.c/h`) - 700+ pre-identified /16 subnets.
8. **Config** (`config.c/h`) - Atomic read/write of `config.json` for resume.
9. **Log** (`log.c/h`) - Leveled logging.
10. **UI** (`ui.c/h`) - Terminal rendering.
11. **Main** (`main.c`) - Thread pool, signal handler, subnet distribution.

### Threading Model

Each of `NUM_THREADS` workers:
1. Gets a starting host offset (0 .. NUM_THREADS-1)
2. Strides by `NUM_THREADS` through current subnet
3. Advances to next subnet when all workers finish
4. Wraps to first subnet after full pass

Within a worker, up to `MAX_CONCURRENT_SCANS` non-blocking connects are in flight at once via the socket pool.

### Protocol Implementation

Minecraft Server List Ping (SLP):

1. **Handshake (0x00)** - protocol version, server addr, port, next state (1=Status)
2. **Status Request (0x00)** - empty
3. **Status Response (0x00)** - JSON with version, players, MOTD, favicon

Responses parsed with bundled cJSON.

### Performance

- **Memory**: ~5–15 MB (socket pool + buffers)
- **CPU**: Scales with `NUM_THREADS`
- **Throughput**: ~2k–10k IPs/sec depending on network and timeouts

## IPC to Backend

Framed JSON messages over `IPC_SOCKET_PATH`. Go backend must be listening on that Unix socket before hits can be reported. Scanner continues scanning if backend is down; reports are dropped past `MAX_CONCURRENT_API`.

## Adding Custom Ranges

Edit `src/ranges.c`:

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

## Troubleshooting

### "Cannot connect to IPC socket"
Start the Go backend first, or check `IPC_SOCKET_PATH` matches on both sides.

### High CPU usage
Lower `NUM_THREADS` or `MAX_CONCURRENT_SCANS`.

### Low scan rate
- Raise `SCAN_BATCH`, `IP_POOL`, `MAX_CONCURRENT_SCANS`
- Lower `SOCKET_TIMEOUT_MS` (risks missing slow servers)
- Check bandwidth and conntrack limits (`net.netfilter.nf_conntrack_max`)

### Resume from start
```bash
rm config.json
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
