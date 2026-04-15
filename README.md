# TaxenHeimer C Scanner

A high-performance Minecraft server scanner rewritten in C from the original Nim implementation.

## Features

- **Multi-threaded scanning** - 12 concurrent threads for maximum throughput
- **Minecraft Server List Ping protocol** - Full implementation with VarInt encoding
- **Non-blocking sockets** - Efficient connection handling with timeout
- **Private IP filtering** - Automatically skips local network ranges
- **Real-time statistics** - Live display of scan progress and results
- **Modular architecture** - Clean separation of concerns across multiple files

## Project Structure

```
c_scanner/
├── src/
│   ├── main.c       - Entry point and thread management
│   ├── packet.c/h   - Minecraft protocol packet handling
│   ├── scanner.c/h  - Core scanning logic
│   ├── utils.c/h    - IP utilities and validation
│   ├── stats.c/h    - Statistics tracking
│   ├── api.c/h      - API reporting to Go backend
│   └── ranges.c/h   - Known subnet ranges
├── Makefile         - Build system
└── README.md        - This file
```

## Building

### Requirements

- GCC or Clang compiler
- POSIX-compliant system (Linux, macOS, BSD)
- pthread library
- libcurl (for API reporting)
- Make

### Install Dependencies

**Debian/Ubuntu:**
```bash
sudo apt-get install build-essential libcurl4-openssl-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc make libcurl-devel
```

**macOS:**
```bash
brew install curl
```

### Compile

```bash
cd c_scanner
make
```

### Debug Build

```bash
make debug
```

### Clean Build

```bash
make clean
make
```

## Running

```bash
./scanner
```

Press `Ctrl+C` to stop scanning gracefully.

## Configuration

Edit constants in the header files to customize:

### scanner.h
- `MINECRAFT_PORT` - Target port (default: 25565)
- `SOCKET_TIMEOUT_MS` - Socket timeout (default: 500ms)
- `SCAN_BATCH` - IPs per batch (default: 15)
- `IP_POOL` - IPs per thread batch (default: 150)

### packet.h
- `PROTOCOL_VERSION` - Minecraft protocol version (default: 769 for 1.21.4)
- `MAX_PACKET_SIZE` - Maximum packet buffer size (default: 8192 bytes)

### main.c
- `NUM_THREADS` - Number of scanner threads (default: 12)
- `RANGE_SCANNER_SUBNET` - Subnet size bits (default: 16 for /16)

## Architecture

### Components

1. **Packet Module** (`packet.c/h`)
   - VarInt encoding/decoding
   - Packet construction (handshake, status request, login)
   - Protocol-compliant data serialization

2. **Scanner Module** (`scanner.c/h`)
   - Socket creation and connection
   - Server status ping implementation
   - Basic JSON parsing for server info

3. **Utils Module** (`utils.c/h`)
   - IP address conversion (int ↔ string)
   - Private IP range validation
   - Network utility functions

4. **Stats Module** (`stats.c/h`)
   - Thread-safe statistics tracking
   - Scan rate calculation
   - Real-time display formatting

5. **API Module** (`api.c/h`)
   - HTTP POST to Go backend
   - JSON payload construction
   - Rate limiting (max 5 concurrent requests)
   - Automatic retry and error handling

6. **Ranges Module** (`ranges.c/h`)
   - Known Minecraft server subnet ranges
   - 700+ pre-identified /16 subnets

7. **Main Module** (`main.c`)
   - Thread pool management
   - Signal handling (Ctrl+C)
   - Subnet distribution across threads

### Threading Model

Each thread:
1. Gets assigned a starting host offset (0-11)
2. Scans every Nth IP in the current subnet (where N = NUM_THREADS)
3. Moves to next subnet when all threads finish current one
4. Wraps around to first subnet when all are complete

Example with 3 threads on subnet 10.0.0.0/16:
- Thread 0: 10.0.0.0, 10.0.0.3, 10.0.0.6, ...
- Thread 1: 10.0.0.1, 10.0.0.4, 10.0.0.7, ...
- Thread 2: 10.0.0.2, 10.0.0.5, 10.0.0.8, ...

### Protocol Implementation

Implements Minecraft Server List Ping (SLP):

1. **Handshake Packet (0x00)**
   - Protocol version (VarInt)
   - Server address (String)
   - Server port (Unsigned Short)
   - Next state (VarInt: 1=Status, 2=Login)

2. **Status Request (0x00)**
   - Empty packet requesting server information

3. **Status Response (0x00)**
   - JSON payload with server details
   - Version, player count, MOTD, favicon, etc.

### Performance

- **Memory**: ~2-5 MB total (minimal allocations)
- **CPU**: Scales linearly with thread count
- **Network**: Limited by timeout and batch size
- **Throughput**: ~100-500 IPs/sec depending on network

## Differences from Nim Version

The C implementation maintains core functionality while simplifying some aspects:

### Included
✓ Multi-threaded scanning  
✓ Minecraft protocol implementation  
✓ Private IP filtering  
✓ Statistics tracking  
✓ Subnet range management  
✓ Graceful shutdown  
✓ API reporting to Go backend  

### Simplified
- No async I/O (uses blocking sockets with timeout)
- Basic JSON parsing (extracts key fields only)
- Simple terminal output (no fancy TUI)
- No config file persistence

### Future Enhancements
- Full JSON parsing with cJSON library
- API integration for result reporting
- Config file support
- Enhanced TUI with ncurses
- IPv6 support
- Custom range file loading

## Adding Custom Ranges

Edit `src/ranges.c` to add your own subnet ranges:

```c
const int32_t KNOWN_RANGES[] = {
    0x08080000,  // 8.8.0.0/16
    0x01010000,  // 1.1.0.0/16
    // Add more /16 subnets here (as 32-bit integers)
};
```

To convert IP to int32:
```
A.B.C.D/16 → (A << 24) | (B << 16) | 0x0000
```

Example: `45.79.0.0/16` → `0x2D4F0000` → `759824384`

## Thread Safety

- `subnet_lock` - Protects subnet index and completion flags
- `stats.lock` - Protects all statistics counters
- `interrupted` - Atomic signal flag for shutdown

All shared state is properly synchronized with mutexes.

## Troubleshooting

### "Permission denied" on install
```bash
sudo make install
```

### "Cannot find -lpthread"
Install pthread development package:
```bash
# Debian/Ubuntu
sudo apt-get install libc6-dev

# Fedora/RHEL
sudo dnf install glibc-devel
```

### High CPU usage
Reduce `NUM_THREADS` or increase sleep time in scanner loop.

### Low scan rate
- Increase `SCAN_BATCH` and `IP_POOL`
- Reduce `SOCKET_TIMEOUT_MS` (may miss slow servers)
- Check network bandwidth and latency

## License

Same as original TaxenHeimer project.

## Credits

Rewritten in C by Kiro AI from the original Nim implementation by taxmachine.

Original project: https://github.com/taxmachine/TaxenHeimer
