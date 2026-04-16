# Makefile for TaxenHeimer C Scanner

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu11 -Isrc -Ilibs/cJSON -pthread
LDFLAGS = -pthread -lm

# Security hardening flags
CFLAGS += -fPIE -fPIC
CFLAGS += -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -Wformat -Wformat-security
CFLAGS += -fno-strict-overflow
LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

# Aggressive optimization flags (compatible with security)
CFLAGS += -O3 -march=native -mtune=native
CFLAGS += -flto=auto -ffunction-sections -fdata-sections
CFLAGS += -finline-functions
LDFLAGS += -flto=auto -Wl,--gc-sections -Wl,-O2

TARGET = scanner
SRCDIR = src
OBJDIR = obj
LIBDIR = libs/cJSON

# Source files — organized by domain
SOURCES = $(SRCDIR)/core/main.c \
          $(SRCDIR)/core/config.c \
          $(SRCDIR)/core/log.c \
          $(SRCDIR)/scanner/scanner.c \
          $(SRCDIR)/scanner/ranges.c \
          $(SRCDIR)/scanner/subnet_stats.c \
          $(SRCDIR)/scanner/dedup.c \
          $(SRCDIR)/scanner/priority.c \
          $(SRCDIR)/scanner/hitqueue.c \
          $(SRCDIR)/scanner/portscan.c \
          $(SRCDIR)/rawnet/rawscan.c \
          $(SRCDIR)/rawnet/tcpkt.c \
          $(SRCDIR)/rawnet/synblast.c \
          $(SRCDIR)/protocol/packet.c \
          $(SRCDIR)/net/api.c \
          $(SRCDIR)/ui/ui.c \
          $(SRCDIR)/ui/stats.c \
          $(SRCDIR)/util/utils.c \
          $(LIBDIR)/cJSON.c

# Object files
OBJECTS = $(SOURCES:%.c=$(OBJDIR)/%.o)

# Default target
.PHONY: all clean run debug install

all: $(TARGET)

# Link
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile
$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -rf $(OBJDIR) $(TARGET)
	@echo "Clean complete"

# Run
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG -O0
debug: clean $(TARGET)

# Install (optional)
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Show help
help:
	@echo "TaxenHeimer C Scanner - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build the scanner (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  run     - Build and run the scanner"
	@echo "  debug   - Build with debug symbols"
	@echo "  install - Install to /usr/local/bin"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Source layout:"
	@echo "  src/core/      - main, config, settings, logging"
	@echo "  src/scanner/   - scan engine, IP ranges, dedup, adaptive timeout"
	@echo "  src/rawnet/    - kernel-bypass raw socket scanner (--raw/--hybrid mode)"
	@echo "  src/protocol/  - Minecraft packet codec"
	@echo "  src/net/       - IPC batch sender"
	@echo "  src/ui/        - terminal UI, stats"
	@echo "  src/util/      - IP utilities"
