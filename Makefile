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

BUILDDIR = build
TARGET = $(BUILDDIR)/scanner
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

PGO_DIR = $(BUILDDIR)/pgo

# Default target
.PHONY: all clean run debug install pgo-generate pgo-use pgo

all: $(TARGET)

# Link
$(TARGET): $(OBJECTS)
	@mkdir -p $(BUILDDIR)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile
$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -rf $(OBJDIR) $(BUILDDIR)
	@echo "Clean complete"

# Run
run: $(TARGET)
	$(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG -O0
debug: clean $(TARGET)

# ── Profile-Guided Optimization ─────────────────────────────────────────────
# Two-step build. First `make pgo-generate` produces an instrumented binary;
# run it against a representative workload (e.g. a ~60 s scan). Then
# `make pgo-use` rebuilds using the collected .gcda profile data for ~3-5%
# additional speedup on branch-heavy paths (rx_process state machine, dedup
# probe loops, VarInt parse).
#
# Convenience target: `make pgo` runs both steps with a short default
# training run. Override with PGO_TRAIN_ARGS=... if you have a specific
# workload.
PGO_TRAIN_ARGS ?= --help

pgo-generate:
	@mkdir -p $(PGO_DIR)
	$(MAKE) clean
	$(MAKE) all CFLAGS="$(CFLAGS) -fprofile-generate=$(PGO_DIR) -fprofile-update=atomic" \
	            LDFLAGS="$(LDFLAGS) -fprofile-generate=$(PGO_DIR)"
	@echo "PGO instrumented binary ready at $(TARGET)."
	@echo "Run it against a representative workload, then: make pgo-use"

pgo-use:
	@if [ -z "$$(find $(PGO_DIR) -name '*.gcda' 2>/dev/null | head -1)" ]; then \
		echo "No profile data found in $(PGO_DIR). Run pgo-generate + a training run first."; \
		exit 1; \
	fi
	$(MAKE) clean
	$(MAKE) all CFLAGS="$(CFLAGS) -fprofile-use=$(PGO_DIR) -fprofile-correction" \
	            LDFLAGS="$(LDFLAGS) -fprofile-use=$(PGO_DIR) -fprofile-correction"
	@echo "PGO-optimized binary built at $(TARGET)."

pgo: pgo-generate
	@echo "Training with: $(TARGET) $(PGO_TRAIN_ARGS)"
	-$(TARGET) $(PGO_TRAIN_ARGS)
	$(MAKE) pgo-use

# Install (optional)
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Show help
help:
	@echo "TaxenHeimer C Scanner - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the scanner (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  run          - Build and run the scanner"
	@echo "  debug        - Build with debug symbols"
	@echo "  pgo-generate - Build instrumented binary for profiling"
	@echo "  pgo-use      - Rebuild using collected profile data"
	@echo "  pgo          - Run both PGO steps with default training args"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Source layout:"
	@echo "  src/core/      - main, config, settings, logging"
	@echo "  src/scanner/   - scan engine, IP ranges, dedup, adaptive timeout"
	@echo "  src/rawnet/    - kernel-bypass raw socket scanner (--raw/--hybrid mode)"
	@echo "  src/protocol/  - Minecraft packet codec"
	@echo "  src/net/       - IPC batch sender"
	@echo "  src/ui/        - terminal UI, stats"
	@echo "  src/util/      - IP utilities"
