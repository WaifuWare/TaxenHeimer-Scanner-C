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
CFLAGS += -O2 -march=native -mtune=native
CFLAGS += -flto -ffunction-sections -fdata-sections
CFLAGS += -finline-functions
LDFLAGS += -Wl,--gc-sections -Wl,-O2

# Check for libcurl
CURL_EXISTS := $(shell pkg-config --exists libcurl && echo yes)
ifeq ($(CURL_EXISTS),yes)
    CFLAGS += -DHAVE_CURL $(shell pkg-config --cflags libcurl)
    LDFLAGS += $(shell pkg-config --libs libcurl)
    $(info Building with libcurl support)
else
    $(info Building without libcurl - API reporting disabled)
endif

TARGET = scanner
SRCDIR = src
OBJDIR = obj
LIBDIR = libs/cJSON

# Source files
SOURCES = $(SRCDIR)/main.c \
          $(SRCDIR)/packet.c \
          $(SRCDIR)/scanner.c \
          $(SRCDIR)/utils.c \
          $(SRCDIR)/stats.c \
          $(SRCDIR)/ranges.c \
          $(SRCDIR)/api.c \
          $(SRCDIR)/ui.c \
          $(SRCDIR)/config.c \
          $(SRCDIR)/log.c \
          $(LIBDIR)/cJSON.c

# Object files
OBJECTS = $(SOURCES:%.c=$(OBJDIR)/%.o)

# Default target
.PHONY: all clean run debug install

all: $(TARGET)

# Create object directory
$(OBJDIR):
	mkdir -p $(OBJDIR)
	mkdir -p $(OBJDIR)/$(SRCDIR)
	mkdir -p $(OBJDIR)/$(LIBDIR)

# Link
$(TARGET): $(OBJDIR) $(OBJECTS)
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
