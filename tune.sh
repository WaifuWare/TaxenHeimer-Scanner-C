#!/usr/bin/env bash
#
# Runtime tuning for TaxenHeimer C scanner.
# Applies sysctls and rlimits optimal for high-fanout TCP connect scanning.
#
# Usage:
#   sudo ./tune.sh apply    # apply settings (not persistent across reboot)
#   sudo ./tune.sh persist  # write to /etc/sysctl.d/99-taxenheimer.conf
#   sudo ./tune.sh show     # print current values
#   sudo ./tune.sh revert   # remove persistent file
#
set -euo pipefail

SYSCTL_FILE="/etc/sysctl.d/99-taxenheimer.conf"

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "error: must run as root (use sudo)" >&2
        exit 1
    fi
}

# key=value pairs
declare -a SETTINGS=(
    # Expand ephemeral port range — default is 32768-60999, giving ~28k ports.
    # Scanner chews through these fast. Raise floor to 10000 for ~55k ports.
    "net.ipv4.ip_local_port_range=10000 65535"

    # Reuse sockets sitting in TIME_WAIT for new outgoing connections.
    # Safe for clients; risky for servers behind NAT.
    "net.ipv4.tcp_tw_reuse=1"

    # Faster FIN handling — lower the timeout from default 60s.
    "net.ipv4.tcp_fin_timeout=15"

    # Allow more half-open connections.
    "net.ipv4.tcp_max_syn_backlog=8192"

    # Orphaned socket ceiling — lots of short-lived scanner sockets.
    "net.ipv4.tcp_max_orphans=65536"

    # Raise max file descriptors system-wide.
    "fs.file-max=2097152"

    # Netfilter conntrack ceiling — only matters if conntrack module is loaded.
    # Scanner creates one conntrack entry per scanned IP.
    "net.netfilter.nf_conntrack_max=524288"

    # Lower conntrack TIME_WAIT so entries expire quickly.
    "net.netfilter.nf_conntrack_tcp_timeout_time_wait=30"

    # Larger socket buffers — helps parallel recv throughput.
    "net.core.rmem_max=16777216"
    "net.core.wmem_max=16777216"

    # Backlog for incoming packets (not critical for scanner, but cheap).
    "net.core.netdev_max_backlog=16384"
)

apply_settings() {
    need_root
    echo "Applying sysctls..."
    for kv in "${SETTINGS[@]}"; do
        key="${kv%%=*}"
        val="${kv#*=}"
        # Skip nf_conntrack keys if module not loaded
        if [[ "$key" == net.netfilter.nf_conntrack* ]]; then
            if [[ ! -e "/proc/sys/${key//.//}" ]]; then
                echo "  skip $key (conntrack not loaded)"
                continue
            fi
        fi
        if sysctl -w "$key=$val" >/dev/null 2>&1; then
            printf "  ok   %s = %s\n" "$key" "$val"
        else
            printf "  fail %s (not writable)\n" "$key" >&2
        fi
    done

    echo
    echo "Raising file descriptor limit for current shell..."
    ulimit -n 1048576 2>/dev/null && echo "  ulimit -n = $(ulimit -n)" || echo "  ulimit raise failed (needs /etc/security/limits.conf)"

    echo
    echo "Done. Settings are live but will reset on reboot. Run 'persist' to make permanent."
}

persist_settings() {
    need_root
    echo "Writing $SYSCTL_FILE..."
    {
        echo "# TaxenHeimer scanner tuning — generated $(date -Iseconds)"
        for kv in "${SETTINGS[@]}"; do
            key="${kv%%=*}"
            val="${kv#*=}"
            if [[ "$key" == net.netfilter.nf_conntrack* ]]; then
                if [[ ! -e "/proc/sys/${key//.//}" ]]; then
                    echo "# $key = $val  (skipped — conntrack not loaded)"
                    continue
                fi
            fi
            echo "$key = $val"
        done
    } > "$SYSCTL_FILE"
    chmod 0644 "$SYSCTL_FILE"
    sysctl --system >/dev/null
    echo "Persisted. Reload with: sudo sysctl --system"

    echo
    echo "NOTE: To persist ulimit -n across sessions, add to /etc/security/limits.conf:"
    echo "    *    soft    nofile    1048576"
    echo "    *    hard    nofile    1048576"
}

show_settings() {
    echo "Current values:"
    for kv in "${SETTINGS[@]}"; do
        key="${kv%%=*}"
        path="/proc/sys/${key//.//}"
        if [[ -e "$path" ]]; then
            printf "  %-55s = %s\n" "$key" "$(cat "$path")"
        else
            printf "  %-55s = (not available)\n" "$key"
        fi
    done
    echo
    echo "  ulimit -n (current shell)              = $(ulimit -n)"
}

revert_settings() {
    need_root
    if [[ -f "$SYSCTL_FILE" ]]; then
        rm -f "$SYSCTL_FILE"
        echo "Removed $SYSCTL_FILE"
        echo "Reboot or reload defaults with: sudo sysctl --system"
    else
        echo "No persistent file to remove."
    fi
}

rawmode_on() {
    need_root
    echo "Enabling raw socket mode iptables rules..."
    # Suppress kernel RSTs for our source port range. The userspace TCP
    # stack manages connections — kernel RSTs would kill them.
    if iptables -C OUTPUT -p tcp --sport 40000:48191 --tcp-flags RST RST -j DROP 2>/dev/null; then
        echo "  iptables RST rule already present"
    else
        iptables -I OUTPUT -p tcp --sport 40000:48191 --tcp-flags RST RST -j DROP
        echo "  ok   iptables RST suppression for ports 40000-48191"
    fi
    echo
    echo "Run scanner with: ./scanner --raw"
}

rawmode_off() {
    need_root
    echo "Removing raw socket mode iptables rules..."
    if iptables -D OUTPUT -p tcp --sport 40000:48191 --tcp-flags RST RST -j DROP 2>/dev/null; then
        echo "  Removed RST suppression rule"
    else
        echo "  No rule to remove"
    fi
}

case "${1:-}" in
    apply)      apply_settings ;;
    persist)    persist_settings ;;
    show)       show_settings ;;
    revert)     revert_settings ;;
    rawmode-on) rawmode_on ;;
    rawmode-off)rawmode_off ;;
    *)
        echo "usage: $0 {apply|persist|show|revert|rawmode-on|rawmode-off}"
        exit 1
        ;;
esac
