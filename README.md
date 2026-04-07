# ProcFlow

eBPF-based host network flow monitor with process enrichment and Wireshark/IDS correlation metadata.

Captures TCP, UDP, and ICMP traffic on a Linux host and emits newline-delimited JSON. Every record is enriched with the process name, full executable path, command line, UID, socket inode (for `ss`/Wireshark correlation), network namespace (container detection), and — for inbound SSH sessions — the authenticated PAM username.

## Requirements

- Ubuntu 20.04+ or Debian 11+ (amd64)
- Linux kernel 4.9+
- Root privileges

## Install

```bash
curl -sSL https://raw.githubusercontent.com/fitz17777/procflow/main/install.sh | sudo bash
```

The installer will:
1. Install `linux-headers-$(uname -r)`, `python3-bpfcc`, and `bpfcc-tools`
2. Download and install the `.deb` package
3. Enable and start the `procflow` systemd service

## Quick start

```bash
# Watch live output
sudo journalctl -u procflow -f

# Or run interactively
sudo procflow --stdout-only | jq .
```

## Service management

```bash
sudo systemctl status procflow
sudo systemctl restart procflow
sudo systemctl stop procflow

# View recent log output
sudo journalctl -u procflow -n 50

# Truncate the log without restarting the service
sudo procflow --clear-log
```

## Log file

```
/var/log/procflow/enriched_flow.log
```

Rotates at 50 MB, retains 5 backups (250 MB total). Mode `640` — readable by root and the `adm` group. Treat it with the same care as `/var/log/auth.log`.

## Event types

| Event type | When emitted |
|---|---|
| `flow_short` | TCP closed before 30s, any UDP socket close, any ICMP packet |
| `flow_long_open` | TCP still open at 30s — snapshot of bytes so far |
| `flow_long_closed` | Long-lived TCP finally closed — final byte counts |
| `connect_failed` | Outbound TCP rejected: ECONNREFUSED, ETIMEDOUT, ENETUNREACH, EHOSTUNREACH |
| `listen_start` | TCP socket entered LISTEN state |

`flow_long_open` and `flow_long_closed` are linked by `session_id`.

## Key fields

| Field | Description |
|---|---|
| `process` | Executable name from `/proc/{pid}/comm` (group leader, not thread name) |
| `exe` | Full path from `/proc/{pid}/exe` — disambiguates `python3`, `java`, `node` |
| `cmdline` | Full command line from `/proc/{pid}/cmdline` |
| `proto_hint` | Application label by port: `SSH`, `HTTPS`, `HTTP`, `DNS`, `QUIC`, `mDNS`, `NTP`, `RDP`, … |
| `sock_ino` | Socket inode — matches `ss -tnp` inode for exact Wireshark correlation |
| `netns_ino` | Network namespace inode — differs from host for container traffic |
| `container_traffic` | `true` when `netns_ino` differs from `/proc/1/ns/net` |
| `dns_query` | Decoded DNS QNAME when `proto_hint` is `DNS` |
| `connect_error` | Error name for `connect_failed` events |
| `local_ip` / `local_port` | Listening address/port for `listen_start` events |
| `authenticated_user` | PAM-authenticated username for inbound TCP (SSH) |
| `tx_bytes` / `rx_bytes` | Bytes transferred, accumulated in kernel space |

## Example output

**Outbound HTTPS:**
```json
{
  "timestamp": "2026-04-07T00:23:25.407914+00:00",
  "event_type": "flow_short",
  "direction": "outbound",
  "process": "curl",
  "exe": "/usr/bin/curl",
  "cmdline": "curl https://github.com/fitz17777/procflow",
  "protocol": "TCP",
  "proto_hint": "HTTPS",
  "src_ip": "10.10.20.101",
  "src_port": 52598,
  "dst_ip": "140.82.114.3",
  "dst_port": 443,
  "sock_ino": 137397,
  "container_traffic": false,
  "tx_bytes": 811,
  "rx_bytes": 822613
}
```

**Inbound SSH with PAM enrichment:**
```json
{
  "timestamp": "2026-04-07T00:21:38.407290+00:00",
  "event_type": "flow_short",
  "direction": "inbound",
  "process": "sshd",
  "exe": "/usr/sbin/sshd",
  "protocol": "TCP",
  "proto_hint": "SSH",
  "src_ip": "10.10.10.10",
  "src_port": 35646,
  "dst_ip": "10.10.20.101",
  "dst_port": 22,
  "authenticated_user": "user-01",
  "pam_service": "sshd",
  "tx_bytes": 209043,
  "rx_bytes": 14301
}
```

**Failed connection:**
```json
{
  "event_type": "connect_failed",
  "connect_error": "ECONNREFUSED",
  "process": "curl",
  "exe": "/usr/bin/curl",
  "cmdline": "curl http://127.0.0.1:9999",
  "dst_ip": "127.0.0.1",
  "dst_port": 9999
}
```

**New listening port:**
```json
{
  "event_type": "listen_start",
  "process": "python3",
  "exe": "/usr/bin/python3.12",
  "cmdline": "python3 -m http.server 8080",
  "protocol": "TCP",
  "local_ip": "0.0.0.0",
  "local_port": 8080
}
```

**DNS query:**
```json
{
  "event_type": "flow_short",
  "process": "systemd-resolve",
  "protocol": "UDP",
  "proto_hint": "DNS",
  "dst_ip": "10.10.20.5",
  "dst_port": 53,
  "dns_query": "github.com",
  "tx_bytes": 39,
  "rx_bytes": 110
}
```

## Useful jq queries

```bash
# All completed flows
sudo procflow --stdout-only | jq 'select(.event_type == "flow_short")'

# Failed outbound connections (port scans, misconfigured apps)
sudo procflow --stdout-only | jq 'select(.event_type == "connect_failed")'

# New listening ports
sudo procflow --stdout-only | jq 'select(.event_type == "listen_start")'

# Container traffic only
sudo procflow --stdout-only | jq 'select(.container_traffic == true)'

# DNS queries with decoded names
sudo procflow --stdout-only | jq 'select(.dns_query != null) | {process, dns_query, dst_ip}'

# ICMP traffic (outbound and inbound)
sudo procflow --stdout-only | jq 'select(.protocol == "ICMP")'

# Correlate with ss by socket inode
ss -tnp | grep 10.10.10.10
# note the inode from the users column, then:
jq 'select(.sock_ino == 137397)' /var/log/procflow/enriched_flow.log

# Traffic to a specific host
jq 'select(.dst_ip == "140.82.114.3")' /var/log/procflow/enriched_flow.log

# Inbound SSH sessions — who connected and how much data
jq 'select(.proto_hint == "SSH" and .direction == "inbound") | {src_ip, authenticated_user, tx_bytes, rx_bytes}' \
  /var/log/procflow/enriched_flow.log
```

## Wireshark / IDS correlation

**Unknown traffic in Wireshark:**
1. Note the dst IP and port from Wireshark
2. Query procflow: `jq 'select(.dst_ip=="x.x.x.x" and .dst_port==Y)'`
3. Get `process`, `exe`, `cmdline` for the definitive answer
4. For live traffic: `ss -tnp | grep x.x.x.x` → note inode → match `sock_ino`

**IDS alert fires:**
1. Check `listen_start` to see which process opened the flagged port
2. Check `connect_failed` to detect local port scanning or beacon failures
3. Check `container_traffic: true` to redirect investigation to the container layer
4. Correlate by timestamp + 5-tuple to get process and user context

## Configuration

Edit `/etc/procflow/procflow.conf`:

```ini
[logging]
log_file = /var/log/procflow/enriched_flow.log
max_bytes = 52428800   # 50 MB
backup_count = 5

[tuning]
# pam_collect_secs = 1.0    # window to collect PAM_SERVICE after PAM_USER
# pam_window_secs  = 15.0   # max wait for PAM match on inbound TCP
# flow_short_secs  = 30.0   # threshold between flow_short and flow_long
# flow_track_secs  = 3600.0 # evict stale open flows after this long
```

Restart after changes: `sudo systemctl restart procflow`

## Manual install

```bash
sudo apt install linux-headers-$(uname -r) python3-bpfcc bpfcc-tools
wget https://github.com/fitz17777/procflow/releases/latest/download/procflow_1.1.0_amd64.deb
sudo dpkg -i procflow_1.1.0_amd64.deb
```

## Uninstall

```bash
sudo dpkg -r procflow
```

Stops and disables the service and removes all installed files. The log directory `/var/log/procflow/` and config `/etc/procflow/` are left in place.

## Man page

```bash
man procflow
```
