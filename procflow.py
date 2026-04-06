#!/usr/bin/env python3
"""
procflow - eBPF-based host network flow monitor with PAM enrichment.

Captures TCP (inbound + outbound) and UDP flows using eBPF kprobes, enriched
with host OS context: process name, PID, UID/username, and — for inbound TCP
sessions — the authenticated PAM username. sshd privsep forks are handled
correctly via /proc ancestry walking.

Event types emitted as newline-delimited JSON:
  flow_short      — connection closed before flow_short_secs (default 30s), or
                    any UDP flow. Single record with full context + byte counts.
  flow_long_open  — emitted at the flow_short_secs mark for still-open TCP.
                    Snapshot of context and bytes transferred so far.
  flow_long_closed — emitted when a long-lived TCP session finally closes.
                    Includes total byte counts. Correlates to flow_long_open
                    via matching session_id (UUID4).

PAM events with no correlated network flow are silently discarded — this tool
only enriches network events, it does not log standalone authentication activity.

Byte counting:
  TX/RX bytes are accumulated per-socket in kernel space via tcp_sendmsg,
  tcp_cleanup_rbuf, udp_sendmsg, and udp_recvmsg kprobes. Final counts are
  delivered at close time via tcp_close / udp_destroy_sock kprobes.

Requirements:
    sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
"""

VERSION = "1.0.2"

import argparse
import configparser
import json
import ctypes
import logging
import socket
import struct
import pwd
import glob
import time
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from logging.handlers import RotatingFileHandler

try:
    from bcc import BPF
except ImportError:
    print(json.dumps({
        "error": "bcc library not found",
        "fix": "sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)"
    }))
    raise SystemExit(1)


# ─── Find libpam at runtime ───────────────────────────────────────────────────
def find_libpam() -> str:
    patterns = [
        "/lib/*/libpam.so.0",
        "/lib/libpam.so.0",
        "/usr/lib/*/libpam.so.0",
        "/usr/lib/libpam.so.0",
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    raise FileNotFoundError(
        "libpam.so.0 not found. Install with: sudo apt install libpam-runtime"
    )


# ─── eBPF C program ───────────────────────────────────────────────────────────
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/sched.h>

#define DIR_OUTBOUND 0
#define DIR_INBOUND  1
#define EVT_FLOW     0
#define EVT_PAM      1
#define EVT_CLOSE    2

#define PAM_SERVICE  1
#define PAM_USER     2

struct event_t {
    u8   evt_type;

    // Flow fields
    u64  ts_ns;
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[TASK_COMM_LEN];
    u32  af;
    u32  saddr4;
    u32  daddr4;
    u8   saddr6[16];
    u8   daddr6[16];
    u16  sport;
    u16  dport;
    u8   proto;
    u8   direction;

    // PAM fields
    char pam_username[64];
    char pam_service[32];

    // Byte count fields (populated for EVT_CLOSE)
    u64  tx_bytes;
    u64  rx_bytes;

    // Socket pointer — populated for EVT_FLOW; used by Python for mid-session reads
    u64  sock_ptr;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(tcp4_pending,    u64, struct sock *);
BPF_HASH(tcp6_pending,    u64, struct sock *);
BPF_HASH(udp_recv_pending, u64, u64);          // pid_tgid → sock ptr (for kretprobe)

// Byte count tracking — keyed by sock* cast to u64
struct byte_count_t {
    u64 tx_bytes;
    u64 rx_bytes;
};
// 65536 entries ≈ 5 MB — covers ~65K concurrent connections before silent drop.
// If byte counts show as 0 on a high-churn host, this map is likely full.
BPF_HASH(sock_bytes,    u64, struct byte_count_t, 65536);
BPF_HASH(tracked_socks, u64, u8,                  65536);

// PAM tracking: stash entry args so retprobe can use them
struct pam_entry_args_t {
    int   item_type;
    void *item_pp;
};
BPF_HASH(pam_entry, u64, struct pam_entry_args_t);

// Accumulate PAM_USER + PAM_SERVICE across calls before emitting
struct pam_info_t {
    char pam_username[64];
    char pam_service[32];
    u8   has_user;
    u8   has_service;
};
BPF_HASH(pam_info, u32, struct pam_info_t);  // keyed by pid


// ── Helper: PPID from task_struct ────────────────────────────────────────────
static inline u32 get_ppid() {
    struct task_struct *task   = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    u32 ppid = 0;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read(&ppid,   sizeof(ppid),   &parent->tgid);
    return ppid;
}


// ════════════════════════════════════════════════════════════════════════════
//  PAM — hook pam_get_item() entry + return
//
//  We capture PAM_SERVICE (1) first, then PAM_USER (2).
//  Only emit the event once we have PAM_USER; include service if already seen.
//  Emitting on PAM_USER instead of PAM_SERVICE avoids the null service issue.
// ════════════════════════════════════════════════════════════════════════════

int uprobe__pam_get_item(struct pt_regs *ctx) {
    int item_type = (int)PT_REGS_PARM2(ctx);
    if (item_type != PAM_USER && item_type != PAM_SERVICE)
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    struct pam_entry_args_t args = {};
    args.item_type = item_type;
    args.item_pp   = (void *)PT_REGS_PARM3(ctx);
    pam_entry.update(&id, &args);
    return 0;
}

int uretprobe__pam_get_item(struct pt_regs *ctx) {
    if ((int)PT_REGS_RC(ctx) != 0)
        goto cleanup;

    {
        u64 id  = bpf_get_current_pid_tgid();
        u32 pid = id >> 32;

        struct pam_entry_args_t *args = pam_entry.lookup(&id);
        if (!args) return 0;

        // Dereference **item → char *str
        char *str_ptr = NULL;
        bpf_probe_read_user(&str_ptr, sizeof(str_ptr), args->item_pp);
        if (!str_ptr) goto cleanup;

        // Initialise accumulator if first call for this pid
        struct pam_info_t empty = {};
        struct pam_info_t *info = pam_info.lookup(&pid);
        if (!info) {
            pam_info.update(&pid, &empty);
            info = pam_info.lookup(&pid);
            if (!info) goto cleanup;
        }

        if (args->item_type == PAM_SERVICE && !info->has_service) {
            bpf_probe_read_user_str(info->pam_service,
                                    sizeof(info->pam_service), str_ptr);
            info->has_service = 1;
            // Don't emit yet — wait for PAM_USER
            pam_entry.delete(&id);
            return 0;
        }

        if (args->item_type == PAM_USER) {
            bpf_probe_read_user_str(info->pam_username,
                                    sizeof(info->pam_username), str_ptr);
            info->has_user = 1;

            // Now we have the username — emit the event
            struct event_t ev = {};
            ev.evt_type = EVT_PAM;
            ev.ts_ns    = bpf_ktime_get_ns();
            ev.pid      = pid;
            ev.ppid     = get_ppid();
            ev.uid      = bpf_get_current_uid_gid() & 0xffffffff;
            bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

            bpf_probe_read_kernel(&ev.pam_username, sizeof(ev.pam_username),
                                  info->pam_username);
            bpf_probe_read_kernel(&ev.pam_service,  sizeof(ev.pam_service),
                                  info->pam_service);

            // Clean up — next pam_get_item call will start fresh
            pam_info.delete(&pid);
            pam_entry.delete(&id);
            events.perf_submit(ctx, &ev, sizeof(ev));
            return 0;
        }
    }

cleanup:
    {
        u64 id = bpf_get_current_pid_tgid();
        pam_entry.delete(&id);
    }
    return 0;
}


// ════════════════════════════════════════════════════════════════════════════
//  OUTBOUND TCP IPv4
// ════════════════════════════════════════════════════════════════════════════

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();
    tcp4_pending.update(&id, &sk);
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct sock **skpp = tcp4_pending.lookup(&id);
    if (!skpp) return 0;
    struct sock *sk = *skpp;
    tcp4_pending.delete(&id);

    int ret = PT_REGS_RC(ctx);
    if (ret != 0 && ret != -115) return 0;

    struct event_t ev = {};
    ev.evt_type  = EVT_FLOW;
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = id >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.af        = AF_INET;
    ev.proto     = IPPROTO_TCP;
    ev.direction = DIR_OUTBOUND;

    u32 saddr = 0, daddr = 0; u16 sport = 0, dport = 0;
    bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    ev.saddr4 = saddr; ev.daddr4 = daddr;
    ev.sport  = sport; ev.dport  = ntohs(dport);

    { u64 sk64 = (u64)(unsigned long)sk; u8 one = 1;
      tracked_socks.update(&sk64, &one);
      struct byte_count_t zbc = {}; sock_bytes.update(&sk64, &zbc); }

    ev.sock_ptr = (u64)(unsigned long)sk;
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}


// ════════════════════════════════════════════════════════════════════════════
//  OUTBOUND TCP IPv6
// ════════════════════════════════════════════════════════════════════════════

int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();
    tcp6_pending.update(&id, &sk);
    return 0;
}

int kretprobe__tcp_v6_connect(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct sock **skpp = tcp6_pending.lookup(&id);
    if (!skpp) return 0;
    struct sock *sk = *skpp;
    tcp6_pending.delete(&id);

    int ret = PT_REGS_RC(ctx);
    if (ret != 0 && ret != -115) return 0;

    struct event_t ev = {};
    ev.evt_type  = EVT_FLOW;
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = id >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.af        = AF_INET6;
    ev.proto     = IPPROTO_TCP;
    ev.direction = DIR_OUTBOUND;

    u16 sport = 0, dport = 0;
    bpf_probe_read(&ev.saddr6, sizeof(ev.saddr6),
                   &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    bpf_probe_read(&ev.daddr6, sizeof(ev.daddr6),
                   &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    ev.sport = sport; ev.dport = ntohs(dport);

    { u64 sk64 = (u64)(unsigned long)sk; u8 one = 1;
      tracked_socks.update(&sk64, &one);
      struct byte_count_t zbc = {}; sock_bytes.update(&sk64, &zbc); }

    ev.sock_ptr = (u64)(unsigned long)sk;
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}


// ════════════════════════════════════════════════════════════════════════════
//  INBOUND TCP
// ════════════════════════════════════════════════════════════════════════════

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    struct event_t ev = {};
    ev.evt_type  = EVT_FLOW;
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.proto     = IPPROTO_TCP;
    ev.direction = DIR_INBOUND;

    u16 sport = 0, dport = 0;

    if (family == AF_INET) {
        ev.af = AF_INET;
        u32 saddr = 0, daddr = 0;
        bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        ev.saddr4 = saddr; ev.daddr4 = daddr;
        ev.sport  = ntohs(dport); ev.dport = sport;
    } else if (family == AF_INET6) {
        ev.af = AF_INET6;
        bpf_probe_read(&ev.saddr6, sizeof(ev.saddr6),
                       &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
        bpf_probe_read(&ev.daddr6, sizeof(ev.daddr6),
                       &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        ev.sport = ntohs(dport); ev.dport = sport;
    } else {
        return 0;
    }

    { u64 sk64 = (u64)(unsigned long)sk; u8 one = 1;
      tracked_socks.update(&sk64, &one);
      struct byte_count_t zbc = {}; sock_bytes.update(&sk64, &zbc); }

    ev.sock_ptr = (u64)(unsigned long)sk;
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}


// ════════════════════════════════════════════════════════════════════════════
//  UDP — flow open, byte counting, flow close
// ════════════════════════════════════════════════════════════════════════════

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t len) {
    u32 daddr = 0;
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    if ((daddr & 0xff) == 127) return 0;

    u64 sk64 = (u64)(unsigned long)sk;

    // Already tracked — just accumulate TX bytes and return
    if (tracked_socks.lookup(&sk64)) {
        struct byte_count_t *bc = sock_bytes.lookup(&sk64);
        if (bc) __sync_fetch_and_add(&bc->tx_bytes, len);
        return 0;
    }

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    struct event_t ev = {};
    ev.evt_type  = EVT_FLOW;
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.proto     = IPPROTO_UDP;
    ev.direction = DIR_OUTBOUND;

    u16 sport = 0, dport = 0;

    if (family == AF_INET) {
        ev.af = AF_INET;
        u32 saddr = 0;
        bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        ev.saddr4 = saddr; ev.daddr4 = daddr;
        ev.sport  = sport; ev.dport  = ntohs(dport);
    } else if (family == AF_INET6) {
        ev.af = AF_INET6;
        bpf_probe_read(&ev.saddr6, sizeof(ev.saddr6),
                       &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        bpf_probe_read(&ev.daddr6, sizeof(ev.daddr6),
                       &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
        bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        ev.sport = sport; ev.dport = ntohs(dport);
    } else {
        return 0;
    }

    // Register and seed TX bytes with this first send
    u8 one = 1;
    tracked_socks.update(&sk64, &one);
    struct byte_count_t zbc = { .tx_bytes = len, .rx_bytes = 0 };
    sock_bytes.update(&sk64, &zbc);

    ev.sock_ptr = sk64;
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    u64 sk64 = (u64)(unsigned long)sk;
    if (!tracked_socks.lookup(&sk64)) return 0;
    u64 id = bpf_get_current_pid_tgid();
    udp_recv_pending.update(&id, &sk64);
    return 0;
}

int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    u64 id = bpf_get_current_pid_tgid();
    u64 *sk64p = udp_recv_pending.lookup(&id);
    if (!sk64p) return 0;
    struct byte_count_t *bc = sock_bytes.lookup(sk64p);
    if (bc) __sync_fetch_and_add(&bc->rx_bytes, (u64)ret);
    udp_recv_pending.delete(&id);
    return 0;
}

int kprobe__udp_destroy_sock(struct pt_regs *ctx, struct sock *sk) {
    u64 sk64 = (u64)(unsigned long)sk;
    if (!tracked_socks.lookup(&sk64)) goto cleanup;

    {
        struct byte_count_t *bc = sock_bytes.lookup(&sk64);
        struct event_t ev = {};
        ev.evt_type = EVT_CLOSE;
        ev.ts_ns    = bpf_ktime_get_ns();
        ev.pid      = bpf_get_current_pid_tgid() >> 32;
        ev.uid      = bpf_get_current_uid_gid() & 0xffffffff;
        ev.proto    = IPPROTO_UDP;

        u16 family = 0;
        bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
        ev.af = family;

        if (family == AF_INET) {
            bpf_probe_read(&ev.saddr4, sizeof(ev.saddr4), &sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read(&ev.daddr4, sizeof(ev.daddr4), &sk->__sk_common.skc_daddr);
        } else if (family == AF_INET6) {
            bpf_probe_read(&ev.saddr6, sizeof(ev.saddr6),
                           &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
            bpf_probe_read(&ev.daddr6, sizeof(ev.daddr6),
                           &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
        } else { goto cleanup; }

        u16 sport = 0, dport = 0;
        bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        ev.sport = sport; ev.dport = ntohs(dport);

        if (bc) { ev.tx_bytes = bc->tx_bytes; ev.rx_bytes = bc->rx_bytes; }
        events.perf_submit(ctx, &ev, sizeof(ev));
    }

cleanup:
    tracked_socks.delete(&sk64);
    sock_bytes.delete(&sk64);
    return 0;
}


// ════════════════════════════════════════════════════════════════════════════
//  BYTE COUNTING — tcp_sendmsg / tcp_cleanup_rbuf / tcp_close
//  Only sockets in tracked_socks are instrumented; all others early-exit.
// ════════════════════════════════════════════════════════════════════════════

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t size) {
    u64 sk64 = (u64)(unsigned long)sk;
    if (!tracked_socks.lookup(&sk64)) return 0;
    struct byte_count_t *bc = sock_bytes.lookup(&sk64);
    if (bc) __sync_fetch_and_add(&bc->tx_bytes, size);
    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    if (copied <= 0) return 0;
    u64 sk64 = (u64)(unsigned long)sk;
    if (!tracked_socks.lookup(&sk64)) return 0;
    struct byte_count_t *bc = sock_bytes.lookup(&sk64);
    if (bc) __sync_fetch_and_add(&bc->rx_bytes, (u64)copied);
    return 0;
}

int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk, long timeout) {
    u64 sk64 = (u64)(unsigned long)sk;
    if (!tracked_socks.lookup(&sk64)) goto cleanup;

    {
        struct byte_count_t *bc = sock_bytes.lookup(&sk64);
        struct event_t ev = {};
        ev.evt_type = EVT_CLOSE;
        ev.ts_ns    = bpf_ktime_get_ns();
        ev.pid      = bpf_get_current_pid_tgid() >> 32;
        ev.uid      = bpf_get_current_uid_gid() & 0xffffffff;
        ev.proto    = IPPROTO_TCP;

        u16 family = 0;
        bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
        ev.af = family;

        if (family == AF_INET) {
            bpf_probe_read(&ev.saddr4, sizeof(ev.saddr4), &sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read(&ev.daddr4, sizeof(ev.daddr4), &sk->__sk_common.skc_daddr);
        } else if (family == AF_INET6) {
            bpf_probe_read(&ev.saddr6, sizeof(ev.saddr6),
                           &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
            bpf_probe_read(&ev.daddr6, sizeof(ev.daddr6),
                           &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
        } else { goto cleanup; }

        u16 sport = 0, dport = 0;
        bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        ev.sport = sport; ev.dport = ntohs(dport);

        if (bc) { ev.tx_bytes = bc->tx_bytes; ev.rx_bytes = bc->rx_bytes; }
        events.perf_submit(ctx, &ev, sizeof(ev));
    }

cleanup:
    tracked_socks.delete(&sk64);
    sock_bytes.delete(&sk64);
    return 0;
}
"""


# ── Python-side struct ────────────────────────────────────────────────────────
class Event(ctypes.Structure):
    _fields_ = [
        ("evt_type",     ctypes.c_uint8),
        ("ts_ns",        ctypes.c_uint64),
        ("pid",          ctypes.c_uint32),
        ("ppid",         ctypes.c_uint32),
        ("uid",          ctypes.c_uint32),
        ("comm",         ctypes.c_char * 16),
        ("af",           ctypes.c_uint32),
        ("saddr4",       ctypes.c_uint32),
        ("daddr4",       ctypes.c_uint32),
        ("saddr6",       ctypes.c_uint8 * 16),
        ("daddr6",       ctypes.c_uint8 * 16),
        ("sport",        ctypes.c_uint16),
        ("dport",        ctypes.c_uint16),
        ("proto",        ctypes.c_uint8),
        ("direction",    ctypes.c_uint8),
        ("pam_username", ctypes.c_char * 64),
        ("pam_service",  ctypes.c_char * 32),
        ("tx_bytes",     ctypes.c_uint64),
        ("rx_bytes",     ctypes.c_uint64),
        ("sock_ptr",     ctypes.c_uint64),
    ]

EVT_FLOW  = 0
EVT_PAM   = 1
EVT_CLOSE = 2


# ── UID → username cache ──────────────────────────────────────────────────────
@lru_cache(maxsize=512)
def uid_to_username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, PermissionError):
        return str(uid)


def proc_name(tgid: int, comm_fallback: bytes) -> str:
    """Return the process name for the given TGID.

    bpf_get_current_comm() reads the *thread* comm, which for multi-threaded
    apps (Firefox, browsers, JVMs) is the worker thread name ("Socket Thread",
    "DNS Resolver #63") rather than the executable name ("firefox-esr").
    Reading /proc/{tgid}/comm always returns the main thread (group leader)
    comm, which is the process name visible in `ps`.

    Falls back to the BPF-captured comm if /proc is unavailable (e.g. the
    process has already exited).
    """
    try:
        with open(f"/proc/{tgid}/comm") as f:
            return f.read().strip()
    except OSError:
        return comm_fallback.decode("utf-8", errors="replace").strip("\x00")


# ── /proc ancestry walker ─────────────────────────────────────────────────────
def get_ppid_from_proc(pid: int):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except (FileNotFoundError, PermissionError, ValueError):
        return None

def get_ancestors(pid: int, max_depth: int = 6) -> list:
    ancestors = []
    current = pid
    for _ in range(max_depth):
        parent = get_ppid_from_proc(current)
        if parent is None or parent <= 1:
            break
        ancestors.append(parent)
        current = parent
    return ancestors


# PAM_COLLECT_SECS: after the first PAM match on an inbound flow, hold the flow
# in pending for this long to accumulate additional PAM data (e.g. the PAM_SERVICE
# call that arrives a few ms after PAM_USER on some sshd configurations).
PAM_COLLECT_SECS = 1.0


# ── PAM correlation / pending inbound table ───────────────────────────────────
# flow_pid → {
#   "record":         dict,       # the flow JSON record (mutable)
#   "queued_at":      float,      # monotonic time queued
#   "child_procs":    list[dict], # PAM sessions matched as children
#   "pam_first_seen": float|None, # monotonic time of first PAM match
# }

PAM_WINDOW_SECS = 15.0
pending_inbound: dict = {}

_bpf = None          # set in main() after BPF() construction
FLOW_SHORT_SECS  = 30.0
FLOW_TRACK_SECS  = 3600.0

# Tracks open TCP flows.
# Key: (local_ip, local_port, remote_ip, remote_port, proto_str) — socket-native order
# Value: {
#   "session_id":   str,    # UUID4
#   "record":       dict,   # base flow fields (PAM-enrichable, no event_type yet)
#   "flow_start":   float,  # monotonic time of connection open
#   "sock_ptr":     int,    # sock* as int, for _bpf["sock_bytes"] mid-session reads
#   "long_emitted": bool,   # True once flow_long_open has been emitted
# }
open_flows: dict = {}


# ── Config file ───────────────────────────────────────────────────────────────
_DEFAULT_CONFIG   = '/etc/procflow/procflow.conf'
_DEFAULT_LOG_FILE = '/var/log/procflow/enriched_flow.log'
_DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MB
_DEFAULT_BACKUPS   = 5

def load_config(path):
    """Read INI config; missing file silently uses all defaults."""
    cfg = configparser.ConfigParser()
    cfg.read(path)
    log_file  = cfg.get('logging', 'log_file',      fallback=_DEFAULT_LOG_FILE)
    max_bytes = cfg.getint('logging', 'max_bytes',   fallback=_DEFAULT_MAX_BYTES)
    backups   = cfg.getint('logging', 'backup_count', fallback=_DEFAULT_BACKUPS)

    global PAM_COLLECT_SECS, PAM_WINDOW_SECS, FLOW_SHORT_SECS, FLOW_TRACK_SECS
    PAM_COLLECT_SECS = cfg.getfloat('tuning', 'pam_collect_secs', fallback=PAM_COLLECT_SECS)
    PAM_WINDOW_SECS  = cfg.getfloat('tuning', 'pam_window_secs',  fallback=PAM_WINDOW_SECS)
    FLOW_SHORT_SECS  = cfg.getfloat('tuning', 'flow_short_secs',  fallback=FLOW_SHORT_SECS)
    FLOW_TRACK_SECS  = cfg.getfloat('tuning', 'flow_track_secs',  fallback=FLOW_TRACK_SECS)

    return log_file, max_bytes, backups


def find_pending_flow_for_pam(pam_pid: int, pam_ppid: int):
    """Return the flow_pid key whose process tree contains pam_pid, or None."""
    if pam_pid in pending_inbound:
        return pam_pid
    if pam_ppid in pending_inbound:
        return pam_ppid
    for ancestor in get_ancestors(pam_pid):
        if ancestor in pending_inbound:
            return ancestor
    return None


def flush_expired_pending():
    now = time.monotonic()
    ready = []
    for pid, v in pending_inbound.items():
        pam_seen = v["pam_first_seen"]
        if pam_seen is not None and now - pam_seen >= PAM_COLLECT_SECS:
            ready.append(pid)
        elif now - v["queued_at"] > PAM_WINDOW_SECS:
            ready.append(pid)

    for pid in ready:
        entry = pending_inbound.pop(pid)
        rec = entry["record"]
        rec["child_processes"] = entry["child_procs"]
        if not rec["child_processes"]:
            rec["auth_note"] = "no_pam_event_within_window"
        fk = make_flow_key_from_record(rec)
        open_flows[fk] = {
            "session_id":   str(uuid.uuid4()),
            "record":       rec,
            "flow_start":   entry["queued_at"],
            "sock_ptr":     entry["sock_ptr"],
            "long_emitted": False,
        }

    flush_open_flows()


def flush_open_flows():
    """Emit flow_long_open for TCP connections that have been open >= FLOW_SHORT_SECS."""
    now = time.monotonic()
    for entry in open_flows.values():
        if not entry["long_emitted"] and now - entry["flow_start"] >= FLOW_SHORT_SECS:
            try:
                bc = _bpf["sock_bytes"][ctypes.c_uint64(entry["sock_ptr"])]
                tx, rx = bc.tx_bytes, bc.rx_bytes
            except Exception:
                tx, rx = 0, 0
            rec = {**entry["record"],
                   "event_type": "flow_long_open",
                   "session_id": entry["session_id"],
                   "tx_bytes":   tx,
                   "rx_bytes":   rx}
            emit(rec)
            entry["long_emitted"] = True

    # Expire entries whose connections were never closed within the tracking window
    stale = [k for k, v in open_flows.items()
             if now - v["flow_start"] > FLOW_TRACK_SECS]
    for k in stale:
        del open_flows[k]


# ── Helpers ───────────────────────────────────────────────────────────────────
def int_to_ipv4(n: int) -> str:
    return socket.inet_ntoa(struct.pack("I", n))

def bytes_to_ipv6(raw) -> str:
    return socket.inet_ntop(socket.AF_INET6, bytes(raw))

def proto_name(p: int) -> str:
    return {6: "TCP", 17: "UDP"}.get(p, str(p))

_json_logger = logging.getLogger('procflow.output')
_json_logger.setLevel(logging.INFO)
_json_logger.propagate = False

def setup_logging(log_file, max_bytes, backup_count, stdout_only=False):
    if stdout_only:
        return
    import os
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    # Force 640 (rw-r-----) on the log file regardless of process umask.
    # The log contains authenticated usernames and connection metadata and
    # must not be world-readable.
    old_umask = os.umask(0o027)
    try:
        handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8')
    finally:
        os.umask(old_umask)
    handler.setFormatter(logging.Formatter('%(message)s'))
    _json_logger.addHandler(handler)

def emit(record: dict):
    line = json.dumps(record)
    print(line, flush=True)
    _json_logger.info(line)


def make_flow_key(ev) -> tuple:
    if ev.af == socket.AF_INET:
        sip, dip = int_to_ipv4(ev.saddr4), int_to_ipv4(ev.daddr4)
    else:
        sip, dip = bytes_to_ipv6(ev.saddr6), bytes_to_ipv6(ev.daddr6)
    return (sip, ev.sport, dip, ev.dport, proto_name(ev.proto))

def make_flow_key_from_record(rec: dict) -> tuple:
    # Always return key in socket-native (local→remote) order to match tcp_close.
    # Inbound flow records have src=remote, dst=local, so swap them.
    if rec["direction"] == "inbound":
        return (rec["dst_ip"], rec["dst_port"],
                rec["src_ip"], rec["src_port"], rec["protocol"])
    return (rec["src_ip"], rec["src_port"],
            rec["dst_ip"], rec["dst_port"], rec["protocol"])


# ── Perf event callback ───────────────────────────────────────────────────────
def handle_event(cpu, data, size):
    ev = ctypes.cast(data, ctypes.POINTER(Event)).contents

    flush_expired_pending()

    # ── Connection closed ─────────────────────────────────────────────────
    if ev.evt_type == EVT_CLOSE:
        fk = make_flow_key(ev)
        entry = open_flows.pop(fk, None)
        if entry is None:
            return  # connection predates monitor or already expired
        rec = {**entry["record"],
               "session_id": entry["session_id"],
               "tx_bytes":   ev.tx_bytes,
               "rx_bytes":   ev.rx_bytes}
        rec["event_type"] = "flow_long_closed" if entry["long_emitted"] else "flow_short"
        emit(rec)
        return

    # ── PAM event ─────────────────────────────────────────────────────────
    if ev.evt_type == EVT_PAM:
        username = ev.pam_username.decode("utf-8", errors="replace").strip("\x00")
        service  = ev.pam_service.decode("utf-8", errors="replace").strip("\x00")

        child_entry = {
            "pid":                ev.pid,
            "ppid":               ev.ppid,
            "process":            proc_name(ev.pid, ev.comm),
            "authenticated_user": username or None,
            "pam_service":        service  or None,
            "timestamp":          datetime.now(timezone.utc).isoformat(),
        }

        flow_pid = find_pending_flow_for_pam(ev.pid, ev.ppid)

        if flow_pid is not None:
            entry = pending_inbound[flow_pid]
            # Deduplicate by pid — one entry per child process.
            # If the pid is already recorded, only update pam_service if we now have it.
            existing = next((c for c in entry["child_procs"]
                             if c["pid"] == child_entry["pid"]), None)
            if existing is None:
                entry["child_procs"].append(child_entry)
            elif existing["pam_service"] is None and child_entry["pam_service"]:
                existing["pam_service"] = child_entry["pam_service"]
            else:
                # Pure duplicate — discard
                pass

            # On first PAM match: enrich top-level fields, start collect window
            if entry["pam_first_seen"] is None:
                rec = entry["record"]
                rec["authenticated_user"] = username or None
                rec["pam_service"]        = service  or None
                entry["pam_first_seen"]   = time.monotonic()
            else:
                # Fold in service name if it arrives after PAM_USER
                rec = entry["record"]
                if rec["pam_service"] is None and service:
                    rec["pam_service"] = service
            # Don't emit yet — flush_expired_pending emits after PAM_COLLECT_SECS
        else:
            # PAM event with no correlated network flow — discard.
            # This monitor only enriches network events.
            return
        return

    # ── Flow event ────────────────────────────────────────────────────────
    if ev.af == socket.AF_INET:
        src_ip = int_to_ipv4(ev.saddr4)
        dst_ip = int_to_ipv4(ev.daddr4)
        af_str = "IPv4"
    else:
        src_ip = bytes_to_ipv6(ev.saddr6)
        dst_ip = bytes_to_ipv6(ev.daddr6)
        af_str = "IPv6"

    record = {
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "direction":          "inbound" if ev.direction == 1 else "outbound",
        "pid":                ev.pid,
        "ppid":               ev.ppid,
        "uid":                ev.uid,
        "username":           uid_to_username(ev.uid),
        "process":            proc_name(ev.pid, ev.comm),
        "protocol":           proto_name(ev.proto),
        "address_family":     af_str,
        "src_ip":             src_ip,
        "src_port":           ev.sport,
        "dst_ip":             dst_ip,
        "dst_port":           ev.dport,
        "authenticated_user": None,
        "pam_service":        None,
        "child_processes":    [],
    }

    if ev.direction == 1 and ev.proto == 6:   # inbound TCP → hold for PAM enrichment
        pending_inbound[ev.pid] = {
            "record":         record,
            "queued_at":      time.monotonic(),
            "child_procs":    [],
            "pam_first_seen": None,
            "sock_ptr":       ev.sock_ptr,
        }
    elif ev.proto == 6:                        # outbound TCP → open_flows
        open_flows[make_flow_key(ev)] = {
            "session_id":   str(uuid.uuid4()),
            "record":       record,
            "flow_start":   time.monotonic(),
            "sock_ptr":     ev.sock_ptr,
            "long_emitted": False,
        }
    else:                                      # UDP → open_flows (byte-counted at close)
        open_flows[make_flow_key(ev)] = {
            "session_id":   str(uuid.uuid4()),
            "record":       record,
            "flow_start":   time.monotonic(),
            "sock_ptr":     ev.sock_ptr,
            "long_emitted": False,
        }


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    import sys, os

    parser = argparse.ArgumentParser(
        prog='procflow',
        description=(
            'eBPF-based host network flow monitor with PAM enrichment.\n\n'
            'Captures TCP and UDP flows and emits newline-delimited JSON records\n'
            'enriched with process, user, and (for inbound SSH) authenticated\n'
            'username. Requires root. BPF program is compiled at startup.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'event types:\n'
            '  flow_short       connection closed before --flow-short-secs (default 30s),\n'
            '                   or any UDP flow; includes final TX/RX byte counts\n'
            '  flow_long_open   emitted at flow_short_secs for still-open TCP connections;\n'
            '                   byte counts are a snapshot, not final\n'
            '  flow_long_closed emitted when a long-lived TCP session closes;\n'
            '                   paired with flow_long_open via session_id\n\n'
            'examples:\n'
            '  sudo procflow\n'
            '  sudo procflow --config /etc/procflow/procflow.conf\n'
            '  sudo procflow --log-file /tmp/flows.log\n'
            '  sudo procflow --stdout-only | jq \'select(.event_type == "flow_short")\'\n'
            '  sudo procflow --no-pam --stdout-only\n'
        ),
    )
    parser.add_argument(
        '--version', action='version',
        version=f'%(prog)s {VERSION}')
    parser.add_argument(
        '--config', default=_DEFAULT_CONFIG, metavar='PATH',
        help=f'INI config file (default: /etc/procflow/procflow.conf)')
    parser.add_argument(
        '--log-file', metavar='PATH',
        help='Log file path; overrides the config file setting')
    parser.add_argument(
        '--stdout-only', action='store_true',
        help='Write JSON only to stdout; do not open or rotate a log file')
    parser.add_argument(
        '--no-pam', action='store_true',
        help='Skip PAM uprobe attachment; flows are captured without '
             'authenticated_user enrichment')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(json.dumps({"error": "Must be run as root (sudo)"}))
        sys.exit(1)

    log_file, max_bytes, backups = load_config(args.config)
    if args.log_file:
        log_file = args.log_file
    setup_logging(log_file, max_bytes, backups, stdout_only=args.stdout_only)

    try:
        libpam_path = find_libpam()
    except FileNotFoundError as e:
        emit({"error": str(e)})
        sys.exit(1)

    emit({"status": "compiling eBPF program..."})

    try:
        b = BPF(text=BPF_PROGRAM)
    except Exception as e:
        emit({"error": "BPF compile failed", "detail": str(e)})
        sys.exit(1)

    global _bpf
    _bpf = b

    expected_event_size = 216
    actual = ctypes.sizeof(Event)
    if actual != expected_event_size:
        emit({"error": f"Event struct size mismatch: Python={actual}, expected={expected_event_size}. "
                       "The C and Python struct layouts are out of sync."})
        sys.exit(1)

    if args.no_pam:
        emit({"status": "PAM enrichment disabled via --no-pam"})
    else:
        try:
            b.attach_uprobe(
                name=libpam_path, sym="pam_get_item",
                fn_name="uprobe__pam_get_item")
            b.attach_uretprobe(
                name=libpam_path, sym="pam_get_item",
                fn_name="uretprobe__pam_get_item")
            emit({"status": "PAM uprobe attached", "libpam": libpam_path, "symbol": "pam_get_item"})
        except Exception as e:
            emit({"warning": f"Could not attach PAM uprobe: {e}. "
                             "Flow events will still be captured without PAM enrichment."})

    emit({"status": "listening for connections — Ctrl+C to stop"})

    b["events"].open_perf_buffer(handle_event, page_cnt=256)

    try:
        while True:
            b.perf_buffer_poll(timeout=100)
            flush_expired_pending()
            flush_open_flows()
    except KeyboardInterrupt:
        # Flush pending inbound flows as flow_short (no byte counts available)
        for entry in pending_inbound.values():
            rec = {**entry["record"],
                   "event_type":      "flow_short",
                   "session_id":      str(uuid.uuid4()),
                   "child_processes": entry["child_procs"],
                   "tx_bytes":        None,
                   "rx_bytes":        None}
            if not entry["child_procs"]:
                rec["auth_note"] = "shutdown_before_pam_event"
            emit(rec)
        # Flush open TCP flows with final byte counts
        for entry in open_flows.values():
            try:
                bc = _bpf["sock_bytes"][ctypes.c_uint64(entry["sock_ptr"])]
                tx, rx = bc.tx_bytes, bc.rx_bytes
            except Exception:
                tx, rx = None, None
            event_type = "flow_long_closed" if entry["long_emitted"] else "flow_short"
            rec = {**entry["record"],
                   "event_type": event_type,
                   "session_id": entry["session_id"],
                   "tx_bytes":   tx,
                   "rx_bytes":   rx}
            emit(rec)
        emit({"status": "shutting down"})
        logging.shutdown()


if __name__ == "__main__":
    main()
