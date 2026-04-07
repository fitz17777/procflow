#!/usr/bin/env python3
"""
procflow - eBPF-based host network flow monitor with PAM enrichment.

Captures TCP (inbound + outbound), UDP, and ICMP flows using eBPF kprobes,
enriched with host OS context: process name, exe path, command line, PID,
UID/username, socket inode (for Wireshark/ss correlation), network namespace
(container detection), and — for inbound TCP sessions — the authenticated PAM
username. sshd privsep forks are handled correctly via /proc ancestry walking.

Event types emitted as newline-delimited JSON:
  flow_short       — connection closed before flow_short_secs (default 30s), or
                     any UDP/ICMP flow. Single record with full context + byte counts.
  flow_long_open   — emitted at the flow_short_secs mark for still-open TCP.
                     Snapshot of context and bytes transferred so far.
  flow_long_closed — emitted when a long-lived TCP session finally closes.
                     Includes total byte counts. Correlates to flow_long_open
                     via matching session_id (UUID4).
  connect_failed   — outbound TCP connection attempt that failed (ECONNREFUSED,
                     ETIMEDOUT, ENETUNREACH, EHOSTUNREACH).
  listen_start     — TCP socket entered LISTEN state (bind + listen syscall).

PAM events with no correlated network flow are silently discarded — this tool
only enriches network events, it does not log standalone authentication activity.

Byte counting:
  TX/RX bytes are accumulated per-socket in kernel space via tcp_sendmsg,
  tcp_cleanup_rbuf, udp_sendmsg, and udp_recvmsg kprobes. Final counts are
  delivered at close time via tcp_close / udp_destroy_sock kprobes.

Wireshark/IDS correlation:
  sock_ino  — socket inode number. Match against `ss -tnp` or `ss -unp` output
              to instantly identify the process behind any Wireshark capture.
  netns_ino — network namespace inode. Differs from /proc/1/ns/net inode for
              container traffic; container_traffic field is set to true.

Requirements:
    sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
"""

VERSION = "1.1.0"

import argparse
import configparser
import json
import ctypes
import errno as errno_mod
import logging
import os
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
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>

#define DIR_OUTBOUND 0
#define DIR_INBOUND  1
#define EVT_FLOW            0
#define EVT_PAM             1
#define EVT_CLOSE           2
#define EVT_CONNECT_FAILED  3
#define EVT_LISTEN          4

#define PAM_SERVICE  1
#define PAM_USER     2

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

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

    // Extended metadata (P1-C sock_ino, P1-D netns_ino, P2-B connect_error, P2-D dns_payload)
    u64  sock_ino;        // socket inode — matches `ss` / /proc/net/* inode column
    u32  netns_ino;       // network namespace inode — differs from host for containers
    s32  connect_error;   // negative errno for EVT_CONNECT_FAILED (e.g. -111 = ECONNREFUSED)
    u8   dns_payload[40]; // first 40 bytes of UDP payload when dport==53 (for QNAME decode)
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


// ── Helper: read socket inode and network namespace inode ────────────────────
static inline void read_sock_meta(struct sock *sk, u64 *sock_ino_out, u32 *netns_ino_out) {
    *sock_ino_out  = 0;
    *netns_ino_out = 0;

    // Socket inode: sk->sk_socket->file->f_inode->i_ino
    struct socket *sock_obj = NULL;
    bpf_probe_read(&sock_obj, sizeof(sock_obj), &sk->sk_socket);
    if (sock_obj) {
        struct file *sock_file = NULL;
        bpf_probe_read(&sock_file, sizeof(sock_file), &sock_obj->file);
        if (sock_file) {
            struct inode *sock_inode = NULL;
            bpf_probe_read(&sock_inode, sizeof(sock_inode), &sock_file->f_inode);
            if (sock_inode) {
                unsigned long ino = 0;
                bpf_probe_read(&ino, sizeof(ino), &sock_inode->i_ino);
                *sock_ino_out = (u64)ino;
            }
        }
    }

    // Network namespace: sk->__sk_common.skc_net.net->ns.inum
    struct net *net = NULL;
    bpf_probe_read(&net, sizeof(net), &sk->__sk_common.skc_net.net);
    if (net) {
        unsigned int inum = 0;
        bpf_probe_read(&inum, sizeof(inum), &net->ns.inum);
        *netns_ino_out = (u32)inum;
    }
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
    // 0 = sync success, -115/EINPROGRESS = async (non-blocking)
    // -111/ECONNREFUSED, -110/ETIMEDOUT, -101/ENETUNREACH, -113/EHOSTUNREACH = failures
    int is_failed = (ret == -111 || ret == -110 || ret == -101 || ret == -113);
    if (ret != 0 && ret != -115 && !is_failed) return 0;

    struct event_t ev = {};
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = id >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.af        = AF_INET;
    ev.proto     = IPPROTO_TCP;
    ev.direction = DIR_OUTBOUND;

    if (is_failed) {
        ev.evt_type      = EVT_CONNECT_FAILED;
        ev.connect_error = ret;
    } else {
        ev.evt_type = EVT_FLOW;
    }

    u32 saddr = 0, daddr = 0; u16 sport = 0, dport = 0;
    bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    ev.saddr4 = saddr; ev.daddr4 = daddr;
    ev.sport  = sport; ev.dport  = ntohs(dport);

    read_sock_meta(sk, &ev.sock_ino, &ev.netns_ino);

    if (!is_failed) {
        u64 sk64 = (u64)(unsigned long)sk; u8 one = 1;
        tracked_socks.update(&sk64, &one);
        struct byte_count_t zbc = {}; sock_bytes.update(&sk64, &zbc);
    }

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
    int is_failed = (ret == -111 || ret == -110 || ret == -101 || ret == -113);
    if (ret != 0 && ret != -115 && !is_failed) return 0;

    struct event_t ev = {};
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = id >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.af        = AF_INET6;
    ev.proto     = IPPROTO_TCP;
    ev.direction = DIR_OUTBOUND;

    if (is_failed) {
        ev.evt_type      = EVT_CONNECT_FAILED;
        ev.connect_error = ret;
    } else {
        ev.evt_type = EVT_FLOW;
    }

    u16 sport = 0, dport = 0;
    bpf_probe_read(&ev.saddr6, sizeof(ev.saddr6),
                   &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    bpf_probe_read(&ev.daddr6, sizeof(ev.daddr6),
                   &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    ev.sport = sport; ev.dport = ntohs(dport);

    read_sock_meta(sk, &ev.sock_ino, &ev.netns_ino);

    if (!is_failed) {
        u64 sk64 = (u64)(unsigned long)sk; u8 one = 1;
        tracked_socks.update(&sk64, &one);
        struct byte_count_t zbc = {}; sock_bytes.update(&sk64, &zbc);
    }

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

    read_sock_meta(sk, &ev.sock_ino, &ev.netns_ino);

    { u64 sk64 = (u64)(unsigned long)sk; u8 one = 1;
      tracked_socks.update(&sk64, &one);
      struct byte_count_t zbc = {}; sock_bytes.update(&sk64, &zbc); }

    ev.sock_ptr = (u64)(unsigned long)sk;
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}


// ════════════════════════════════════════════════════════════════════════════
//  TCP LISTEN — fires when a socket enters LISTEN state (bind + listen)
// ════════════════════════════════════════════════════════════════════════════

int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog) {
    struct sock *sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), &sock->sk);
    if (!sk) return 0;

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) return 0;

    struct event_t ev = {};
    ev.evt_type  = EVT_LISTEN;
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.proto     = IPPROTO_TCP;
    ev.af        = family;
    ev.direction = DIR_INBOUND;

    // dport = local listening port; daddr = local bind address (0.0.0.0 = all)
    u16 lport = 0;
    bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    ev.dport = lport;

    if (family == AF_INET) {
        bpf_probe_read(&ev.daddr4, sizeof(ev.daddr4), &sk->__sk_common.skc_rcv_saddr);
    } else {
        bpf_probe_read(&ev.daddr6, sizeof(ev.daddr6),
                       &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    }

    read_sock_meta(sk, &ev.sock_ino, &ev.netns_ino);
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

    // DNS payload extraction: capture first 40 bytes of DNS query when dport==53
    if (ev.dport == 53) {
        const struct iovec *iov = NULL;
        bpf_probe_read(&iov, sizeof(iov), &msg->msg_iter.__iov);
        if (iov) {
            void *iov_base = NULL;
            bpf_probe_read(&iov_base, sizeof(iov_base), &iov->iov_base);
            if (iov_base)
                bpf_probe_read_user(ev.dns_payload, sizeof(ev.dns_payload), iov_base);
        }
    }

    read_sock_meta(sk, &ev.sock_ino, &ev.netns_ino);

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
//  ICMP — raw socket send path (IPv4 and IPv6)
//  Reuses EVT_FLOW; Python identifies ICMP by proto field (1 or 58).
//  sport/dport are 0 (ICMP has no ports).
// ════════════════════════════════════════════════════════════════════════════

int kprobe__raw_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t len) {
    u8 proto = 0;
    bpf_probe_read(&proto, sizeof(proto), &sk->sk_protocol);
    if (proto != IPPROTO_ICMP) return 0;

    struct event_t ev = {};
    ev.evt_type  = EVT_FLOW;
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.af        = AF_INET;
    ev.proto     = IPPROTO_ICMP;
    ev.direction = DIR_OUTBOUND;

    // Source: bound local address (0.0.0.0 if unbound — routing selects it later)
    bpf_probe_read(&ev.saddr4, sizeof(ev.saddr4), &sk->__sk_common.skc_rcv_saddr);

    // Destination: raw sockets use sendto() without connect(), so skc_daddr is 0.
    // The destination address is in msg->msg_name (moved to kernel space by the syscall).
    void *msg_name = NULL;
    bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
    if (msg_name) {
        struct sockaddr_in sa = {};
        bpf_probe_read_kernel(&sa, sizeof(sa), msg_name);
        if (sa.sin_family == AF_INET)
            ev.daddr4 = sa.sin_addr.s_addr;
    }
    if (!ev.daddr4)
        bpf_probe_read(&ev.daddr4, sizeof(ev.daddr4), &sk->__sk_common.skc_daddr);

    read_sock_meta(sk, &ev.sock_ino, &ev.netns_ino);
    ev.sock_ptr = (u64)(unsigned long)sk;
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

int kprobe__rawv6_sendmsg(struct pt_regs *ctx, struct sock *sk,
                          struct msghdr *msg, size_t len) {
    u8 proto = 0;
    bpf_probe_read(&proto, sizeof(proto), &sk->sk_protocol);
    if (proto != IPPROTO_ICMPV6) return 0;

    struct event_t ev = {};
    ev.evt_type  = EVT_FLOW;
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.af        = AF_INET6;
    ev.proto     = IPPROTO_ICMPV6;
    ev.direction = DIR_OUTBOUND;

    bpf_probe_read(&ev.saddr6, sizeof(ev.saddr6),
                   &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);

    // Destination from msg->msg_name for unconnected raw sockets
    void *msg_name6 = NULL;
    bpf_probe_read_kernel(&msg_name6, sizeof(msg_name6), &msg->msg_name);
    if (msg_name6) {
        struct sockaddr_in6 sa6 = {};
        bpf_probe_read_kernel(&sa6, sizeof(sa6), msg_name6);
        if (sa6.sin6_family == AF_INET6)
            bpf_probe_read_kernel(&ev.daddr6, sizeof(ev.daddr6),
                                  &sa6.sin6_addr.in6_u.u6_addr8);
    }
    if (!*(u64 *)ev.daddr6)
        bpf_probe_read(&ev.daddr6, sizeof(ev.daddr6),
                       &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);

    read_sock_meta(sk, &ev.sock_ino, &ev.netns_ino);
    ev.sock_ptr = (u64)(unsigned long)sk;
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}


// ════════════════════════════════════════════════════════════════════════════
//  INBOUND ICMP — kernel receives ICMP packets via icmp_rcv / icmpv6_rcv.
//  The process context here is kernel softirq, not a userspace process.
// ════════════════════════════════════════════════════════════════════════════

int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    unsigned char *head = NULL;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    u16 nh_off = 0;
    bpf_probe_read_kernel(&nh_off, sizeof(nh_off), &skb->network_header);

    struct iphdr iph = {};
    bpf_probe_read_kernel(&iph, sizeof(iph), head + nh_off);

    // Skip loopback
    if ((iph.saddr & 0xff) == 127 || (iph.daddr & 0xff) == 127) return 0;

    struct event_t ev = {};
    ev.evt_type  = EVT_FLOW;
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.af        = AF_INET;
    ev.proto     = IPPROTO_ICMP;
    ev.direction = DIR_INBOUND;
    ev.saddr4    = iph.saddr;   // remote sender
    ev.daddr4    = iph.daddr;   // local host

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

int kprobe__icmpv6_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    unsigned char *head = NULL;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    u16 nh_off = 0;
    bpf_probe_read_kernel(&nh_off, sizeof(nh_off), &skb->network_header);

    struct ipv6hdr iph6 = {};
    bpf_probe_read_kernel(&iph6, sizeof(iph6), head + nh_off);

    struct event_t ev = {};
    ev.evt_type  = EVT_FLOW;
    ev.ts_ns     = bpf_ktime_get_ns();
    ev.pid       = bpf_get_current_pid_tgid() >> 32;
    ev.ppid      = get_ppid();
    ev.uid       = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.af        = AF_INET6;
    ev.proto     = IPPROTO_ICMPV6;
    ev.direction = DIR_INBOUND;
    bpf_probe_read_kernel(&ev.saddr6, sizeof(ev.saddr6), &iph6.saddr.in6_u.u6_addr8);
    bpf_probe_read_kernel(&ev.daddr6, sizeof(ev.daddr6), &iph6.daddr.in6_u.u6_addr8);

    events.perf_submit(ctx, &ev, sizeof(ev));
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
        ("sock_ino",     ctypes.c_uint64),
        ("netns_ino",    ctypes.c_uint32),
        ("connect_error",ctypes.c_int32),
        ("dns_payload",  ctypes.c_uint8 * 40),
    ]

EVT_FLOW           = 0
EVT_PAM            = 1
EVT_CLOSE          = 2
EVT_CONNECT_FAILED = 3
EVT_LISTEN         = 4

# IPPROTO values for ICMP (stateless — emitted immediately, not tracked)
_ICMP_PROTOS = {1, 58}  # IPPROTO_ICMP, IPPROTO_ICMPV6


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


def proc_exe(tgid: int):
    """Return the full executable path for the given TGID, or None."""
    try:
        return os.readlink(f"/proc/{tgid}/exe")
    except OSError:
        return None


def proc_cmdline(tgid: int, maxlen: int = 256):
    """Return the command line for the given TGID (args joined by spaces), or None."""
    try:
        with open(f"/proc/{tgid}/cmdline", "rb") as f:
            raw = f.read(maxlen)
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except OSError:
        return None


# ── Protocol hint labels ──────────────────────────────────────────────────────
_PROTO_LABELS = {
    # (ip_proto, dport): label
    (17, 53):   "DNS",
    (17, 5353): "mDNS",
    (17, 123):  "NTP",
    (17, 443):  "QUIC",
    (6,  22):   "SSH",
    (6,  80):   "HTTP",
    (6,  443):  "HTTPS",
    (6,  25):   "SMTP",
    (6,  587):  "SMTP",
    (6,  465):  "SMTPS",
    (6,  993):  "IMAPS",
    (6,  143):  "IMAP",
    (6,  110):  "POP3",
    (6,  3389): "RDP",
    (6,  5900): "VNC",
    (6,  6443): "k8s-api",
}

def proto_label(ip_proto: int, dport: int, dst_ip=None):
    """Return a human-readable application protocol hint, or None."""
    if ip_proto == 17 and dport == 5353:
        return "mDNS"  # also check dst for 224.0.0.251 if needed
    return _PROTO_LABELS.get((ip_proto, dport))


# ── DNS QNAME decoder ─────────────────────────────────────────────────────────
def decode_dns_qname(payload: bytes):
    """Decode the QNAME from the first 40 bytes of a DNS UDP payload.

    DNS wire format: 12-byte header, then QNAME as length-prefixed labels
    terminated by a zero byte. Returns None if the payload is too short,
    malformed, or uses compression (which we can't resolve in 40 bytes).
    """
    if len(payload) < 13:
        return None
    try:
        pos = 12
        labels = []
        while pos < len(payload):
            length = payload[pos]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:   # compression pointer — can't resolve
                break
            pos += 1
            if pos + length > len(payload):
                break
            labels.append(payload[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels) if labels else None
    except Exception:
        return None


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

# Host network namespace inode — set in main() by reading /proc/1/ns/net.
# Any flow whose netns_ino differs from this value is container traffic.
HOST_NETNS_INO: int = 0

# Tracks open TCP/UDP flows.
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
    return {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(p, str(p))

_json_logger = logging.getLogger('procflow.output')
_json_logger.setLevel(logging.INFO)
_json_logger.propagate = False

def setup_logging(log_file, max_bytes, backup_count, stdout_only=False):
    if stdout_only:
        return
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


def _container_flag(netns_ino: int):
    """True if netns_ino is non-zero and differs from the host netns."""
    if not netns_ino:
        return None
    return netns_ino != HOST_NETNS_INO


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
            existing = next((c for c in entry["child_procs"]
                             if c["pid"] == child_entry["pid"]), None)
            if existing is None:
                entry["child_procs"].append(child_entry)
            elif existing["pam_service"] is None and child_entry["pam_service"]:
                existing["pam_service"] = child_entry["pam_service"]

            # On first PAM match: enrich top-level fields, start collect window
            if entry["pam_first_seen"] is None:
                rec = entry["record"]
                rec["authenticated_user"] = username or None
                rec["pam_service"]        = service  or None
                entry["pam_first_seen"]   = time.monotonic()
            else:
                rec = entry["record"]
                if rec["pam_service"] is None and service:
                    rec["pam_service"] = service
        else:
            # PAM event with no correlated network flow — discard.
            return
        return

    # ── Failed TCP connect ────────────────────────────────────────────────
    if ev.evt_type == EVT_CONNECT_FAILED:
        if ev.af == socket.AF_INET:
            src_ip = int_to_ipv4(ev.saddr4)
            dst_ip = int_to_ipv4(ev.daddr4)
            af_str = "IPv4"
        else:
            src_ip = bytes_to_ipv6(ev.saddr6)
            dst_ip = bytes_to_ipv6(ev.daddr6)
            af_str = "IPv6"
        err_code = -ev.connect_error  # connect_error is negative (e.g. -111)
        err_name = errno_mod.errorcode.get(err_code, str(err_code))
        tgid = ev.pid
        record = {
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "event_type":        "connect_failed",
            "connect_error":     err_name,
            "pid":               ev.pid,
            "ppid":              ev.ppid,
            "uid":               ev.uid,
            "username":          uid_to_username(ev.uid),
            "process":           proc_name(tgid, ev.comm),
            "exe":               proc_exe(tgid),
            "cmdline":           proc_cmdline(tgid),
            "protocol":          proto_name(ev.proto),
            "proto_hint":        proto_label(ev.proto, ev.dport),
            "address_family":    af_str,
            "src_ip":            src_ip,
            "src_port":          ev.sport,
            "dst_ip":            dst_ip,
            "dst_port":          ev.dport,
            "sock_ino":          ev.sock_ino or None,
            "netns_ino":         ev.netns_ino or None,
            "container_traffic": _container_flag(ev.netns_ino),
        }
        emit(record)
        return

    # ── TCP listen start ──────────────────────────────────────────────────
    if ev.evt_type == EVT_LISTEN:
        if ev.af == socket.AF_INET:
            local_ip = int_to_ipv4(ev.daddr4)
            af_str = "IPv4"
        else:
            local_ip = bytes_to_ipv6(ev.daddr6)
            af_str = "IPv6"
        tgid = ev.pid
        record = {
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "event_type":        "listen_start",
            "pid":               ev.pid,
            "ppid":              ev.ppid,
            "uid":               ev.uid,
            "username":          uid_to_username(ev.uid),
            "process":           proc_name(tgid, ev.comm),
            "exe":               proc_exe(tgid),
            "cmdline":           proc_cmdline(tgid),
            "protocol":          proto_name(ev.proto),
            "address_family":    af_str,
            "local_ip":          local_ip,
            "local_port":        ev.dport,
            "sock_ino":          ev.sock_ino or None,
            "netns_ino":         ev.netns_ino or None,
            "container_traffic": _container_flag(ev.netns_ino),
        }
        emit(record)
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

    tgid  = ev.pid
    hint  = proto_label(ev.proto, ev.dport, dst_ip)
    netns = ev.netns_ino or None

    record = {
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "direction":          "inbound" if ev.direction == 1 else "outbound",
        "pid":                ev.pid,
        "ppid":               ev.ppid,
        "uid":                ev.uid,
        "username":           uid_to_username(ev.uid),
        "process":            proc_name(tgid, ev.comm),
        "exe":                proc_exe(tgid),
        "cmdline":            proc_cmdline(tgid),
        "protocol":           proto_name(ev.proto),
        "proto_hint":         hint,
        "address_family":     af_str,
        "src_ip":             src_ip,
        "src_port":           ev.sport,
        "dst_ip":             dst_ip,
        "dst_port":           ev.dport,
        "sock_ino":           ev.sock_ino or None,
        "netns_ino":          netns,
        "container_traffic":  _container_flag(ev.netns_ino),
        "authenticated_user": None,
        "pam_service":        None,
        "child_processes":    [],
    }

    # DNS query name (decoded from captured UDP payload when dport==53)
    if hint == "DNS":
        dns_bytes = bytes(ev.dns_payload)
        if any(dns_bytes):  # non-zero payload was captured
            qname = decode_dns_qname(dns_bytes)
            if qname:
                record["dns_query"] = qname

    # ICMP/ICMPv6: stateless — emit immediately as flow_short
    if ev.proto in _ICMP_PROTOS:
        record["event_type"] = "flow_short"
        record["tx_bytes"]   = None
        record["rx_bytes"]   = None
        del record["authenticated_user"]
        del record["pam_service"]
        del record["child_processes"]
        emit(record)
        return

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
    import sys

    parser = argparse.ArgumentParser(
        prog='procflow',
        description=(
            'eBPF-based host network flow monitor with PAM enrichment.\n\n'
            'Captures TCP, UDP, and ICMP flows and emits newline-delimited JSON\n'
            'records enriched with process, exe path, command line, user, socket\n'
            'inode (Wireshark/ss correlation), network namespace (container\n'
            'detection), and — for inbound SSH — authenticated username.\n'
            'Requires root. BPF program is compiled at startup.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'event types:\n'
            '  flow_short       connection closed before --flow-short-secs (default 30s),\n'
            '                   or any UDP/ICMP flow; includes final TX/RX byte counts\n'
            '  flow_long_open   emitted at flow_short_secs for still-open TCP connections;\n'
            '                   byte counts are a snapshot, not final\n'
            '  flow_long_closed emitted when a long-lived TCP session closes;\n'
            '                   paired with flow_long_open via session_id\n'
            '  connect_failed   outbound TCP that failed (ECONNREFUSED, ETIMEDOUT, etc.)\n'
            '  listen_start     TCP socket entered LISTEN state\n\n'
            'wireshark/ids correlation:\n'
            '  sock_ino field matches inode in `ss -tnp` / `ss -unp` output\n'
            '  container_traffic: true when netns_ino differs from host namespace\n\n'
            'examples:\n'
            '  sudo procflow\n'
            '  sudo procflow --config /etc/procflow/procflow.conf\n'
            '  sudo procflow --log-file /tmp/flows.log\n'
            '  sudo procflow --stdout-only | jq \'select(.event_type == "flow_short")\'\n'
            '  sudo procflow --stdout-only | jq \'select(.dns_query != null)\'\n'
            '  sudo procflow --stdout-only | jq \'select(.container_traffic == true)\'\n'
            '  sudo procflow --no-pam --stdout-only\n'
            '  sudo procflow --clear-log\n'
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
    parser.add_argument(
        '--clear-log', action='store_true',
        help='Truncate the active log file and remove rotated backups, then exit. '
             'Safe to run while the service is active.')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(json.dumps({"error": "Must be run as root (sudo)"}))
        sys.exit(1)

    log_file, max_bytes, backups = load_config(args.config)
    if args.log_file:
        log_file = args.log_file

    if args.clear_log:
        # Truncate the active log in-place so the running daemon's file
        # descriptor stays valid — it will simply continue writing from byte 0.
        try:
            with open(log_file, 'w'):
                pass
        except FileNotFoundError:
            pass
        removed = []
        for i in range(1, backups + 1):
            backup = f"{log_file}.{i}"
            try:
                os.remove(backup)
                removed.append(backup)
            except FileNotFoundError:
                break
        print(json.dumps({"status": "log cleared", "log_file": log_file,
                          "backups_removed": removed}))
        sys.exit(0)

    setup_logging(log_file, max_bytes, backups, stdout_only=args.stdout_only)

    # Determine host network namespace inode for container traffic detection
    global HOST_NETNS_INO
    try:
        ns_link = os.readlink("/proc/1/ns/net")
        HOST_NETNS_INO = int(ns_link.split("[")[1].rstrip("]"))
    except Exception:
        HOST_NETNS_INO = 0

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

    expected_event_size = 272
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

    emit({"status": "listening for connections — Ctrl+C to stop",
          "host_netns_ino": HOST_NETNS_INO or None})

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
        # Flush open TCP/UDP flows with final byte counts
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
