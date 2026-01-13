#ifndef P2P_H
#define P2P_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>

#include "protocol_defs.h"

// Configuration
#define P2P_PORT 31337
#define MAX_NEIGHBORS 15
#define GOSSIP_INTERVAL_MS 60000 // 60 seconds

typedef struct {
    uint32_t ip;        // Network Byte Order
    uint16_t port;      // Network Byte Order
    time_t last_seen;
    bool is_active;
} Neighbor;

// Packet Types (Mapped to Wire Constants)
#define P2P_TYPE_GOSSIP WIRE_P2P_TYPE_GOSSIP
#define P2P_TYPE_CMD    WIRE_P2P_TYPE_CMD
#define P2P_MAGIC       WIRE_P2P_MAGIC
#define SIG_LEN         64

// Struct for internal command handling
typedef struct {
    uint32_t nonce;
    uint8_t signature[SIG_LEN];
    uint16_t len;
    uint8_t payload[1024]; // Max payload
} P2PCommand;

/**
 * Initializes the P2P subsystem (UDP socket).
 * @return socket fd on success, -1 on failure
 */
int p2p_init(void);

/**
 * Adds a neighbor to the table. Updates last_seen if exists.
 * @param ip IP in Network Byte Order
 * @param port Port in Network Byte Order
 */
void p2p_add_neighbor(uint32_t ip, uint16_t port);

/**
 * Handles incoming UDP P2P packets (Gossip).
 * @param sock Socket FD
 */
void p2p_handle_packet(int sock);

/**
 * Periodically called to gossip with neighbors.
 * Sends neighbor list to random peers.
 */
void p2p_gossip(int sock);

#endif // P2P_H
