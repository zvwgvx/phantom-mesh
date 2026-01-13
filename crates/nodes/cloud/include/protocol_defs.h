#ifndef PROTOCOL_DEFS_H
#define PROTOCOL_DEFS_H

/* Generated from Rust crates/shared/protocol/src/wire.rs */

#include <stdint.h>

// Wire Constants
#define WIRE_P2P_MAGIC 0x9A1D3F7C
#define WIRE_P2P_TYPE_GOSSIP 1
#define WIRE_P2P_TYPE_CMD 2
#define WIRE_MQTT_PUBLISH 0x30
#define WIRE_MAX_TOPIC_LEN 256

// Packed Structures Matches Rust #[repr(C, packed)]
// Note: Fields are Network Byte Order (Big Endian)

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t type;
} WireP2PHeader;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t type;
    uint32_t nonce;
    uint8_t signature[64];
    uint16_t payload_len;
} WireP2PCommand;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t type;
    uint8_t count;
} WireP2PGossip;

#endif // PROTOCOL_DEFS_H
