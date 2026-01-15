#include "verify.h"
#include "tweetnacl.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static const uint8_t MASTER_PUBKEY[PUBKEY_LEN] = {
    0x75, 0xbf, 0x34, 0x60, 0xf7, 0x00, 0x57, 0x06, 
    0xa3, 0x82, 0x85, 0x4d, 0x0b, 0x31, 0xc7, 0x63, 
    0x30, 0x4d, 0x15, 0x19, 0x18, 0xd1, 0xca, 0x87, 
    0xe7, 0x38, 0x99, 0xcc, 0x79, 0x3d, 0xb8, 0x6a
};

bool ed25519_verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig) {
    if (msg_len == 0 || !msg || !sig) return false;

    unsigned long long smlen = SIG_LEN + msg_len;
    unsigned char *sm = malloc(smlen);
    if (!sm) return false;

    memcpy(sm, sig, SIG_LEN);
    memcpy(sm + SIG_LEN, msg, msg_len);

    unsigned char *m = malloc(smlen);
    if (!m) {
        free(sm);
        return false;
    }
    unsigned long long mlen;

    int ret = crypto_sign_open(m, &mlen, sm, smlen, MASTER_PUBKEY);

    free(sm);
    free(m);

    return (ret == 0);
}

void randombytes(unsigned char *x, unsigned long long xlen) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, x, xlen);
        close(fd);
    } else {
        for (unsigned long long i = 0; i < xlen; i++) x[i] = rand() % 256;
    }
}

