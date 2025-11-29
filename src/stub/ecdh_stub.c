/*
    ecdh_stub.c -- Stub implementation for ECDH (disabled)

    This file provides empty implementations for ECDH functions.
    ECDH is no longer used - key exchange is handled via TLS.
*/

#include "../ecdh.h"
#include <stdbool.h>
#include <stddef.h>

ecdh_t *ecdh_generate_public(void *pubkey) {
    (void)pubkey;
    return NULL;
}

bool ecdh_compute_shared(ecdh_t *ecdh, const void *pubkey, void *shared) {
    (void)ecdh;
    (void)pubkey;
    (void)shared;
    return false;
}

void ecdh_free(ecdh_t *ecdh) {
    (void)ecdh;
}
