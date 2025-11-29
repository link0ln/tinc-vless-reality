/*
    ecdsagen_stub.c -- Stub implementation for ECDSA key generation (disabled)

    This file provides empty implementations for ECDSA key generation functions.
    ECDSA is no longer used - authentication is handled via TLS certificates.
*/

#include "../ecdsagen.h"
#include "../ecdsa.h"
#include <stdbool.h>
#include <stdio.h>

ecdsa_t *ecdsa_generate(void) {
    return NULL;
}

bool ecdsa_write_pem_public_key(ecdsa_t *ecdsa, FILE *fp) {
    (void)ecdsa;
    (void)fp;
    return false;
}

bool ecdsa_write_pem_private_key(ecdsa_t *ecdsa, FILE *fp) {
    (void)ecdsa;
    (void)fp;
    return false;
}
