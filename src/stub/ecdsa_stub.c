/*
    ecdsa_stub.c -- Stub implementation for ECDSA (disabled)

    This file provides empty implementations for ECDSA functions.
    ECDSA is no longer used - authentication is handled via TLS certificates.
*/

#include "../ecdsa.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

ecdsa_t *ecdsa_set_base64_public_key(const char *p) {
    (void)p;
    return NULL;
}

char *ecdsa_get_base64_public_key(ecdsa_t *ecdsa) {
    (void)ecdsa;
    return NULL;
}

ecdsa_t *ecdsa_read_pem_public_key(FILE *fp) {
    (void)fp;
    return NULL;
}

ecdsa_t *ecdsa_read_pem_private_key(FILE *fp) {
    (void)fp;
    return NULL;
}

size_t ecdsa_size(ecdsa_t *ecdsa) {
    (void)ecdsa;
    return 0;
}

bool ecdsa_sign(ecdsa_t *ecdsa, const void *in, size_t inlen, void *out) {
    (void)ecdsa;
    (void)in;
    (void)inlen;
    (void)out;
    return false;
}

bool ecdsa_verify(ecdsa_t *ecdsa, const void *in, size_t inlen, const void *out) {
    (void)ecdsa;
    (void)in;
    (void)inlen;
    (void)out;
    return false;
}

bool ecdsa_active(ecdsa_t *ecdsa) {
    (void)ecdsa;
    return false;
}

void ecdsa_free(ecdsa_t *ecdsa) {
    (void)ecdsa;
}
