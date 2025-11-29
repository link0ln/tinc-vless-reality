/*
    rsagen_stub.c -- Stub implementation for RSA key generation (disabled)

    This file provides empty implementations for RSA key generation functions.
    RSA is no longer used - authentication is handled via TLS certificates.
*/

#include "../rsagen.h"
#include "../rsa.h"
#include <stdbool.h>
#include <stdio.h>

rsa_t *rsa_generate(size_t bits, unsigned long e) {
    (void)bits;
    (void)e;
    return NULL;
}

bool rsa_write_pem_public_key(rsa_t *rsa, FILE *fp) {
    (void)rsa;
    (void)fp;
    return false;
}

bool rsa_write_pem_private_key(rsa_t *rsa, FILE *fp) {
    (void)rsa;
    (void)fp;
    return false;
}
