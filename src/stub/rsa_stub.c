/*
    rsa_stub.c -- Stub implementation for RSA (disabled)

    This file provides empty implementations for RSA functions.
    RSA is no longer used - authentication is handled via TLS certificates.
*/

#include "../rsa.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

void rsa_free(rsa_t *rsa) {
    (void)rsa;
}

rsa_t *rsa_set_hex_public_key(char *n, char *e) {
    (void)n;
    (void)e;
    return NULL;
}

rsa_t *rsa_set_hex_private_key(char *n, char *e, char *d) {
    (void)n;
    (void)e;
    (void)d;
    return NULL;
}

rsa_t *rsa_read_pem_public_key(FILE *fp) {
    (void)fp;
    return NULL;
}

rsa_t *rsa_read_pem_private_key(FILE *fp) {
    (void)fp;
    return NULL;
}

size_t rsa_size(rsa_t *rsa) {
    (void)rsa;
    return 0;
}

bool rsa_public_encrypt(rsa_t *rsa, void *in, size_t len, void *out) {
    (void)rsa;
    (void)in;
    (void)len;
    (void)out;
    return false;
}

bool rsa_private_decrypt(rsa_t *rsa, void *in, size_t len, void *out) {
    (void)rsa;
    (void)in;
    (void)len;
    (void)out;
    return false;
}
