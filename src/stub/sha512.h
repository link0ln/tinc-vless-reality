/*
    sha512.h -- SHA512 wrapper using OpenSSL

    This replaces the ed25519/sha512.h implementation
*/

#ifndef TINC_STUB_SHA512_H
#define TINC_STUB_SHA512_H

#include <stddef.h>
#include <openssl/sha.h>

// Original ed25519 sha512 returns 0 on success
static inline int sha512(const void *data, size_t len, unsigned char *hash) {
    SHA512(data, len, hash);
    return 0;  // Success
}

#endif
