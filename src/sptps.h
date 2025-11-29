#ifndef TINC_SPTPS_H
#define TINC_SPTPS_H

/*
    sptps.h -- Stub header for SPTPS (disabled)

    SPTPS is no longer used - authentication is handled via TLS certificates.
    This header provides type definitions for compilation compatibility.
*/

#include "system.h"
#include "ecdsa.h"
#include "ecdh.h"

#define SPTPS_VERSION 0

// Record types
#define SPTPS_HANDSHAKE 128
#define SPTPS_ALERT 129
#define SPTPS_CLOSE 130

// Key exchange states
#define SPTPS_KEX 1
#define SPTPS_SECONDARY_KEX 2
#define SPTPS_SIG 3
#define SPTPS_ACK 4

// Overhead for datagrams
#define SPTPS_DATAGRAM_OVERHEAD 21

typedef bool (*send_data_t)(void *handle, uint8_t type, const void *data, size_t len);
typedef bool (*receive_record_t)(void *handle, uint8_t type, const void *data, uint16_t len);

// Stub cipher context type
typedef struct chacha_poly1305_ctx {
    void *dummy;
} chacha_poly1305_ctx_t;

typedef struct sptps {
    bool initiator;
    bool datagram;
    int state;

    char *inbuf;
    size_t buflen;
    uint16_t reclen;

    bool instate;
    chacha_poly1305_ctx_t *incipher;
    uint32_t inseqno;
    uint32_t received;
    unsigned int replaywin;
    unsigned int farfuture;
    char *late;

    bool outstate;
    chacha_poly1305_ctx_t *outcipher;
    uint32_t outseqno;

    ecdsa_t *mykey;
    ecdsa_t *hiskey;
    ecdh_t *ecdh;

    char *mykex;
    char *hiskex;
    char *key;
    char *label;
    size_t labellen;

    void *handle;
    send_data_t send_data;
    receive_record_t receive_record;
} sptps_t;

extern unsigned int sptps_replaywin;
extern void sptps_log_quiet(sptps_t *s, int s_errno, const char *format, va_list ap);
extern void sptps_log_stderr(sptps_t *s, int s_errno, const char *format, va_list ap);
extern void (*sptps_log)(sptps_t *s, int s_errno, const char *format, va_list ap);
extern bool sptps_start(sptps_t *s, void *handle, bool initiator, bool datagram, ecdsa_t *mykey, ecdsa_t *hiskey, const void *label, size_t labellen, send_data_t send_data, receive_record_t receive_record);
extern bool sptps_stop(sptps_t *s);
extern bool sptps_send_record(sptps_t *s, uint8_t type, const void *data, uint16_t len);
extern size_t sptps_receive_data(sptps_t *s, const void *data, size_t len);
extern bool sptps_force_kex(sptps_t *s);
extern bool sptps_verify_datagram(sptps_t *s, const void *data, size_t len);

#endif
