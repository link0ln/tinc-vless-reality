/*
    sptps_stub.c -- Stub implementation for SPTPS (disabled)

    This file provides empty implementations for SPTPS functions.
    SPTPS is no longer used - authentication is handled via TLS certificates.
*/

#include "../sptps.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

unsigned int sptps_replaywin = 0;

void sptps_log_quiet(sptps_t *s, int s_errno, const char *format, va_list ap) {
    (void)s;
    (void)s_errno;
    (void)format;
    (void)ap;
}

void sptps_log_stderr(sptps_t *s, int s_errno, const char *format, va_list ap) {
    (void)s;
    (void)s_errno;
    (void)format;
    (void)ap;
}

void (*sptps_log)(sptps_t *s, int s_errno, const char *format, va_list ap) = sptps_log_quiet;

bool sptps_start(sptps_t *s, void *handle, bool initiator, bool datagram,
                 ecdsa_t *mykey, ecdsa_t *hiskey, const void *label, size_t labellen,
                 send_data_t send_data, receive_record_t receive_record) {
    (void)s;
    (void)handle;
    (void)initiator;
    (void)datagram;
    (void)mykey;
    (void)hiskey;
    (void)label;
    (void)labellen;
    (void)send_data;
    (void)receive_record;
    return false;
}

bool sptps_stop(sptps_t *s) {
    (void)s;
    return true;
}

bool sptps_send_record(sptps_t *s, uint8_t type, const void *data, uint16_t len) {
    (void)s;
    (void)type;
    (void)data;
    (void)len;
    return false;
}

size_t sptps_receive_data(sptps_t *s, const void *data, size_t len) {
    (void)s;
    (void)data;
    (void)len;
    return 0;
}

bool sptps_force_kex(sptps_t *s) {
    (void)s;
    return false;
}

bool sptps_verify_datagram(sptps_t *s, const void *data, size_t len) {
    (void)s;
    (void)data;
    (void)len;
    return false;
}
