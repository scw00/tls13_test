#pragma once

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>

#include <cstring>
#include <stdio.h>
#include <stdlib.h>

void report_error(SSL *ssl, int ret);

int ssl_connect(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len);

int ssl_accept(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len);

int ssl_read_ex(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len);

int ssl_write_early_data(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len);

int ssl_read_early_data(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len);

int ssl_create_connection(SSL *server_ssl, SSL *client_ssl);

void ssl_shutdown_pair(SSL *server_ssl, SSL *client_ssl);

void ssl_ctx_create_pair(SSL_CTX *&server_ctx, SSL_CTX *&client_ctx);

static constexpr int MAX_HANDSHAKE_MSG_LEN = 2048;

static uint8_t client_hello[MAX_HANDSHAKE_MSG_LEN] = {0};
static size_t client_hello_len                     = 0;

static uint8_t retry[MAX_HANDSHAKE_MSG_LEN] = {0};
static size_t retry_len                     = 0;

static uint8_t server_hello[MAX_HANDSHAKE_MSG_LEN] = {0};
static size_t server_hello_len                     = 0;

static uint8_t client_finished[MAX_HANDSHAKE_MSG_LEN] = {0};
static size_t client_finished_len                     = 0;

static uint8_t post_handshake_msg[MAX_HANDSHAKE_MSG_LEN] = {0};
static size_t post_handshake_msg_len                     = 0;

static const unsigned char key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f
};

#define TLS13_AES_256_GCM_SHA384_BYTES  ((const unsigned char *)"\x13\x02")
#define TLS13_AES_128_GCM_SHA256_BYTES  ((const unsigned char *)"\x13\x01")

static SSL_SESSION *clientpsk = NULL;
static SSL_SESSION *serverpsk = NULL;

static constexpr uint8_t MSG1[] =   "Hello";
static constexpr uint8_t MSG2[] =   "World.";
static constexpr uint8_t MSG3[] =   "This";
static constexpr uint8_t MSG4[] =   "is";
static constexpr uint8_t MSG5[] =   "a";
static constexpr uint8_t MSG6[] =   "test";
static constexpr uint8_t MSG7[] =   "message.";

