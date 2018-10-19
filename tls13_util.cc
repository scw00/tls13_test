#include "tls13_util.h"
#include "cert.h"

void
ssl_ctx_create_pair(SSL_CTX *&server_ssl_ctx, SSL_CTX *&client_ssl_ctx)
{
  client_ssl_ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_max_early_data(client_ssl_ctx, SSL3_RT_MAX_PLAIN_LENGTH);
  SSL_CTX_clear_options(client_ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
  SSL_CTX_set_min_proto_version(client_ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(client_ssl_ctx, TLS1_3_VERSION);

  server_ssl_ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_set_min_proto_version(server_ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(server_ssl_ctx, TLS1_3_VERSION);
  BIO *crt_bio(BIO_new_mem_buf(server_crt, sizeof(server_crt)));
  BIO *key_bio(BIO_new_mem_buf(server_key, sizeof(server_key)));
  SSL_CTX_clear_options(server_ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
  SSL_CTX_use_certificate(server_ssl_ctx, PEM_read_bio_X509(crt_bio, nullptr, nullptr, nullptr));
  SSL_CTX_use_PrivateKey(server_ssl_ctx, PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr));
  SSL_CTX_set_cipher_list(server_ssl_ctx, ciphers);
  SSL_CTX_set_max_early_data(server_ssl_ctx, SSL3_RT_MAX_PLAIN_LENGTH);
}

void
ssl_shutdown_pair(SSL *server_ssl, SSL *client_ssl)
{
  if (server_ssl != nullptr) {
    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
  }

  if (client_ssl != nullptr) {
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
  }
}

void
report_error(SSL *ssl, int ret)
{
  char err_buf[256] = {0};
  ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
  printf("%s\n", err_buf);
  return;
}

int 
ssl_connect(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len)
{
  BIO *rbio = BIO_new(BIO_s_mem());
  BIO *wbio = BIO_new(BIO_s_mem());
  if (in != nullptr || in_len != 0) {
    BIO_write(rbio, in, in_len);
  }
  SSL_set_bio(ssl, rbio, wbio);
  int err = SSL_ERROR_NONE;
  ERR_clear_error();
  int ret = 0;

  ret = SSL_connect(ssl);
  if (ret < 0) {
    err = SSL_get_error(ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      break;
    default:
      char err_buf[256] = {0};
      ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
      printf("Handshake: %s\n", err_buf);
      return err;
    }
  }

  out_len = BIO_ctrl_pending(wbio);
  if (out_len > 0) {
    BIO_read(wbio, out, max_out_len);
  }
  return 1;
}

int 
ssl_accept(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len)
{
  BIO *rbio = BIO_new(BIO_s_mem());
  BIO *wbio = BIO_new(BIO_s_mem());
  if (in != nullptr || in_len != 0) {
    BIO_write(rbio, in, in_len);
  }
  SSL_set_bio(ssl, rbio, wbio);
  int err = SSL_ERROR_NONE;
  ERR_clear_error();
  int ret = 0;

  ret = SSL_accept(ssl);
  if (ret < 0) {
    err = SSL_get_error(ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      break;
    default:
      char err_buf[256] = {0};
      ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
      printf("Handshake: %s\n", err_buf);
      return err;
    }
  }

  out_len = BIO_ctrl_pending(wbio);
  if (out_len > 0) {
    BIO_read(wbio, out, max_out_len);
  }
  return 1;
}

int 
ssl_read_ex(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len)
{
  BIO *rbio = BIO_new(BIO_s_mem());
  BIO *wbio = BIO_new(BIO_s_mem());
  if (in != nullptr || in_len != 0) {
    BIO_write(rbio, in, in_len);
  }
  SSL_set_bio(ssl, rbio, wbio);
  int err = SSL_ERROR_NONE;
  ERR_clear_error();
  int ret = 0;

  ret = SSL_read_ex(ssl, out, max_out_len, &out_len);
  if (ret < 0) {
    err = SSL_get_error(ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      break;
    default:
      char err_buf[256] = {0};
      ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
      printf("Handshake: %s\n", err_buf);
      return err;
    }
  }
  out_len = BIO_ctrl_pending(wbio);
  if (out_len > 0) {
    BIO_read(wbio, out, max_out_len);
  }
  return 1;
}

int
ssl_write_early_data(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len)
{
  BIO *rbio = BIO_new(BIO_s_mem());
  BIO *wbio = BIO_new(BIO_s_mem());

  SSL_set_bio(ssl, rbio, wbio);
  int err = SSL_ERROR_NONE;
  ERR_clear_error();
  int ret = 0;
  size_t len;

  ret = SSL_write_early_data(ssl, in, in_len, &len);
  if (ret < 0) {
    err = SSL_get_error(ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      break;
    default:
      char err_buf[256] = {0};
      ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
      printf("Handshake: %s\n", err_buf);
      return err;
    }
  }
  out_len = BIO_ctrl_pending(wbio);
  if (out_len > 0) {
    BIO_read(wbio, out, max_out_len);
  }
  return 1;
}

int
ssl_read_early_data(SSL *ssl, uint8_t *out, size_t &out_len, size_t max_out_len, uint8_t *in, size_t in_len)
{
  BIO *rbio = BIO_new(BIO_s_mem());
  BIO *wbio = BIO_new(BIO_s_mem());
  if (in != nullptr || in_len != 0) {
    BIO_write(rbio, in, in_len);
  }
  SSL_set_bio(ssl, rbio, wbio);
  int err = SSL_ERROR_NONE;
  ERR_clear_error();
  int ret = 0;

  ret = SSL_read_early_data(ssl, out, max_out_len, &out_len);
  if (ret < 0) {
    err = SSL_get_error(ssl, ret);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      break;
    default:
      char err_buf[256] = {0};
      ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
      printf("Handshake: %s\n", err_buf);
      return err;
    }
  }
  out_len = BIO_ctrl_pending(wbio);
  if (out_len > 0) {
    BIO_read(wbio, out, max_out_len);
  }
  return 1;
}

int
ssl_create_connection(SSL *server_ssl, SSL *client_ssl)
{
  int ret;
  uint8_t client_hello[MAX_HANDSHAKE_MSG_LEN] = {0};
  size_t client_hello_len                     = 0;

  // client hello
  ret = ssl_connect(client_ssl, client_hello, client_hello_len, MAX_HANDSHAKE_MSG_LEN, nullptr, 0);
  if (ret <= 0 ) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      exit(0);
    }
  }

  // server hello
  ret = ssl_accept(server_ssl, server_hello, server_hello_len, MAX_HANDSHAKE_MSG_LEN, client_hello, client_hello_len);
  if (ret <= 0 ) {
    int err           = SSL_get_error(server_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(server_ssl, ret);
      exit(0);
    }
  }

  // finished
  ret = ssl_connect(client_ssl, client_finished, client_finished_len, MAX_HANDSHAKE_MSG_LEN, server_hello, server_hello_len);
  if (ret <= 0 ) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      exit(0);
    }
  }

  // post msg 
  ret = ssl_accept(server_ssl, post_handshake_msg, post_handshake_msg_len, MAX_HANDSHAKE_MSG_LEN, client_finished, client_finished_len);
  if (ret <= 0 ) {
    int err           = SSL_get_error(server_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(server_ssl, ret);
      exit(0);
    }
  }

  // done
  unsigned char buf; 
  size_t len;
  ret = ssl_read_ex(client_ssl, &buf, len, static_cast<size_t>(sizeof(buf)), post_handshake_msg, post_handshake_msg_len);
  if (ret <= 0 ) {
    int err           = SSL_get_error(server_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(server_ssl, ret);
      exit(0);
    }
  }
  return 1;
}
