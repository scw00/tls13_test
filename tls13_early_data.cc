#include "tls13_util.h"

int
main()
{
  SSL_CTX *client_ssl_ctx, *server_ssl_ctx;
  ssl_ctx_create_pair(server_ssl_ctx, client_ssl_ctx);

  SSL *client_ssl = SSL_new(client_ssl_ctx);
  SSL *server_ssl = SSL_new(server_ssl_ctx);

  ssl_create_connection(server_ssl, client_ssl);

  auto client_session = SSL_get1_session(client_ssl);
  ssl_shutdown_pair(server_ssl, client_ssl);

  client_ssl = SSL_new(client_ssl_ctx);
  server_ssl = SSL_new(server_ssl_ctx);
  SSL_set_max_early_data(client_ssl, SSL3_RT_MAX_PLAIN_LENGTH);

  int ret;
  SSL_set_session(client_ssl, client_session);

  memset(client_hello, 0, MAX_HANDSHAKE_MSG_LEN);
  client_hello_len = 0;
  ret = ssl_write_early_data(client_ssl, client_hello, client_hello_len, MAX_HANDSHAKE_MSG_LEN, const_cast<uint8_t *>(MSG1), sizeof(MSG1));
  if (ret <= 0 ) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      exit(0);
    }
  }

  memset(server_hello, 0, MAX_HANDSHAKE_MSG_LEN);
  server_hello_len = 0;
  ret = ssl_read_early_data(server_ssl, server_hello, server_hello_len, MAX_HANDSHAKE_MSG_LEN, client_hello, client_hello_len);
  if (ret <= 0 ) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      exit(0);
    }
  }
  if (SSL_get_early_data_status(server_ssl) != SSL_EARLY_DATA_ACCEPTED) {
    report_error(server_ssl, 2);
    exit(0);
  }

  memset(client_finished, 0, MAX_HANDSHAKE_MSG_LEN);
  client_finished_len = 0;
  ret = ssl_connect(client_ssl, client_finished, client_finished_len, MAX_HANDSHAKE_MSG_LEN, server_hello, server_hello_len);
  if (ret <= 0) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      exit(0);
    }
  }

  memset(post_handshake_msg, 0, MAX_HANDSHAKE_MSG_LEN);
  post_handshake_msg_len = 0;
  ret = ssl_accept(server_ssl, post_handshake_msg, post_handshake_msg_len, MAX_HANDSHAKE_MSG_LEN, client_finished, client_finished_len);
  if (ret <= 0) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      exit(0);
    }
  }

}
