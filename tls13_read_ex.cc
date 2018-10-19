#include "tls13_util.h"

int 
main() 
{
  SSL_CTX *client_ssl_ctx, *server_ssl_ctx;
  ssl_ctx_create_pair(server_ssl_ctx, client_ssl_ctx);

  SSL *client_ssl = SSL_new(client_ssl_ctx);
  SSL *server_ssl = SSL_new(server_ssl_ctx);

  int ret = 0;
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
  // ret = ssl_read_ex(client_ssl, &buf, len, static_cast<size_t>(sizeof(buf)), nullptr, 0);
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
