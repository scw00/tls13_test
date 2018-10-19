
#include <cassert>

#include "tls13_util.h"
#include "cert.h"

constexpr unsigned char client_psk_id[] = "client psk id";
constexpr unsigned char client_psk[] = "client psk";

constexpr static char session_file[] = "session.txt";

#define ASSERTION 0

#if ASSERTION == 1
#define tls_assert(a) assert(a);
#else 
#define tls_assert(a) void(a)
#endif

// static int
// ssl_client_use_session_callback(SSL *ssl, const EVP_MD *md, const unsigned char **id, size_t *idlen, SSL_SESSION **sess)
// {
//   printf("[ssl_client_use_session_callback] md: %p\n", md);
//   if (clientpsk != nullptr) {
//     *sess = clientpsk;
//   }
// 
//   *id = client_psk_id;
//   *idlen = sizeof(client_psk_id);
//   return 1;
// }

// static int
// ssl_server_find_session_callback(SSL *ssl, const unsigned char *identity, size_t identity_len, SSL_SESSION **sess)
// {
//   printf("[ssl_server_find_session_callback] id %*.s\n", static_cast<int>(identity_len), identity);
//   if (serverpsk != nullptr) {
//     *sess = serverpsk; 
//   }
//   return 1;
// }

static unsigned int
ssl_client_set_psk_callback(SSL *ssl, const char *hint, char *id, unsigned int max_id_len, unsigned char *psk, unsigned int max_psk_len)
{
  printf("[ssl_client_psk_callback]\n");
  memcpy(id, client_psk_id, sizeof(client_psk_id));
  memcpy(psk, client_psk, sizeof(client_psk));
  return sizeof(client_psk) - 1;
}

// static unsigned int
// ssl_server_psk_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
// {
//   printf("[ssl_server_psk_callback]\n");
//   memcpy(psk, client_psk, sizeof(client_psk));
//   return sizeof(client_psk) - 1;
// }

static int 
ssl_client_new_session(SSL *ssl, SSL_SESSION *session)
{
  auto file = BIO_new_file(session_file, "w");
  tls_assert(file != nullptr);

  PEM_write_bio_SSL_SESSION(file, session);
  BIO_free(file);
  return 0;
}

static int 
reuse_session_by_session_file(SSL *client_ssl)
{
  auto file = BIO_new_file(session_file, "r"); 
  if (file == nullptr) {
    return -1; 
  }

  auto session = PEM_read_bio_SSL_SESSION(file, nullptr, 0, nullptr);
  if (session == nullptr) {
    return -1;
  }

  clientpsk = session;
  return 0;
}

/*

          Client                                               Server

   Initial Handshake:
          ClientHello
          + key_share               -------->
                                                          ServerHello
                                                          + key_share
                                                {EncryptedExtensions}
                                                {CertificateRequest*}
                                                       {Certificate*}
                                                 {CertificateVerify*}
                                                           {Finished}
                                    <--------     [Application Data*]
          {Certificate*}
          {CertificateVerify*}
          {Finished}                -------->
                                    <--------      [NewSessionTicket]
          [Application Data]        <------->      [Application Data]


   Subsequent Handshake:
          ClientHello
          + key_share*
          + pre_shared_key          -------->
                                                          ServerHello
                                                     + pre_shared_key
                                                         + key_share*
                                                {EncryptedExtensions}
                                                           {Finished}
                                    <--------     [Application Data*]
          {Finished}                -------->
          [Application Data]        <------->      [Application Data]

               Figure 3: Message Flow for Resumption and PSK
*/

static int 
ssl_key_callback(SSL *ssl, int name, const unsigned char *secret, size_t secret_len, const unsigned char *key, size_t key_len,
                                      const unsigned char *iv, size_t iv_len, void *arg)
{
  switch (name) {
    case SSL_KEY_CLIENT_EARLY_TRAFFIC:
      printf("client_early_traffic\n");
      break;
    case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
      printf("client_handshake_traffic\n");
      break;
    case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
      printf("client_application_traffic\n");
      break;
    case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
      printf("server_handshake_traffic\n");
      break;
    case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
      printf("server_application_traffic\n");
      break;
    default:
      break;
    }

  return 1;
}


int
main()
{
  SSL_CTX *client_ssl_ctx, *server_ssl_ctx; 
  ssl_ctx_create_pair(server_ssl_ctx, client_ssl_ctx);

//   SSL_CTX_set_psk_use_session_callback(client_ssl_ctx, ssl_client_use_session_callback);
//   SSL_CTX_set_psk_find_session_callback(server_ssl_ctx, ssl_server_find_session_callback);
//   SSL_CTX_set_psk_client_callback(client_ssl_ctx, ssl_client_set_psk_callback);  
//   SSL_CTX_set_psk_server_callback(server_ssl_ctx, ssl_server_psk_callback);

  SSL_CTX_set_session_cache_mode(client_ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  SSL_CTX_sess_set_new_cb(client_ssl_ctx, ssl_client_new_session);
  SSL_CTX_set_max_early_data(server_ssl_ctx, 0xffff);
  SSL_CTX_set_max_early_data(client_ssl_ctx, 0xffff);

  SSL *server_ssl = SSL_new(server_ssl_ctx);
  SSL *client_ssl = SSL_new(client_ssl_ctx);

  ssl_create_connection(server_ssl, client_ssl);

  ssl_shutdown_pair(server_ssl, client_ssl);

  client_ssl = SSL_new(client_ssl_ctx);
  server_ssl = SSL_new(server_ssl_ctx);

  SSL_set_psk_client_callback(client_ssl, ssl_client_set_psk_callback);
  SSL_set_key_callback(client_ssl, ssl_key_callback, nullptr);
  SSL_set_key_callback(server_ssl, ssl_key_callback, nullptr);

  tls_assert(reuse_session_by_session_file(client_ssl) == 0);
  SSL_set_session(client_ssl, clientpsk);

//   SSL_set_session(client_ssl, clientpsk);
//   auto cipher = SSL_CIPHER_find(client_ssl, TLS13_AES_128_GCM_SHA256_BYTES);
//   clientpsk = SSL_SESSION_new();
//   SSL_SESSION_set1_master_key(clientpsk, key, sizeof(key)); 
//   SSL_SESSION_set_cipher(clientpsk, cipher);
//   SSL_SESSION_set_protocol_version(clientpsk, TLS1_3_VERSION);
//   SSL_SESSION_up_ref(clientpsk);
  
  
  int ret;
  memset(client_hello, 0, MAX_HANDSHAKE_MSG_LEN);
  client_hello_len = 0;
  ret = ssl_write_early_data(client_ssl, client_hello, client_hello_len, MAX_HANDSHAKE_MSG_LEN, (uint8_t *)"hello world", 11);
  if (ret <= 0 ) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      tls_assert(0);
    }
  }

  memset(client_finished, 0, MAX_HANDSHAKE_MSG_LEN);
  client_finished_len = 0;
  ret = ssl_connect(client_ssl, client_finished, client_finished_len, MAX_HANDSHAKE_MSG_LEN, server_hello, server_hello_len);
  if (ret <= 0) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      tls_assert(0);
    }
  }

  memset(server_hello, 0, MAX_HANDSHAKE_MSG_LEN);
  server_hello_len = 0;
  ret = ssl_read_early_data(server_ssl, server_hello, server_hello_len, MAX_HANDSHAKE_MSG_LEN, client_hello, client_hello_len);
  if (ret <= 0 ) {
    int err           = SSL_get_error(server_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(server_ssl, ret);
      tls_assert(0);
    }
  }

  if (SSL_get_early_data_status(server_ssl) != SSL_EARLY_DATA_ACCEPTED) {
    report_error(server_ssl, 2);
    tls_assert(0);
  }

  memset(client_finished, 0, MAX_HANDSHAKE_MSG_LEN);
  client_finished_len = 0;
  ret = ssl_connect(client_ssl, client_finished, client_finished_len, MAX_HANDSHAKE_MSG_LEN, server_hello, server_hello_len);
  if (ret <= 0) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      tls_assert(0);
    }
  }

  memset(post_handshake_msg, 0, MAX_HANDSHAKE_MSG_LEN);
  post_handshake_msg_len = 0;
  ret = ssl_accept(server_ssl, post_handshake_msg, post_handshake_msg_len, MAX_HANDSHAKE_MSG_LEN, client_finished, client_finished_len);
  if (ret <= 0) {
    int err           = SSL_get_error(client_ssl, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      report_error(client_ssl, ret);
      tls_assert(0);
    }
  }



  tls_assert(SSL_session_reused(client_ssl));
}
