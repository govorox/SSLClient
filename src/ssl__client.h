/* Provide SSL/TLS functions to ESP32 with Arduino
 * by Evandro Copercini - 2017 - Apache 2.0 License
 * Additions Copyright (C) 2019 Vadim Govorovski.
 */

#ifndef SSL__CLIENT_H
#define SSL__CLIENT_H

#ifdef SSL_CLIENT_TEST_ENVIRONMENT
#include "MbedTLS.h"
#else
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/oid.h>
#if (MBEDTLS_VERSION_MAJOR >= 3) && !defined(MBEDTLS_BACKPORT)
#include <mbedtls/net_sockets.h>
#else
#include <mbedtls/net.h>
#endif
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>
#include <mbedtls/oid.h>
#endif

#include <Client.h>

#define SSL_CLIENT_LOW_LATENCY_NETWORK_HANDSHAKE_TIMEOUT 5000U
#define SSL_CLIENT_DEFAULT_HANDSHAKE_TIMEOUT 15000U
#define SSL_CLIENT_SLOW_NETWORK_HANDSHAKE_TIMEOUT 30000U
#define SSL_CLIENT_UNRELIABLE_NETWORK_HANDSHAKE_TIMEOUT 45000U
#define SSL_CLIENT_SEND_BUFFER_SIZE 1024U

typedef struct sslclient__context {
  Client* client;

  mbedtls_ssl_context ssl_ctx;
  mbedtls_ssl_config ssl_conf;

  mbedtls_ctr_drbg_context drbg_ctx;
  mbedtls_entropy_context entropy_ctx;

  mbedtls_x509_crt ca_cert;
  mbedtls_x509_crt client_cert;
  mbedtls_pk_context client_key;

  unsigned long handshake_timeout;
} sslclient__context;

void ssl_init(sslclient__context *ssl_client, Client *client);
void log_failed_cert(int flags);
void cleanup(sslclient__context *ssl_client, bool ca_cert_initialized, bool client_cert_initialized, bool client_key_initialized, int ret, const char *rootCABuff, const char *cli_cert, const char *cli_key);
int start_ssl_client(sslclient__context *ssl_client, const char *host, uint32_t port, int timeout, const char *rootCABuff, bool useRootCABundle, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey, bool insecure, const char **alpn_protos);
int init_tcp_connection(sslclient__context *ssl_client, const char *host, uint32_t port);
int seed_random_number_generator(sslclient__context *ssl_client);
int set_up_tls_defaults(sslclient__context *ssl_client);
int auth_root_ca_buff(sslclient__context *ssl_client, const char *rootCABuff, bool *ca_cert_initialized, const char *pskIdent, const char *psKey, bool insecure);
int auth_client_cert_key(sslclient__context *ssl_client, const char *cli_cert, const char *cli_key, bool *client_cert_initialized, bool *client_key_initialized);
int set_hostname_for_tls(sslclient__context *ssl_client, const char *host);
int set_io_callbacks_and_timeout(sslclient__context *ssl_client, int timeout);
int perform_ssl_handshake(sslclient__context *ssl_client, const char *cli_cert, const char *cli_key);
int verify_server_cert(sslclient__context *ssl_client);
void stop_ssl_socket(sslclient__context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key);
int data_to_read(sslclient__context *ssl_client);
int send_ssl_data(sslclient__context *ssl_client, const uint8_t *data, size_t len);
int get_ssl_receive(sslclient__context *ssl_client, uint8_t *data, size_t length);
bool verify_ssl_fingerprint(sslclient__context *ssl_client, const char* fp, const char* domain_name);
bool verify_ssl_dn(sslclient__context *ssl_client, const char* domain_name);
bool get_peer_fingerprint(sslclient__context *ssl_client, uint8_t sha256[32]);

#endif
