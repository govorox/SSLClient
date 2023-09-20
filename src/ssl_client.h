/* Provide SSL/TLS functions to ESP32 with Arduino
 * by Evandro Copercini - 2017 - Apache 2.0 License
 * Additions Copyright (C) 2019 Vadim Govorovski.
 */

#ifndef ARD_SSL_H
#define ARD_SSL_H

#ifdef SSL_CLIENT_TEST_ENVIRONMENT
#include "MbedTLS.h"
#else
#include <mbedtls/platform.h>
#include <mbedtls/net.h>
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

using namespace std;

typedef struct sslclient_context {
  Client* client;

  mbedtls_ssl_context ssl_ctx;
  mbedtls_ssl_config ssl_conf;

  mbedtls_ctr_drbg_context drbg_ctx;
  mbedtls_entropy_context entropy_ctx;

  mbedtls_x509_crt ca_cert;
  mbedtls_x509_crt client_cert;
  mbedtls_pk_context client_key;

  unsigned long handshake_timeout;
} sslclient_context;

static int configure_default_ssl(sslclient_context *ssl_client);
static int configure_ca_cert(sslclient_context *ssl_client, const char *rootCABuff);
static int configure_psk(sslclient_context *ssl_client, const char *pskIdent, const char *psKey);
static int configure_client_cert_key(sslclient_context *ssl_client, const char *cli_cert, const char *cli_key);
int initialize_ssl_client(sslclient_context *ssl_client, const char *host, uint32_t port);
int seed_rng(sslclient_context *ssl_client);
int setup_ssl_configuration(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey);
int load_certificates_and_keys(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key);
int perform_handshake(sslclient_context *ssl_client, const char *host, int timeout=SSL_CLIENT_SLOW_NETWORK_HANDSHAKE_TIMEOUT);
void confirm_protocols(sslclient_context* ssl_client, const char* cli_cert, const char* cli_key);
int verify_peer_certificate(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key);
void clean_up_resources(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key);
void ssl_init(sslclient_context *ssl_client, Client *client);
int start_ssl_client(sslclient_context *ssl_client, const char *host, uint32_t port, int timeout, const char *rootCABuff, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey);
void stop_ssl_socket(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key);
int data_to_read(sslclient_context *ssl_client);
int send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len);
int get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, int length);
bool verify_ssl_fingerprint(sslclient_context *ssl_client, const char* fp, const char* domain_name);
bool verify_ssl_dn(sslclient_context *ssl_client, const char* domain_name);

#endif
