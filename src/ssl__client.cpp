/* Provide SSL/TLS functions to ESP32 with Arduino IDE
*
* Adapted from the ssl_client example of mbedtls.
*
* Original Copyright (C) 2006-2015, ARM Limited, All Rights Reserved, Apache 2.0 License.
* Additions Copyright (C) 2017 Evandro Luis Copercini, Apache 2.0 License.
* Additions Copyright (C) 2019 Vadim Govorovski.
*/
#ifdef PLATFORMIO
#include <Arduino.h>
#endif
#include "ssl__client.h"
#include "certBundle.h"
#include <string>

using namespace std;

#if !defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
#  error "Please configure IDF framework to include mbedTLS -> Enable pre-shared-key ciphersuites and activate at least one cipher"
#endif

const char *persy = "esp32-tls";

/**
 * \brief           Handle the error.
 * 
 * \param err       int - The error code.
 * \param function  const char* - The function name.
 * \param line      int - The line number. 
 * \return int      The error code. 
 */
static int _handle_error(int err, const char * function, int line) {
  if(err == -30848) {
    return err;
  }
#ifdef MBEDTLS_ERROR_C
  char error_buf[100];
  mbedtls_strerror(err, error_buf, 100);

  if (err == MBEDTLS_ERR_NET_SEND_FAILED) { 
    strncpy(error_buf, "Failed to send data - underlying network layer error", sizeof(error_buf) - 1);
    error_buf[sizeof(error_buf) - 1] = '\0';
  }
  
  log_e("[%s():%d]: (%d) %s", function, line, err, error_buf);
#else
  log_e("[%s():%d]: code %d", function, line, err);
#endif
  return err;
}

#define handle_error(e) _handle_error(e, __FUNCTION__, __LINE__)

/**
 * \brief          Read at most 'len' characters. If no error occurs,
 *                 the actual amount read is returned.
 *
 * \param ctx      Client*
 * \param buf      The buffer to write to
 * \param len      Maximum length of the buffer
 *
 * \return         the number of bytes received,
 *                 or a non-zero error code; with a non-blocking socket,
 *                 MBEDTLS_ERR_SSL_WANT_READ indicates read() would block.
 * \return int    -1 if Client* is nullptr.
 * \return int    -2 if connect failed.
 */
static int client_net_recv( void *ctx, unsigned char *buf, size_t len ) {
  Client *client = (Client*)ctx;
  if (!client) { 
    log_e("Uninitialised!");
    return -1;
  }
  
  if (!client->connected()) {
    log_e("Not connected!");
    return -2;
  }

  int result = client->read(buf, len);
  log_v("SSL client RX res=%d len=%zu", result, len);

  // if (result > 0) {
    //esp_log_buffer_hexdump_internal("SSL.RD", buf, (uint16_t)result, ESP_LOG_VERBOSE);
  // }
  
  return result;
}

/**
 * \brief           Read at most 'len' characters. If no error occurs,
 *                  the actual amount read is returned.
 * 
 * \param ctx       Client* - The client context. 
 * \param buf       unsigned char* - The buffer to write to. 
 * \param len       size_t - The maximum length of the buffer. 
 * \param timeout   uint32_t - The timeout in milliseconds. 
 * \return int      The number of bytes received, or a non-zero error code;
 *                  with a non-blocking socket, MBEDTLS_ERR_SSL_WANT_READ
 *                  indicates read() would block. 
 * \return int      0 if incorrectly called and len = 0,
 * \return int      -1 if Client* is nullptr.
 * \return int      -2 if connect failed.
 */
int client_net_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout) {
  Client *client = (Client*)ctx;

  if (!client) { 
    log_e("Uninitialised!");
    return -1;
  }

  if (len == 0) {
    log_e("Zero length specified!");
    return 0;
  }

  log_v("Timeout set to %u", timeout);

  unsigned long start = millis();
  unsigned long tms = start + timeout;
  
  do {
    int pending = client->available();
    if (pending < len && timeout > 0) {
      delay(1);
    } else {
      break;
    }
  } while (millis() < tms);
  
  int result = client->read(buf, len);
  
  if (!result) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  log_v("SSL client RX (received=%d expected=%zu in %lums)", result, len, millis()-start);
  
  // if (result > 0) {
    //esp_log_buffer_hexdump_internal("SSL.RD", buf, (uint16_t)result, ESP_LOG_VERBOSE);
  // }
  
  return result;
}

/**
 * \brief         Write at most 'len' characters. If no error occurs,
 *                the actual amount read is returned.
 *
 * \param ctx     Client*
 * \param buf     The buffer to read from
 * \param len     The length of the buffer
 * \return int    The number of bytes sent, or a non-zero
 *                error code; with a non-blocking socket,
 *                MBEDTLS_ERR_SSL_WANT_WRITE indicates write() would block.
 * \return int    -1 if Client* is nullptr.
 * \return int    -2 if connect failed.
 */
static int client_net_send(void *ctx, const unsigned char *buf, size_t len) {
  Client *client = (Client*)ctx;
  if (!client) { 
    log_e("Uninitialised!");
    return -1;
  }
  
  if (!client->connected()) {
    log_e("Not connected!");
    return -2;
  }
  
  // esp_log_buffer_hexdump_internal("SSL.WR", buf, (uint16_t)len, ESP_LOG_VERBOSE);BEDTLS_ERR_NET_SEND_FAILED;

  // int result = client->write(buf, len);
  int result = 0;
  for (int i = 0; i < len; i += SSL_CLIENT_SEND_BUFFER_SIZE) {
    int bytesToWrite;

    if (SSL_CLIENT_SEND_BUFFER_SIZE > len - i) {
      bytesToWrite = len - i;
    } else {
      bytesToWrite = SSL_CLIENT_SEND_BUFFER_SIZE;
    }

    // Create a new buffer for each chunk
    unsigned char buffer[bytesToWrite];
    memcpy(buffer, &buf[i], bytesToWrite);

    // Send the buffer to the client
    result += client->write(buffer, bytesToWrite);
    if (result == 0) {
      log_e("write failed");
      result = MBEDTLS_ERR_NET_SEND_FAILED;
      break;
    }
  }
  
  log_v("SSL client TX res=%d len=%zu", result, len);
  
  return result;
}

/**
 * \brief             Initialize the sslclient__context struct.
 * 
 * \param ssl_client  sslclient__context* - The ssl client context. 
 * \param client      Client* - The client. 
 */
void ssl_init(sslclient__context *ssl_client, Client *client) {
  log_d("Init SSL");
  // reset embedded pointers to zero
  memset(ssl_client, 0, sizeof(sslclient__context));
  ssl_client->client = client;
  mbedtls_ssl_init(&ssl_client->ssl_ctx);
  mbedtls_ssl_config_init(&ssl_client->ssl_conf);
  mbedtls_ctr_drbg_init(&ssl_client->drbg_ctx);
}

/**
 * \brief Cleans up allocated resources and stops the SSL socket if an error occurred.
 *
 * \param ssl_client Pointer to the SSL client context.
 * \param ca_cert_initialized Flag indicating if the CA certificate was initialized.
 * \param client_cert_initialized Flag indicating if the client certificate was initialized.
 * \param client_key_initialized Flag indicating if the client key was initialized.
 * \param ret Return value from the previous operations.
 * \param rootCABuff Pointer to the root CA buffer.
 * \param cli_cert Pointer to the client certificate.
 * \param cli_key Pointer to the client key.
 */
void cleanup(
  sslclient__context *ssl_client,
  bool ca_cert_initialized,
  bool client_cert_initialized,
  bool client_key_initialized,
  int ret,
  const char *rootCABuff,
  const char *cli_cert,
  const char *cli_key
) {
  if (ca_cert_initialized) {
    mbedtls_x509_crt_free(&ssl_client->ca_cert);
  }
  if (client_cert_initialized) {
    mbedtls_x509_crt_free(&ssl_client->client_cert);
  }
  if (client_key_initialized) {
    mbedtls_pk_free(&ssl_client->client_key);
  }
  if (ret != 0) {
    stop_ssl_socket(ssl_client, rootCABuff, cli_cert, cli_key);  // Stop SSL socket on error
  }
  log_d("Free internal heap after TLS %u", ESP.getFreeHeap());
}

/**
 * \brief Logs information about a failed certificate verification.
 *
 * \param flags Flags returned from the certificate verification process.
 */
void log_failed_cert(int flags) {
  if (flags != 0) {
    char buf[512];
    memset(buf, 0, sizeof(buf));
    mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
    log_e("Failed to verify peer certificate! verification info: %s", buf);
  }
}

/**
 * \brief Starts the SSL client, handling initialization, authentication, and connection processes.
 *
 * \param ssl_client Pointer to the SSL client context.
 * \param host Pointer to the host string.
 * \param port Port number for the connection.
 * \param timeout Timeout value for the connection.
 * \param rootCABuff Pointer to the root CA buffer.
 * \param useRootCABundle Flag indicating if the root CA bundle should be used.
 * \param cli_cert Pointer to the client certificate.
 * \param cli_key Pointer to the client key.
 * \param pskIdent Pointer to the PSK identifier.s
 * \param psKey Pointer to the PSK key.
 * \param insecure Flag indicating if the connection is insecure.
 * \param alpn_protos Pointer to the ALPN protocols.
 * \return 1 on successful SSL client start, 0 otherwise.
 */
int start_ssl_client(
  sslclient__context *ssl_client,
  const char *host,
  uint32_t port,
  int timeout,
  const char *rootCABuff,
  bool useRootCABundle,
  const char *cli_cert,
  const char *cli_key,
  const char *pskIdent,
  const char *psKey,
  bool insecure,
  const char **alpn_protos
) {
  log_v("Free internal heap before TLS %u", ESP.getFreeHeap());
  log_v("Connecting to %s:%d", host, port);

  int ret = 0; // for mbedtls function return values
  bool ca_cert_initialized = false;
  bool client_cert_initialized = false;
  bool client_key_initialized = false;

  do {
    ret = init_tcp_connection(ssl_client, host, port); // Step 1 - Initiate TCP connection
    if (ret != 0) {
      break;
    } 
    ret = seed_random_number_generator(ssl_client); // Step 2 - Seed the random number generator
    if (ret == MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED || ret != 0) {
      break;
    }
    log_v("Random number generator seeded, ret: %d", ret);
    ret = set_up_tls_defaults(ssl_client); // Step 3 - Set up the SSL/TLS defaults
    if (ret != 0) { // MBEDTLS_ERR_XXX_ALLOC_FAILED undefined?
      break;
    }
    if (alpn_protos != NULL) {
      log_v("Setting ALPN protocols");
      if ((ret = mbedtls_ssl_conf_alpn_protocols(&ssl_client->ssl_conf, alpn_protos) ) != 0) {
        return handle_error(ret);
      }
    }
    log_v("SSL config defaults set, ret: %d", ret);
    ret = auth_root_ca_buff(ssl_client, rootCABuff, &ca_cert_initialized, pskIdent, psKey, insecure); // Step 4 route a - Set up required auth mode rootCaBuff
    if (ret != 0) {
      break;
    }
    log_v("SSL auth mode set, ret: %d", ret);
    ret = auth_client_cert_key(ssl_client, cli_cert, cli_key, &client_cert_initialized, &client_key_initialized); // Step 4 route b - Set up required auth mode cli_cert and cli_key
    if (ret != 0) {
      break;
    }
    log_v("SSL client cert and key set, ret: %d", ret);
    ret = set_hostname_for_tls(ssl_client, host); // Step 5 - Set the hostname for a TLS session
    if (ret != 0) {
      break;
    }
    log_v("SSL hostname set, ret: %d", ret);
    ret = set_io_callbacks_and_timeout(ssl_client, timeout); // Step 6 - Configure IO callbacks and set a read timeout for the SSL client context
    if (ret != 0) {
      break;
    }
    log_v("SSL IO callbacks and timeout set, ret: %d", ret);
    ret = perform_ssl_handshake(ssl_client, cli_cert, cli_key); // Step 7 - Perform SSL/TLS handshake
    if (ret != 0) {
      break;
    }
    int flags = verify_server_cert(ssl_client); // Step 8 - Verify the server certificate
    ret = flags;
    if (ret != 0) {
      log_failed_cert(flags);
    } else {
      log_v("Certificate verified.");
    }
  } while (0); // do once, force break on error

  // Step 9 - Cleanup and return
  cleanup(ssl_client, ca_cert_initialized, client_cert_initialized, client_key_initialized, ret, rootCABuff, cli_cert, cli_key);

  if (ret == 0) {
    return 1; 
  }

  handle_error(ret);
  return 0;
}

/**
 * \brief             Initializes a TCP connection to a remote host on the specified port.
 *
 * \param ssl_client  sslclient__context* - The SSL client context.
 * \param host        const char* - The host to connect to.
 * \param port        uint32_t - The port to connect to.
 *
 * \return int        0 if the TCP connection is successfully established.
 * \return int       -1 if the SSL client's Client pointer is null.
 * \return int       -2 if the connection to the server failed.
 *
 * This function initiates a TCP connection to a remote host on the specified port using the provided
 * SSL client context. It checks if the Client pointer within the context is valid, attempts to
 * establish the TCP connection, and returns appropriate error codes if any issues are encountered.
 */
int init_tcp_connection(sslclient__context *ssl_client, const char *host, uint32_t port) {
  Client *pClient = ssl_client->client;
  if (!pClient) {
    log_e("Client pointer is null.");
    return -1;
  }

  log_v("Client pointer: %p", (void*) pClient);

  if (!pClient->connect(host, port)) {
    log_e(
      "Connection to server failed, is the signal good, server available at this address and timeout sufficient? %s:%d", host, port);
    return -2;
  }

  return 0;
}

/**
 * \brief Seed the random number generator for SSL/TLS operations.
 *
 * \param ssl_client  sslclient__context* - The SSL client context.
 *
 * \return int        0 if the random number generator is successfully seeded.
 * \return int        An error code if the seeding process fails.
 *
 * This function initializes the random number generator used in SSL/TLS operations.
 * It sets up the entropy source and uses it to seed the deterministic random bit generator (DRBG).
 * The DRBG is essential for generating secure cryptographic keys and nonces during SSL/TLS
 * communication. If successful, the function returns 0; otherwise, it returns an error code.
 */
int seed_random_number_generator(sslclient__context *ssl_client) {
  log_v("Seeding the random number generator");
  mbedtls_entropy_init(&ssl_client->entropy_ctx);
  log_v("Entropy context initialized");
  int ret = mbedtls_ctr_drbg_seed(&ssl_client->drbg_ctx, mbedtls_entropy_func,
                                  &ssl_client->entropy_ctx, (const unsigned char *) persy, strlen(persy));
  return ret;
}

/**
 * \brief Set up SSL/TLS configuration with default settings.
 *
 * \param ssl_client  sslclient__context* - The SSL client context.
 *
 * \return int        0 if SSL/TLS configuration is successfully set up with defaults.
 * \return int        An error code if the setup process fails.
 *
 * This function configures SSL/TLS settings with default values, including specifying that
 * it's used as a client, operating in a stream transport mode, and applying the default preset.
 * The SSL/TLS configuration is essential for establishing secure communication over the network.
 * If successful, the function returns 0; otherwise, it returns an error code.
 */
int set_up_tls_defaults(sslclient__context *ssl_client) {
  log_v("Setting up the SSL/TLS defaults...");

  int ret = mbedtls_ssl_config_defaults(&ssl_client->ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  return ret;
}

/**
 * \brief Configure SSL/TLS authentication options based on provided parameters.
 *
 * \param ssl_client       sslclient__context* - The SSL client context.
 * \param rootCABuff       const char* - The root CA certificate buffer.
 * \param ca_cert_initialized bool* - Indicates whether CA certificate is initialized.
 * \param pskIdent         const char* - The PSK identity.
 * \param psKey            const char* - The PSK key.
 * \param func_ret         int* - Pointer to an integer to hold the return value.
 * \param insecure         bool - Flag indicating if the connection is insecure.
 *
 * \return int             0 if the SSL/TLS authentication options are configured successfully.
 * \return int             An error code if the configuration process fails.
 *
 * This function configures SSL/TLS authentication options based on the provided parameters.
 * If `rootCABuff` is not NULL, it loads the root CA certificate and configures SSL/TLS to
 * require verification. If `pskIdent` and `psKey` are not NULL, it sets up a pre-shared key
 * (PSK) for authentication. If none of the options are provided, it configures SSL/TLS with
 * no verification. The function may modify the value pointed to by `func_ret` to indicate errors.
 * If successful, the function returns 0; otherwise, it returns an error code, -1 for a null context.
 */
int auth_root_ca_buff(sslclient__context *ssl_client, const char *rootCABuff, bool *ca_cert_initialized,
                      const char *pskIdent, const char *psKey, bool insecure) {
  if (ssl_client == nullptr) {
    log_e("Uninitialised context!");
    return -1;
  }

  int ret = 0;

  if (insecure) {
    mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
  } else if (rootCABuff != nullptr) {
    log_v("Loading CA cert");
    mbedtls_x509_crt_init(&ssl_client->ca_cert);
    mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    ret = mbedtls_x509_crt_parse(&ssl_client->ca_cert, (const unsigned char *)rootCABuff, strlen(rootCABuff) + 1);

    if (ret < 0) {
      // if ret > 0 n certs failed, ret < 0 pem or x509 error code.
      return ret;
    }

    mbedtls_ssl_conf_ca_chain(&ssl_client->ssl_conf, &ssl_client->ca_cert, NULL);

    if (ca_cert_initialized != nullptr) {
      *ca_cert_initialized = true;
    } else {
      log_e("ca_cert_initialized is null!");
      return -1;
    }
    
  } else if (pskIdent != nullptr && psKey != nullptr) {
    log_v("Setting up PSK");
    
    // convert PSK from hex to binary
    if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2*MBEDTLS_PSK_MAX_LEN) {
      log_e("pre-shared key not valid hex or too long");
      return -1;
    }

    unsigned char psk[MBEDTLS_PSK_MAX_LEN];
    size_t psk_len = strlen(psKey)/2;

    for (int j=0; j<strlen(psKey); j+= 2) {
      char c = psKey[j];
      if (c >= '0' && c <= '9') c -= '0';
      else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
      else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
      else return -1;
      psk[j/2] = c<<4;
      c = psKey[j+1];
      if (c >= '0' && c <= '9') c -= '0';
      else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
      else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
      else return -1;
      psk[j/2] |= c;
    }

    // set mbedtls config
    ret = mbedtls_ssl_conf_psk(&ssl_client->ssl_conf, psk, psk_len,
                              (const unsigned char *)pskIdent, strlen(pskIdent));
    if (ret != 0) { // MBEDTLS_ERR_SSL_XXX undefined?
      log_e("mbedtls_ssl_conf_psk returned %d", ret);
      return ret;
    }
  } else {
    mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    log_w("WARNING: Use certificates for a more secure communication!");
    ret = 0;
  } 
  return ret;
}

/**
 * \brief Authenticate the client by initializing certificates and keys.
 * 
 * This function initializes and loads the client's certificate and private key into
 * the provided SSL client context. It also provides a status of the initialization
 * of the certificate and key.
 *
 * \param[in,out] ssl_client Pointer to the SSL client context.
 * \param[in] cli_cert Pointer to the client certificate in string format.
 * \param[in] cli_key Pointer to the client private key in string format.
 * \param[out] client_cert_initialized Pointer to a boolean indicating if the client certificate was initialized.
 * \param[out] client_key_initialized Pointer to a boolean indicating if the client key was initialized.
 * 
 * \return 0 if successful, or a non-zero error code indicating a failure during the initialization or parsing.
 *         Positive error codes indicate number of certs that failed.
 *         Negative error codes indicate a PEM or x509 error.
 */
int auth_client_cert_key(sslclient__context *ssl_client, const char *cli_cert, const char *cli_key, bool *client_cert_initialized, bool *client_key_initialized) {
  int ret = 0;
  // Step 4 route b - Set up required auth mode cli_cert and cli_key
  if (cli_cert != NULL && cli_key != NULL) {
    mbedtls_x509_crt_init(&ssl_client->client_cert);
    mbedtls_pk_init(&ssl_client->client_key);

    log_v("Loading CRT cert");
    ret = mbedtls_x509_crt_parse(&ssl_client->client_cert, (const unsigned char *)cli_cert, strlen(cli_cert) + 1);
    if (ret != 0) {
      // if ret > 0 n certs failed, ret < 0 pem or x509 error code.
      return ret;
    } else {
      *client_cert_initialized = true;
    }

    log_v("Loading private key");
#if (MBEDTLS_VERSION_MAJOR >= 3) && !defined(MBEDTLS_BACKPORT)
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ctr_drbg_free(&ctr_drbg);
#else
    ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0);
#endif
    if (ret != 0) { // PK or PEM non-zero error codes
      mbedtls_x509_crt_free(&ssl_client->client_cert); // cert+key are free'd in pair
      return ret;
    } else {
      *client_key_initialized = true;
    }

    ret = mbedtls_ssl_conf_own_cert(&ssl_client->ssl_conf, &ssl_client->client_cert, &ssl_client->client_key);
  }
  return ret;
}

/**
 * \brief Set the hostname for a TLS session.
 * 
 * This function sets the hostname for a TLS session which should match
 * the Common Name (CN) in the server certificate to ensure the identity
 * of the remote host. It configures the provided SSL client context 
 * with the hostname and sets up the SSL context with the necessary 
 * configurations.
 * 
 * \param ssl_client A pointer to the sslclient__context structure 
 *        representing the SSL client context.
 * \param host A pointer to a character string representing the hostname.
 * 
 * \return int Returns 0 on success. On failure, it returns 
 *         MBEDTLS_ERR_SSL_ALLOC_FAILED if there's a memory allocation 
 *         failure, MBEDTLS_ERR_SSL_BAD_INPUT_DATA for bad input data,
 *         or other mbedtls error codes as defined in mbedtls error header file.
 * 
 * \note The hostname set should match the CN in the server certificate.
 * 
 * Usage:
 * \code
 *      sslclient__context ssl_client;
 *      const char *host = "example.com";
 *      int ret = set_hostname_for_tls(&ssl_client, host);
 *      if(ret != 0) {
 *          // handle error
 *      }
 * \endcode
 */
int set_hostname_for_tls(sslclient__context *ssl_client, const char *host) {
  int ret;
  log_v("Setting hostname for TLS session...");

  // Hostname set here should match CN in server certificate
  ret = mbedtls_ssl_set_hostname(&ssl_client->ssl_ctx, host);
    
  if (ret == MBEDTLS_ERR_SSL_ALLOC_FAILED || ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA || ret != 0) {
    log_e("Failed to set hostname for tls session");
    return ret;
  }

  mbedtls_ssl_conf_rng(&ssl_client->ssl_conf, mbedtls_ctr_drbg_random, &ssl_client->drbg_ctx);

  ret = mbedtls_ssl_setup(&ssl_client->ssl_ctx, &ssl_client->ssl_conf);

  return ret;
}

/**
 * \brief Configures IO callbacks and sets a read timeout for the SSL client context.
 *
 * This function sets up the IO callbacks for sending, receiving, and receiving with timeout 
 * for the provided SSL client context. It also configures the read timeout for the SSL client context.
 *
 * \param ssl_client A pointer to the sslclient__context structure representing the SSL client context.
 * \param timeout The timeout value in milliseconds for reading operations.
 *
 * \return int Returns 0 on success, -1 
 *
 * Usage:
 * \code
 *      sslclient__context ssl_client;
 *      int timeout = 5000;  // 5 seconds
 *      int ret = set_io_callbacks_and_timeout(&ssl_client, timeout);
 *      if (ret != 0) {
 *          // handle error
 *      }
 * \endcode
 *
 * \note The function assumes that the sslclient__context structure is properly initialized and the 
 *       client_net_send, client_net_recv, and client_net_recv_timeout functions are correctly implemented.
 */
int set_io_callbacks_and_timeout(sslclient__context *ssl_client, int timeout) {
  if (ssl_client == nullptr) {
    log_e("Uninitialised context!");
    return -1;
  }
  
  if (timeout < 0) {
    log_e("Invalid timeout value");
    return -2;
  }

  log_v("Setting up IO callbacks...");
  mbedtls_ssl_set_bio(&ssl_client->ssl_ctx, ssl_client->client, client_net_send, NULL, client_net_recv_timeout);

  log_v("Setting timeout to %i", timeout);
  mbedtls_ssl_conf_read_timeout(&ssl_client->ssl_conf, timeout);

  return 0;
}

/**
 * \brief Performs the SSL/TLS handshake for a given SSL client context.
 *
 * This function initiates and manages the SSL/TLS handshake process. It also checks for 
 * timeout conditions and handles client certificate and key if provided.
 * 
 * \param ssl_client A pointer to the sslclient__context structure representing the SSL client context.
 * \param func_ret A pointer to an integer where a specific error code can be stored for further analysis.
 * \param cli_cert A pointer to a character string representing the client's certificate. If not needed, pass NULL.
 * \param cli_key A pointer to a character string representing the client's private key. If not needed, pass NULL.
 *
 * \return int Returns 0 on successful handshake completion. Returns -1 if the handshake process 
 *         times out. Returns a mbedtls error code if any other error occurs during the handshake process.
 *
 * Usage:
 * \code
 *      sslclient__context ssl_client;
 *      int func_ret = 0;
 *      const char *cli_cert = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
 *      const char *cli_key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----";
 *      int ret = perform_ssl_handshake(&ssl_client, &func_ret, cli_cert, cli_key);
 *      if(ret != 0) {
 *          // handle error
 *      }
 * \endcode
 *
 * \note This function assumes that the sslclient__context structure is properly initialized and the 
 *       mbedtls libraries are correctly configured.
 */
int perform_ssl_handshake(sslclient__context *ssl_client, const char *cli_cert, const char *cli_key) { 
  if (ssl_client == nullptr) {
    log_e("Uninitialised context!");
    return -1;
  }

  int ret = 0;
  bool breakBothLoops = false;
  log_v("Performing the SSL/TLS handshake, timeout %lu ms", ssl_client->handshake_timeout);
  unsigned long handshake_start_time = millis();
  log_d("calling mbedtls_ssl_handshake with ssl_ctx address %p", (void *)&ssl_client->ssl_ctx);

  int loopCount = 0;
  while ((ret = mbedtls_ssl_handshake(&ssl_client->ssl_ctx)) != 0) {
    loopCount++;
  #if defined(_W5500_H_) || defined(W5500_WORKAROUND)
    if (ret == -1 && loopCount < 200) {
        continue; // Treat -1 as a non-error for up to 200 iterations
    }
  #endif
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        break; // Break on any other error
    }

    if ((millis()-handshake_start_time) > ssl_client->handshake_timeout) {
      log_e("SSL handshake timeout");
      breakBothLoops = true;
      break; 
    }

    vTaskDelay(10 / portTICK_PERIOD_MS);
  }

  if (breakBothLoops) {
    return -1;
  }

  if (cli_cert != NULL && cli_key != NULL) {
    log_d("Protocol is %s Ciphersuite is %s", mbedtls_ssl_get_version(&ssl_client->ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_client->ssl_ctx));
    int exp = mbedtls_ssl_get_record_expansion(&ssl_client->ssl_ctx);
    if (exp >= 0) {
      log_d("Record expansion is %d", exp);
    } else {
      log_w("Record expansion is unknown (compression)");
    }
  }
  return ret;
}

/**
 * \brief Verifies the server's certificate using the provided SSL client context.
 *
 * This function performs a verification of the server's certificate to ensure it's valid and trustworthy.
 * The verification process checks the server certificate against the provided root CA. 
 * If client certificate and key are provided, they can be used for further verification or cleanup.
 *
 * \param ssl_client A pointer to the sslclient__context structure representing the SSL client context.
 * \param ret The return value of the mbedtls_ssl_handshake function.
 * \param rootCABuff A pointer to a character string containing the root CA certificate.
 * \param cli_cert A pointer to a character string representing the client's certificate. If not needed, pass NULL.
 * \param cli_key A pointer to a character string representing the client's private key. If not needed, pass NULL.
 *
 * \return int Returns 0 on successful verification. Returns a non-zero error code on failure,
 *         which can be obtained from the mbedtls library.
 *
 * Usage:
 * \code
 *      sslclient__context ssl_client;
 *      const char *rootCABuff = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
 *      const char *cli_cert = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
 *      const char *cli_key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----";
 *      int ret = verify_server_cert(&ssl_client, rootCABuff, cli_cert, cli_key);
 *      if(ret != 0) {
 *          // handle error
 *      }
 * \endcode
 *
 * \note This function assumes that the sslclient__context structure is properly initialized and the 
 *       mbedtls libraries are correctly configured. Also, ensure that the root CA certificate is correct 
 *       and corresponds to the CA that issued the server's certificate.
 */
int verify_server_cert(sslclient__context *ssl_client) {
  if (ssl_client == nullptr) {
    log_e("Uninitialised context!");
    return -1;
  }
  
  log_v("Verifying peer X.509 certificate...");

  int flags = mbedtls_ssl_get_verify_result(&ssl_client->ssl_ctx);

  return flags;
}

/**
 * \brief             Stop the ssl socket.
 * 
 * \param ssl_client  sslclient__context* - The ssl client context. 
 * \param rootCABuff  const char* - The root CA certificate. 
 * \param cli_cert    const char* - The client certificate. 
 * \param cli_key     const char* - The client key. 
 */
void stop_ssl_socket(sslclient__context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key) {
  log_d("Cleaning SSL connection.");
  
  // Stop the client connection
  if (ssl_client && ssl_client->client) {
    log_d("Stopping SSL client. Current client pointer address: %p", (void *)ssl_client->client);
    ssl_client->client->stop();
  }
#if (MBEDTLS_VERSION_MAJOR >= 3) && !defined(MBEDTLS_BACKPORT)
  if (ssl_client->ssl_conf.private_ca_chain != NULL) {
#else
  if (ssl_client->ssl_conf.ca_chain != NULL) {
#endif
    log_d("Freeing CA cert. Current ca_cert address: %p", (void *)&ssl_client->ca_cert);

    // Free the memory associated with the CA certificate
    mbedtls_x509_crt_free(&ssl_client->ca_cert);
  }
#if (MBEDTLS_VERSION_MAJOR >= 3) && !defined(MBEDTLS_BACKPORT)
  if (ssl_client->ssl_conf.private_key_cert != NULL) {
#else
  if (ssl_client->ssl_conf.key_cert != NULL) {
#endif
    log_d("Freeing client cert and client key. Current client_cert address: %p, client_key address: %p", 
          (void *)&ssl_client->client_cert, (void *)&ssl_client->client_key);

    // Free the memory associated with the client certificate and key
    mbedtls_x509_crt_free(&ssl_client->client_cert);
    mbedtls_pk_free(&ssl_client->client_key);
  }

  // Free other SSL-related contexts and log their current addresses
  log_d("Freeing SSL context. Current ssl_ctx address: %p", (void *)&ssl_client->ssl_ctx);
  mbedtls_ssl_free(&ssl_client->ssl_ctx);

  log_d("Freeing SSL config. Current ssl_conf address: %p", (void *)&ssl_client->ssl_conf);
  mbedtls_ssl_config_free(&ssl_client->ssl_conf);

  log_d("Freeing DRBG context. Current drbg_ctx address: %p", (void *)&ssl_client->drbg_ctx);
  mbedtls_ctr_drbg_free(&ssl_client->drbg_ctx);

  log_d("Freeing entropy context. Current entropy_ctx address: %p", (void *)&ssl_client->entropy_ctx);
  mbedtls_entropy_free(&ssl_client->entropy_ctx);

  log_d("Finished cleaning SSL connection.");
}

/**
 * \brief             Check if there is data to read or not.
 * 
 * \param ssl_client  sslclient__context* - The ssl client context. 
 * \return int        The number of bytes to read. 
 */
int data_to_read(sslclient__context *ssl_client) {
  int ret, res;
  
  ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, NULL, 0);
  log_v("RET: %i",ret);
  
  res = mbedtls_ssl_get_bytes_avail(&ssl_client->ssl_ctx);
  log_v("RES: %i",res);
  
  if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
    return handle_error(ret);
  }

  return res;
}

 /**
  * \brief              Send data to the ssl server. 
  * 
  * \param ssl_client   sslclient__context* - The ssl client context. 
  * \param data         const uint8_t* - The data to send. 
  * \param len          size_t - The length of the data. 
  * \return int         The number of bytes sent. 
  */
int send_ssl_data(sslclient__context *ssl_client, const uint8_t *data, size_t len) {
  if(ssl_client != nullptr) {
    log_v("ssl_client->client: %p", (void *)ssl_client->client);
    log_v("ssl_client->handshake_timeout: %lu", ssl_client->handshake_timeout);
  } else {
    log_e("ssl_client is null!");
    return -1;
  }
  
  log_v("Writing SSL (%zu bytes)...", len);

  // Print the data being sent
  // for (size_t i = 0; i < len; i++) {
  //   log_v("Data[%zu]: %02X", i, data[i]);
  // }

  int ret = -1;

  while ((ret = mbedtls_ssl_write(&ssl_client->ssl_ctx, data, len)) <= 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      return handle_error(ret);
    }
  }

  len = ret;
  log_v("%zu bytes written", len);
  return ret;
}

/**
 * \brief                 Get the ssl receive object.
 * 
 * \param ssl_client      sslclient__context* - The ssl client context. 
 * \param data            uint8_t* - The data to receive. 
 * \param length          int - The length of the data. 
 * \return size_t         The number of bytes received. 
 */
int get_ssl_receive(sslclient__context *ssl_client, uint8_t *data, size_t length) {
  log_v( "Reading SSL (%d bytes)", length);
  int ret = -1;

  ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, data, length);

  log_v( "%d bytes read", ret);
  return ret;
}

/**
 * \brief           Get the ssl receive object with timeout.
 * 
 * \param pb        sslclient__context* - The ssl client context. 
 * \param res       uint8_t* - The data to receive. 
 * \return bool     True if the data was received, false otherwise. 
 */
static bool parse_hex_nibble(char pb, uint8_t* res) {
  if (pb >= '0' && pb <= '9') {
    *res = (uint8_t) (pb - '0'); return true;
  } else if (pb >= 'a' && pb <= 'f') {
    *res = (uint8_t) (pb - 'a' + 10); return true;
  } else if (pb >= 'A' && pb <= 'F') {
    *res = (uint8_t) (pb - 'A' + 10); return true;
  }
  return false;
}

/**
 * \brief               Compare a name from certificate and domain name, return true if they match.
 * 
 * \param name          const string& - The name from certificate. 
 * \param domainName    const string& - The domain name. 
 * \return bool         True if the name from certificate and domain name match, false otherwise.  
 */
static bool match_name(const string& name, const string& domainName) {
  size_t wildcardPos = name.find("*");
  if (wildcardPos == (size_t)12) {
    return false; // We don't support wildcards for subdomains
  }
  if (wildcardPos == string::npos) {
    // Not a wildcard, expect an exact match
    return name == domainName;
  }

  size_t firstDotPos = name.find(".");
  if (wildcardPos > firstDotPos) {
    // Wildcard is not part of leftmost component of domain name
    // Do not attempt to match (rfc6125 6.4.3.1)
    return false;
  }

  if (wildcardPos != 0 || firstDotPos != 1) {
    // Matching of wildcards such as baz*.example.com and b*z.example.com
    // is optional. Maybe implement this in the future?
    return false;
  }

  size_t domainNameFirstDotPos = domainName.find('.');
  if (domainNameFirstDotPos == string::npos) {
    return false;
  }
  return domainName.substr(domainNameFirstDotPos) == name.substr(firstDotPos);
}

/**
 * \brief               Verifies certificate provided by the peer to match specified SHA256 fingerprint.
 * 
 * \param ssl_client    sslclient__context* - The ssl client context. 
 * \param fp            const char* - The SHA256 fingerprint. 
 * \param domain_name   const char* - The domain name. 
 * \return bool         True if the certificate matches the fingerprint, false otherwise. 
 */
bool verify_ssl_fingerprint(sslclient__context *ssl_client, const char* fp, const char* domain_name) {
  // Convert hex string to byte array
  uint8_t fingerprint_local[32];
  int len = strlen(fp);
  int pos = 0;
  for (size_t i = 0; i < sizeof(fingerprint_local); ++i) {
    while (pos < len && ((fp[pos] == ' ') || (fp[pos] == ':'))) {
      ++pos;
    }

    if (pos > len - 2) {
      log_d("pos:%d len:%d fingerprint too short", pos, len);
      return false;
    }

    uint8_t high, low;
    if (!parse_hex_nibble(fp[pos], &high) || !parse_hex_nibble(fp[pos+1], &low)) {
      log_d("pos:%d len:%d invalid hex sequence: %c%c", pos, len, fp[pos], fp[pos+1]);
      return false;
    }

    pos += 2;
    fingerprint_local[i] = low | (high << 4);
  }

  // Get certificate provided by the peer
  uint8_t fingerprint_remote[32];
  if (!get_peer_fingerprint(ssl_client, fingerprint_remote)) {
    return false;
  }

  // Check if fingerprints match
  if (memcmp(fingerprint_local, fingerprint_remote, 32)) {
    log_w("fingerprint doesn't match");
    return false;
  }

  // Additionally check if certificate has domain name if provided
  if (domain_name) {
    return verify_ssl_dn(ssl_client, domain_name);
  } else {
    return true;
  }
}

/**
 * \brief Get the peer fingerprint object
 * 
 * \param ssl_client 
 * \param sha256 
 * \return true 
 * \return false 
 */
bool get_peer_fingerprint(sslclient__context *ssl_client, uint8_t sha256[32]) {
  if (!ssl_client) {
    log_d("Invalid ssl_client pointer");
    return false;
  };

  const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);
  if (!crt) {
    log_d("Failed to get peer cert.");
    return false;
  };

  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, false);
  mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
  mbedtls_sha256_finish(&sha256_ctx, sha256);

  return true;
}

/**
 * \brief               Checks if peer certificate has specified domain in CN or SANs.
 * 
 * \param ssl_client    sslclient__context* - The ssl client context.
 * \param domain_name   const char* - The domain name. 
 * \return bool         True if the certificate has the domain name, false otherwise.
 */
bool verify_ssl_dn(sslclient__context *ssl_client, const char* domain_name)
{
  log_d("domain name: '%s'", (domain_name)?domain_name:"(null)");
  string domain_name_str(domain_name);
  transform(domain_name_str.begin(), domain_name_str.end(), domain_name_str.begin(), ::tolower);

  // Get certificate provided by the peer
  const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);

  // Check for domain name in SANs
  const mbedtls_x509_sequence* san = &crt->subject_alt_names;
  while (san != nullptr) {
    string san_str((const char*)san->buf.p, san->buf.len);
    transform(san_str.begin(), san_str.end(), san_str.begin(), ::tolower);

    if (match_name(san_str, domain_name_str)) {
      return true;
    }

    log_d("SAN '%s': no match", san_str.c_str());

    // Fetch next SAN
    san = san->next;
  }

  // Check for domain name in CN
  const mbedtls_asn1_named_data* common_name = &crt->subject;
  while (common_name != nullptr) {
    // While iterating through DN objects, check for CN object
    if (!MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &common_name->oid)) {
      string common_name_str((const char*)common_name->val.p, common_name->val.len);

      if (match_name(common_name_str, domain_name_str)) {
        return true;
      }

      log_d("CN '%s': not match", common_name_str.c_str());
    }

    // Fetch next DN object
    common_name = common_name->next;
  }

  return false;
}
