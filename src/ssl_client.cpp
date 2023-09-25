/* Provide SSL/TLS functions to ESP32 with Arduino IDE
*
* Adapted from the ssl_client example of mbedtls.
*
* Original Copyright (C) 2006-2015, ARM Limited, All Rights Reserved, Apache 2.0 License.
* Additions Copyright (C) 2017 Evandro Luis Copercini, Apache 2.0 License.
* Additions Copyright (C) 2019 Vadim Govorovski.
*/

#include "Arduino.h"
#include <algorithm>
#include <string>
#include "ssl_client.h"

//#define ARDUHAL_LOG_LEVEL 5
//#include <esp32-hal-log.h>

#if !defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
#  error "Please configure IDF framework to include mbedTLS -> Enable pre-shared-key ciphersuites and activate at least one cipher"
#endif

const char *pers = "esp32-tls";

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

  if (result > 0) {
    //esp_log_buffer_hexdump_internal("SSL.RD", buf, (uint16_t)result, ESP_LOG_VERBOSE);
  }
  
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
 * \return int    -1 if Client* is nullptr.
 * \return int    -2 if connect failed.
 */
int client_net_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout) {
  Client *client = (Client*)ctx;

  log_v("Timeout set to %u", timeout);

  if (!client) { 
    log_e("Uninitialised!");
    return -1;
  }

  unsigned long start = millis();
  unsigned long tms = start + timeout;
  
  do {
    int pending = client->available();
    if (pending < len && timeout > 0) {
      delay(1);
    } else break;
  } while (millis() < tms);
  
  int result = client->read(buf, len);
  
  if (!result) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  log_v("SSL client RX (received=%d expected=%zu in %lums)", result, len, millis()-start);

  if (result > 0) {
    //esp_log_buffer_hexdump_internal("SSL.RD", buf, (uint16_t)result, ESP_LOG_VERBOSE);
  }
  
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
  
  log_d("SSL client TX res=%d len=%zu", result, len);
  return result;
}

/**
 * \brief             Initialize the sslclient_context struct.
 * 
 * \param ssl_client  sslclient_context* - The ssl client context. 
 * \param client      Client* - The client. 
 */
void ssl_init(sslclient_context *ssl_client, Client *client) {
  log_v("Init SSL");
  // reset embedded pointers to zero
  memset(ssl_client, 0, sizeof(sslclient_context));
  ssl_client->client = client;
  mbedtls_ssl_init(&ssl_client->ssl_ctx);
  mbedtls_ssl_config_init(&ssl_client->ssl_conf);
  mbedtls_ctr_drbg_init(&ssl_client->drbg_ctx);
}

/**
 * \brief             Start the ssl client.
 * 
 * \param ssl_client  sslclient_context* - The ssl client context.
 * \param host        const char* - The host to connect to.
 * \param port        uint32_t - The port to connect to.
 * \param timeout     int - The timeout in milliseconds.
 * \param rootCABuff  const char* - The root CA certificate.
 * \param cli_cert    const char* - The client certificate.
 * \param cli_key     const char*- The client key.
 * \param pskIdent    const char* - The PSK identity.
 * \param psKey       const char* - The PSK key.
 * \return int        1 if successful.
 * \return int        -1 if Client* is nullptr.
 * \return int        -2 if connect failed.
 * \return int        -3 if PSK key is invalid.
 * \return int        -4 if SSL handshake timeout.
 */
int start_ssl_client(
  sslclient_context *ssl_client,
  const char *host,
  uint32_t port,
  int timeout,
  const char *rootCABuff,
  const char *cli_cert,
  const char *cli_key,
  const char *pskIdent,
  const char *psKey
) {
  log_v("Free internal heap before TLS %u", ESP.getFreeHeap());
  log_v("Connecting to %s:%d", host, port);

  int ret = 0; // for mbedtls function return values
  int func_ret = 0; // for start_ssl_client return values
  bool ca_cert_initialized = false;
  bool client_cert_initialized = false;
  bool client_key_initialized = false;
  bool breakBothLoops = false;

  do { // executes once, breaks on error...

    // Step 1 - Initiate TCP connection
    Client *pClient = ssl_client->client;
    if (!pClient) {
      log_e("Client pointer is null.");
      func_ret = -1;
      break;
    }

    log_v("Client pointer: %p", (void*) pClient); // log_v

    if (!pClient->connect(host, port)) {
      log_e("Connection to server failed!");
      func_ret = -2;
      break;
    }

    // Step 2 - Seed the random number generator
    log_v("Seeding the random number generator");
    mbedtls_entropy_init(&ssl_client->entropy_ctx);
    log_v("Entropy context initialized"); // log_v

    ret = mbedtls_ctr_drbg_seed(&ssl_client->drbg_ctx, mbedtls_entropy_func,
                                &ssl_client->entropy_ctx, (const unsigned char *) pers, strlen(pers));

    if (ret == MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED || ret != 0) {
      break;
    }

    log_v("Random number generator seeded, ret: %d", ret); // log_v

    // Step 3 - Set up the SSL/TLS defaults
    log_v("Setting up the SSL/TLS defaults...");

    ret = mbedtls_ssl_config_defaults(&ssl_client->ssl_conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) { // MBEDTLS_ERR_XXX_ALLOC_FAILED undefined?
      break;
    }

    log_v("SSL config defaults set, ret: %d", ret);

    // Step 4 route a - Set up required auth mode rootCaBuff
    if (rootCABuff != NULL) {
      log_v("Loading CA cert");
      mbedtls_x509_crt_init(&ssl_client->ca_cert);
      mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
      ret = mbedtls_x509_crt_parse(&ssl_client->ca_cert, (const unsigned char *)rootCABuff, strlen(rootCABuff) + 1);

      if (ret < 0) {
        break; // if ret > 0 n certs failed, ret < 0 pem or x509 error code.
      }

      mbedtls_ssl_conf_ca_chain(&ssl_client->ssl_conf, &ssl_client->ca_cert, NULL);
      // mbedtls_ssl_conf_verify(&ssl_client->ssl_ctx, my_verify, NULL );

      ca_cert_initialized = true;
      
    } else if (pskIdent != NULL && psKey != NULL) {
      log_v("Setting up PSK");
      
      // convert PSK from hex to binary
      if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2*MBEDTLS_PSK_MAX_LEN) {
        log_e("pre-shared key not valid hex or too long");
        func_ret = -3;
        break;
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
        break;
      }
    } else {
      mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
      log_i("WARNING: Use certificates for a more secure communication!");
    }

    // Step 4 route b - Set up required auth mode cli_cert and cli_key
    if (cli_cert != NULL && cli_key != NULL) {
      mbedtls_x509_crt_init(&ssl_client->client_cert);
      mbedtls_pk_init(&ssl_client->client_key);

      log_v("Loading CRT cert");
      ret = mbedtls_x509_crt_parse(&ssl_client->client_cert, (const unsigned char *)cli_cert, strlen(cli_cert) + 1);
      if (ret != 0) {
        break; // if ret > 0 n certs failed, ret < 0 pem or x509 error code.
      } else {
        client_cert_initialized = true;
      }

      log_v("Loading private key");
      ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0);
      if (ret != 0) { // PK or PEM non-zero error codes
        mbedtls_x509_crt_free(&ssl_client->client_cert); // cert+key are free'd in pair
        break;
      } else {
        client_key_initialized = true;
      }

      ret = mbedtls_ssl_conf_own_cert(&ssl_client->ssl_conf, &ssl_client->client_cert, &ssl_client->client_key);
      if (ret == MBEDTLS_ERR_SSL_ALLOC_FAILED || ret != 0) {
        break;
      }
    }

    // Step 5 - Set hostname for TLS session
    log_v("Setting hostname for TLS session...");

    // Hostname set here should match CN in server certificate
    ret = mbedtls_ssl_set_hostname(&ssl_client->ssl_ctx, host);
     
    if (ret == MBEDTLS_ERR_SSL_ALLOC_FAILED || ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA || ret != 0) {
      break;
    }

    mbedtls_ssl_conf_rng(&ssl_client->ssl_conf, mbedtls_ctr_drbg_random, &ssl_client->drbg_ctx);

    ret = mbedtls_ssl_setup(&ssl_client->ssl_ctx, &ssl_client->ssl_conf);

    if (ret == MBEDTLS_ERR_SSL_ALLOC_FAILED || ret != 0) {
      break;
    }

    // Step 6 - Set up the I/O callbacks (this is the heart of it)
    log_v("Setting up IO callbacks...");
    mbedtls_ssl_set_bio(&ssl_client->ssl_ctx, ssl_client->client,
                        client_net_send, NULL, client_net_recv_timeout );
  
    log_v("Setting timeout to %i", timeout);
    mbedtls_ssl_conf_read_timeout(&ssl_client->ssl_conf,  timeout);

    // Step 7 - Perform the SSL/TLS handshake
    log_v("Performing the SSL/TLS handshake...");
    unsigned long handshake_start_time = millis();

    while ((ret = mbedtls_ssl_handshake(&ssl_client->ssl_ctx)) != 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        break;
      }
      if ((millis()-handshake_start_time) > ssl_client->handshake_timeout) {
        log_e("SSL handshake timeout");
        func_ret = -4;
        breakBothLoops = true;
        break; 
      }
      vTaskDelay(10 / portTICK_PERIOD_MS);
    }

    if (breakBothLoops) {
      break;  // break the outer do-while loop
    }

    if (cli_cert != NULL && cli_key != NULL) {
      log_v("Protocol is %s Ciphersuite is %s", mbedtls_ssl_get_version(&ssl_client->ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_client->ssl_ctx));
      ret = mbedtls_ssl_get_record_expansion(&ssl_client->ssl_ctx);
      if (ret != 0) {
        if (ret == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE) {
          log_w("Record expansion is not available (compression)");
        } else {
          log_e(" mbedtls_ssl_get_record_expansion returned -0x%x", -ret);
        }
        break;
      } else {
        log_w("Record expansion is unknown (compression)");
      }
    }

    // Step 8 - Verify the server certificate
    log_v("Verifying peer X.509 certificate...");

    int flags = mbedtls_ssl_get_verify_result(&ssl_client->ssl_ctx);

    if (ret != 0) {
      char buf[512];
      memset(buf, 0, sizeof(buf));
      mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
      log_e("Failed to verify peer certificate! verification info: %s", buf);
      stop_ssl_socket(ssl_client, rootCABuff, cli_cert, cli_key);  // It's not safe continue.
      break;
    } else {
      log_v("Certificate verified.");
    }

  } while (0); // executes once, breaks on error...

  // Step 9 - Cleanup and return
  if (ca_cert_initialized) {
    mbedtls_x509_crt_free(&ssl_client->ca_cert);
  }

  if (client_cert_initialized) {
    mbedtls_x509_crt_free(&ssl_client->client_cert);
  }

  if (client_key_initialized) {
    mbedtls_pk_free(&ssl_client->client_key);
  }

  log_v("Free internal heap after TLS %u", ESP.getFreeHeap());

  if (ret < 0) {
    return handle_error(ret);
    stop_ssl_socket(ssl_client, rootCABuff, cli_cert, cli_key);
  } else {
    func_ret = 1;
  }

  return func_ret;
}

/**
 * \brief             Stop the ssl socket.
 * 
 * \param ssl_client  sslclient_context* - The ssl client context. 
 * \param rootCABuff  const char* - The root CA certificate. 
 * \param cli_cert    const char* - The client certificate. 
 * \param cli_key     const char* - The client key. 
 */
void stop_ssl_socket(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key) {
  log_v("Cleaning SSL connection.");
  log_v("Stopping SSL client. Current client pointer address: %p", (void *)ssl_client->client);
  
  // Stop the client connection
  ssl_client->client->stop();

  if (ssl_client->ssl_conf.ca_chain != NULL) {
    log_v("Freeing CA cert. Current ca_cert address: %p", (void *)&ssl_client->ca_cert);

    // Free the memory associated with the CA certificate
    mbedtls_x509_crt_free(&ssl_client->ca_cert);
  }

  if (ssl_client->ssl_conf.key_cert != NULL) {
    log_v("Freeing client cert and client key. Current client_cert address: %p, client_key address: %p", 
          (void *)&ssl_client->client_cert, (void *)&ssl_client->client_key);

    // Free the memory associated with the client certificate and key
    mbedtls_x509_crt_free(&ssl_client->client_cert);
    mbedtls_pk_free(&ssl_client->client_key);
  }

  // Free other SSL-related contexts and log their current addresses
  log_v("Freeing SSL context. Current ssl_ctx address: %p", (void *)&ssl_client->ssl_ctx);
  mbedtls_ssl_free(&ssl_client->ssl_ctx);

  log_v("Freeing SSL config. Current ssl_conf address: %p", (void *)&ssl_client->ssl_conf);
  mbedtls_ssl_config_free(&ssl_client->ssl_conf);

  log_v("Freeing DRBG context. Current drbg_ctx address: %p", (void *)&ssl_client->drbg_ctx);
  mbedtls_ctr_drbg_free(&ssl_client->drbg_ctx);

  log_v("Freeing entropy context. Current entropy_ctx address: %p", (void *)&ssl_client->entropy_ctx);
  mbedtls_entropy_free(&ssl_client->entropy_ctx);

  // log_v("Resetting embedded pointers to zero for ssl_client at address: %p", (void *)ssl_client);
  // memset(ssl_client, 0, sizeof(sslclient_context));
}


/**
 * \brief             Check if there is data to read or not.
 * 
 * \param ssl_client  sslclient_context* - The ssl client context. 
 * \return int        The number of bytes to read. 
 */
int data_to_read(sslclient_context *ssl_client) {
  int ret, res;
  ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, NULL, 0);
  //log_e("RET: %i",ret);   //for low level debug
  res = mbedtls_ssl_get_bytes_avail(&ssl_client->ssl_ctx);
  //log_e("RES: %i",res);    //for low level debug
  if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
    return handle_error(ret);
  }

  return res;
}

 /**
  * \brief              Send data to the ssl server. 
  * 
  * \param ssl_client   sslclient_context* - The ssl client context. 
  * \param data         const uint8_t* - The data to send. 
  * \param len          size_t - The length of the data. 
  * \return int         The number of bytes sent. 
  */
int send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len) {
    // Log contents of ssl_client
  if(ssl_client != nullptr) {
    log_v("ssl_client->client: %p", (void *)ssl_client->client);
    log_v("ssl_client->handshake_timeout: %lu", ssl_client->handshake_timeout);
  } else {
    log_e("ssl_client is null!");
    return -1;
  }
  
  log_v("Writing SSL (%zu bytes)...", len); // for low level debug
  int ret = -1;

  while ((ret = mbedtls_ssl_write(&ssl_client->ssl_ctx, data, len)) <= 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      return handle_error(ret);
    }
  }

  len = ret;
  log_v("%zu bytes written", len); // for low level debug
  return ret;
}

/**
 * \brief                 Get the ssl receive object.
 * 
 * \param ssl_client      sslclient_context* - The ssl client context. 
 * \param data            uint8_t* - The data to receive. 
 * \param length          int - The length of the data. 
 * \return size_t            The number of bytes received. 
 */
int get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, size_t length) {
  log_v( "Reading SSL (%d bytes)", length);   //for low level debug
  int ret = -1;

  ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, data, length);

  log_v( "%d bytes read", ret);   //for low level debug
  return ret;
}

/**
 * \brief           Get the ssl receive object with timeout.
 * 
 * \param pb        sslclient_context* - The ssl client context. 
 * \param res       uint8_t* - The data to receive. 
 * \return bool     True if the data was received, false otherwise. 
 */
static bool parseHexNibble(char pb, uint8_t* res) {
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
static bool matchName(const string& name, const string& domainName) {
  size_t wildcardPos = name.find('*');
  if (wildcardPos == string::npos) {
    // Not a wildcard, expect an exact match
    return name == domainName;
  }

  size_t firstDotPos = name.find('.');
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
 * \param ssl_client    sslclient_context* - The ssl client context. 
 * \param fp            const char* - The SHA256 fingerprint. 
 * \param domain_name   const char* - The domain name. 
 * \return bool         True if the certificate matches the fingerprint, false otherwise. 
 */
bool verify_ssl_fingerprint(sslclient_context *ssl_client, const char* fp, const char* domain_name)
{
  // Convert hex string to byte array
  uint8_t fingerprint_local[32];
  int len = strlen(fp);
  int pos = 0;
  for (size_t i = 0; i < sizeof(fingerprint_local); ++i) {
    while (pos < len && ((fp[pos] == ' ') || (fp[pos] == ':'))) {
      ++pos;
    }
    if (pos > len - 2) {
      log_v("pos:%d len:%d fingerprint too short", pos, len);
      return false;
    }
    uint8_t high, low;
    if (!parseHexNibble(fp[pos], &high) || !parseHexNibble(fp[pos+1], &low)) {
      log_v("pos:%d len:%d invalid hex sequence: %c%c", pos, len, fp[pos], fp[pos+1]);
      return false;
    }
    pos += 2;
    fingerprint_local[i] = low | (high << 4);
  }

  // Get certificate provided by the peer
  const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);

  if (!crt) {
    log_v("could not fetch peer certificate");
    return false;
  }

  // Calculate certificate's SHA256 fingerprint
  uint8_t fingerprint_remote[32];
  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, false);
  mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
  mbedtls_sha256_finish(&sha256_ctx, fingerprint_remote);

  // Check if fingerprints match
  if (memcmp(fingerprint_local, fingerprint_remote, 32)) {
    log_d("fingerprint doesn't match");
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
 * \brief               Checks if peer certificate has specified domain in CN or SANs.
 * 
 * \param ssl_client    sslclient_context* - The ssl client context.
 * \param domain_name   const char* - The domain name. 
 * \return bool         True if the certificate has the domain name, false otherwise.
 */
bool verify_ssl_dn(sslclient_context *ssl_client, const char* domain_name)
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

    if (matchName(san_str, domain_name_str)) {
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

      if (matchName(common_name_str, domain_name_str)) {
        return true;
      }

      log_d("CN '%s': not match", common_name_str.c_str());
    }

    // Fetch next DN object
    common_name = common_name->next;
  }

  return false;
}
