/*
  SSLClient.cpp - Base class that provides Client SSL to ESP32
  Additions (c) 2011 Adrian McEwen.  All right reserved.
  Additions Copyright (C) 2017 Evandro Luis Copercini.
  Additions Copyright (C) 2019 Vadim Govorovski.
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "SSLClient.h"
#include "certBundle.h"
// #include <errno.h>

#undef connect
#undef write
#undef read

/**
 * @brief Default constructor for the SSLClient class.
 *
 * Initializes an SSLClient object with default settings without associating it
 * to any specific client instance.
 */
SSLClient::SSLClient() {
  _connected = false;
  sslclient = new sslclient__context;
  ssl_init(sslclient, nullptr);
  sslclient->handshake_timeout = 120000;
  _use_insecure = false;
  _CA_cert = NULL;
  _cert = NULL;
  _private_key = NULL;
  _pskIdent = NULL;
  _psKey = NULL;
  _alpn_protos = NULL;
  _use_ca_bundle = false;
}

/**
 * @brief Constructor for the SSLClient class.
 *
 * Initializes an SSLClient object with default settings, binding it to the 
 * provided client instance.
 *
 * @param client Pointer to the client instance the SSLClient should be 
 *               associated with.
 */
SSLClient::SSLClient(Client* client) {
  _connected = false;
  sslclient = new sslclient__context;
  _use_insecure = false;
  ssl_init(sslclient, client);
  sslclient->handshake_timeout = 120000;
  _CA_cert = NULL;
  _cert = NULL;
  _private_key = NULL;
  _pskIdent = NULL;
  _psKey = NULL;
  _alpn_protos = NULL;
  _use_ca_bundle = false;
}

/**
 * @brief Destructor for the SSLClient class.
 *
 * Safely terminates any ongoing SSL connection, releases associated resources,
 * and deallocates the memory used by the SSL client.
 */
SSLClient::~SSLClient() {
  stop();
  delete sslclient;
  sslclient = nullptr;
}

/**
 * @brief Terminates the current SSL connection and releases associated resources.
 *
 * This function stops the SSL socket and logs relevant information based on the state of 
 * the client connection. After the SSL connection is terminated, it resets the 
 * connected flag and peek value of the SSL client.
 *
 * @note If the client connection is `nullptr` or its value is less than 0, 
 *       the SSL socket will not be stopped and a log message will be generated.
 */
void SSLClient::stop() {
  if (sslclient->client != nullptr) {
    if (sslclient->client >= (void*)0) {
      log_d("Stopping ssl client");
      stop_ssl_socket(sslclient, _CA_cert, _cert, _private_key);
    } else {
      log_d("stop() not called because client is < 0");
    }
  } else {
    log_d("stop() not called because client is nullptr");
  }
  _connected = false;
  _peek = -1;
}

/**
 * @brief Establishes an SSL connection to the specified IP address and port.
 *
 * Based on the class members `_pskIdent` and `_psKey`, this function will decide 
 * whether to establish a connection using a pre-shared key or using a certificate authority.
 * If `_pskIdent` and `_psKey` are set, it uses them to establish a connection.
 * Otherwise, it uses `_CA_cert`, `_cert`, and `_private_key` for the connection.
 *
 * @param ip The IP address of the server to connect to.
 * @param port The port number on the server to connect to.
 * 
 * @return Returns 1 if the connection is established successfully, and 0 otherwise.
 */
int SSLClient::connect(IPAddress ip, uint16_t port) {
  if (_pskIdent && _psKey) {
    log_v("connect with PSK");
    return connect(ip, port, _pskIdent, _psKey);
  }

  log_v("connect with CA");
  return connect(ip, port, _CA_cert, _cert, _private_key);
}

/**
 * @brief Establishes an SSL connection to the specified IP address and port with a given timeout.
 *
 * This function sets the connection timeout and then delegates the connection 
 * process to the `connect` method that takes `IPAddress` and `port` as its parameters.
 *
 * @param ip The IP address of the server to connect to.
 * @param port The port number on the server to connect to.
 * @param timeout The timeout duration for the connection, in milliseconds.
 * 
 * @return Returns 1 if the connection is established successfully, and 0 otherwise.
 */
int SSLClient::connect(IPAddress ip, uint16_t port, int32_t timeout) {
  _timeout = timeout;
  return connect(ip, port);
}

/**
 * @brief Establishes an SSL connection to the specified host and port.
 *
 * This function determines the type of SSL connection (either with a Pre-Shared Key (PSK) 
 * or with Certificates (CA)) based on the availability of the PSK identifier and key. 
 * Depending on which credentials are set, it delegates to the appropriate `connect` variant.
 *
 * @param host Pointer to a null-terminated string representing the hostname or IP address 
 *             of the server to connect to.
 * @param port The port number on the server to connect to.
 * 
 * @return Returns 1 if the connection is established successfully, and 0 otherwise.
 */
int SSLClient::connect(const char *host, uint16_t port) {
  if (_pskIdent && _psKey) {
    log_v("connect with PSK");
    return connect(host, port, _pskIdent, _psKey);
  }

  log_v("connect with CA");
  return connect(host, port, _CA_cert, _cert, _private_key);
}

/**
 * @brief Establishes an SSL connection to the specified host and port with a given timeout.
 *
 * This function acts as an overloaded variant of the `connect` function, allowing the caller
 * to specify a connection timeout value. It then delegates the actual connection process 
 * to the other variant of the `connect` function.
 *
 * @param host    Pointer to a null-terminated string representing the hostname or IP address of the server to connect to.
 * @param port    The port number on the server to connect to.
 * @param timeout The timeout value (in milliseconds) for the SSL connection. If the connection is not established
 *                within this time, the attempt will fail.
 * 
 * @return Returns 1 if the connection is established successfully, and 0 otherwise.
 */
int SSLClient::connect(const char *host, uint16_t port, int32_t timeout) {
  _timeout = timeout;
  return connect(host, port);
}

/**
 * @brief Establishes an SSL connection to the specified IP address and port using a certificate and private key for authentication.
 *
 * This function acts as an overloaded variant of the `connect` function, accepting an `IPAddress` object instead of 
 * a host string. It then delegates the actual connection process to the other variant of the `connect` function.
 *
 * @param ip            The IP address of the server to connect to, given as an `IPAddress` object.
 * @param port          The port number on the server to connect to.
 * @param _CA_cert      Pointer to a null-terminated string containing the root Certificate Authority (CA) certificate.
 * @param _cert         Pointer to a null-terminated string containing the client's certificate.
 * @param _private_key  Pointer to a null-terminated string containing the client's private key.
 * 
 * @return Returns 1 if the connection is established successfully, and 0 otherwise.
 */
int SSLClient::connect(IPAddress ip, uint16_t port, const char *_CA_cert, const char *_cert, const char *_private_key) {
  return connect(ip.toString().c_str(), port, _CA_cert, _cert, _private_key);
}

/**
 * @brief Establishes an SSL connection to a given server.
 * 
 * This function initializes an SSL connection to a server specified by its host and port.
 * It also accepts optional parameters for CA certificate, client certificate, and client private key for SSL authentication.
 * The function will log important debugging information like timeout values and whether certificates are provided.
 * 
 * @param host          The hostname or IP address of the server.
 * @param port          The port number on the server to connect to.
 * @param _CA_cert      Pointer to the CA certificate for server verification. NULL if not provided.
 * @param _cert         Pointer to the client certificate for client authentication. NULL if not provided.
 * @param _private_key  Pointer to the private key corresponding to the client certificate. NULL if not provided.
 * 
 * @return 1 if the SSL connection is successfully established, 0 otherwise.
 */
int SSLClient::connect(const char *host, uint16_t port, const char *_CA_cert, const char *_cert, const char *_private_key)
{
  log_v("Connecting to %s:%d", host, port);
  log_v("Timeout value: %d", _timeout);
  log_v("CA Certificate: %s", _CA_cert ? "Provided" : "Not Provided");
  log_v("Client Certificate: %s", _cert ? "Provided" : "Not Provided");
  log_v("Private Key: %s", _private_key ? "Provided" : "Not Provided");

  if(_timeout > 0){
    sslclient->handshake_timeout = _timeout;
    log_v("Handshake timeout set to: %d", sslclient->handshake_timeout);
  }

  int ret = start_ssl_client(sslclient, host, port, _timeout, _CA_cert, _use_ca_bundle, _cert, _private_key, NULL, NULL, _use_insecure, _alpn_protos);
  _lastError = ret;
  log_v("Return value from start_ssl_client: %d", ret);

  if (ret != 1) {
    log_e("start_ssl_client failed: %d", ret);
    stop();
    _connected = false;
    return 0;
  }

  log_i("SSL connection established");
  _connected = true;
  return 1;
}

/**
 * @brief Establishes an SSL connection to the specified IP address and port using a pre-shared key (PSK) for authentication.
 *
 * This function acts as an overloaded variant of the `connect` function, accepting an `IPAddress` object instead of 
 * a host string. It then delegates the actual connection process to the other variant of the `connect` function.
 *
 * @param ip       The IP address of the server to connect to, given as an `IPAddress` object.
 * @param port     The port number on the server to connect to.
 * @param pskIdent Pointer to a null-terminated string containing the pre-shared key identity.
 * @param psKey    Pointer to a null-terminated string containing the pre-shared key.
 * 
 * @return Returns 1 if the connection is established successfully, and 0 otherwise.
 */
int SSLClient::connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey) {
  return connect(ip.toString().c_str(), port,_pskIdent, _psKey);
}

/**
 * @brief Establishes an SSL connection to the specified host and port using a pre-shared key (PSK) for authentication.
 *
 * This function attempts to start an SSL client connection to a server using the provided 
 * host, port, and pre-shared key details for authentication. If a timeout has been set using 
 * `_timeout`, it will be used for the handshake timeout.
 *
 * @param host     Pointer to a null-terminated string containing the host (domain name or IP) to connect to.
 * @param port     The port number on the host to connect to.
 * @param pskIdent Pointer to a null-terminated string containing the pre-shared key identity.
 * @param psKey    Pointer to a null-terminated string containing the pre-shared key.
 * 
 * @return Returns 1 if the connection is established successfully, and 0 otherwise.
 */
int SSLClient::connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey) {
  log_v("start_ssl_client with PSK");

  if (_timeout > 0) {
    sslclient->handshake_timeout = _timeout;
  }

  int ret = start_ssl_client(sslclient, host, port, _timeout, NULL, false, NULL, NULL, _pskIdent, _psKey, _use_insecure, _alpn_protos);
  _lastError = ret;

  if (ret < 0) {
    log_e("start_ssl_client: %d", ret);
    stop();
    return 0;
  }

  _connected = true;
  return 1;
}

/**
 * @brief Returns the next byte from the SSL connection without consuming it.
 *
 * This function allows the caller to inspect the next byte of data 
 * that would be returned from the `read` function without actually 
 * consuming or removing that byte from the input stream. If a peeked 
 * byte is already available, it returns that byte. Otherwise, it 
 * attempts a timed read and stores the result for future `peek` or 
 * `read` calls.
 *
 * @return The next byte from the SSL connection if available, or -1 if 
 *         no data is available or there's an error.
 */
int SSLClient::peek() {
  if(_peek >= 0){
    return _peek;
  }

  _peek = timedRead();
  return _peek;
}

/**
 * @brief Reads a single byte of data from the SSL connection.
 *
 * This function attempts to read one byte of data from the SSL connection. 
 * If there's an error during the read operation, the function will return 
 * the error code. Otherwise, it returns the read byte.
 *
 * @return The read byte of data from the SSL connection or an error code 
 *         (negative value) if there's a reading error.
 */
int SSLClient::read() {
  uint8_t data = -1;
  int res = read(&data, 1);

  if (res < 0) {
    return res;
  }

  return data;
}

/**
 * @brief Writes a single byte of data to the SSL connection.
 *
 * This function sends a single byte of data to the SSL connection 
 * by internally calling the write function that handles buffer writes.
 *
 * @param data The byte of data to be written to the SSL connection.
 * @return Number of bytes successfully written to the SSL connection. 
 *         Typically, this will be 1 if the operation was successful, or 
 *         0 if there was an error or the connection is closed.
 */
size_t SSLClient::write(uint8_t data) {
  return write(&data, 1);
}

/**
 * @brief Writes the specified data to the SSL connection.
 *
 * This function sends the data in the provided buffer to the established 
 * SSL connection. If the client is not currently connected, the function 
 * will return without sending any data.
 *
 * @param buf Pointer to the data buffer containing the data to be sent.
 * @param size Size of the data (in bytes) to be sent.
 * @return The number of bytes that were successfully sent or `0` if the 
 * data couldn't be sent or the client was not connected.
 */
size_t SSLClient::write(const uint8_t *buf, size_t size) {
  if (!_connected) {
    log_w("SSLClient is not connected.");
    return 0;
  }

  log_d("Sending data to SSL connection...");
  int res = send_ssl_data(sslclient, buf, size);
  
  if (res < 0) {
    log_e("Error sending data to SSL connection. Stopping SSLClient...");
    stop();
    res = 0;
  }
  
  return res;
}

/**
 * @brief Reads data from the sslclient.
 * 
 * If there is a byte peeked, it returns that byte.
 * 
 * @param buf Buffer to read into. 
 * @param size Size of the buffer.
 * @return int  1 if a byte has been peeked and the client is not connected.
 * @return int  < 1 if client is connected and there is an error from get_ssl_receive().
 * @return int  > 1 if res + peeked. 
 */
int SSLClient::read(uint8_t *buf, size_t size) {
  log_v("This is the iClient->read() implementation");
  int peeked = 0;
  int avail = available();

  if ((!buf && size) || avail <= 0) {
    return -1; // return error if no buffer or nothing to read.
  }

  if (!size) {
    return 0; // return 0 if no bytes requested.
  }

  if (_peek >= 0) {
    buf[0] = _peek; // Places this peeked byte at the start of the buffer.
    _peek = -1; // Resets _peek to -1 to indicate no bytes are currently peeked.
    size--; // Decreases the available size (size) by 1.
    avail--; // Decreases the available bytes (avail) by 1.
    if (!size || !avail) { // If there's no space left in the buffer (size) or no data left to read (avail)
      return 1;  // Return 1 to indicate one byte has been read.
    }
    buf++; // Increment the buffer pointer.
    peeked = 1; // set peeked to 1 to indicate one byte has been read from the peeked value.
  }

  size_t res = get_ssl_receive(sslclient, buf, size);

  if (res < 0) {
    stop();
    return peeked?peeked:res; // If peeked is true return peeked, otherwise return res, i.e. data_to_read error.
  }

  return res + peeked; // Return the number of bytes read + the number of bytes peeked.
}

/**
 * @brief Returns how many bytes of data are available to be read from the sslclient.
 *                      
 * It takes into account both directly readable bytes and a potentially "peeked" byte.                     
 * If there's an error or the client is not connected, it handles these scenarios appropriately.
 * 
 * @return int  1 if a byte has been peeked and the client is not connected.
 * @return int  < 1 if client is connected and there is an error from data_to_read().
 * @return int  > 1 if res + peeked.
 */
int SSLClient::available() {
  int peeked = (_peek >= 0); // 1 if a byte has been peeked (available to read without advancing the read pointer)

  if (!_connected) {
    return peeked;
  }
  
  int res = data_to_read(sslclient); // how many bytes available to read.
  
  if (res < 0) {
    stop();
    return peeked?peeked:res; // If peeked is true return peeked, otherwise return res, i.e. data_to_read error.
  }

  return res+peeked;
}

/**
 * @brief Checks if the SSLClient is currently connected to a server.
 *
 * This function reads zero bytes from the connection to refresh the 
 * internal connection state. It then returns the current connection status.
 *
 * @return A byte indicating the connection status: `1` if connected, `0` otherwise.
 */
uint8_t SSLClient::connected() {
  uint8_t dummy = 0;
  read(&dummy, 0);

  return _connected;
}

/**
 * @brief Sets the client to use an insecure connection.
 * 
 * This function sets the client to use an insecure connection, which means that the client
 * will not verify the server's certificate during the SSL/TLS handshake. This is useful for
 * testing or development purposes, but it is not recommended for production use.
 * 
 * @return void
 */
void SSLClient::setInsecure() {
  _CA_cert = NULL;
  _cert = NULL;
  _private_key = NULL;
  _pskIdent = NULL;
  _psKey = NULL;
  _use_insecure = true;   
}

/**
 * @brief Sets the root Certificate Authority (CA) for the SSL/TLS client.
 *
 * This function is used to specify the root CA certificate for the SSL/TLS client.
 * The root CA certificate is crucial for verifying the server's identity during the 
 * SSL/TLS handshake. If the server's certificate is not signed by this root CA or
 * is not traceable back to this root CA, the verification will fail.
 *
 * @param rootCA The root CA certificate in its binary or PEM form.
 */
void SSLClient::setCACert(const char *rootCA) {
  log_d("Set root CA");
  _CA_cert = rootCA;
  _use_insecure = false;
}

/**
 * @brief Sets the root Certificate Authority (CA) for the SSL/TLS client.
 * 
 * This function is used to specify the root CA certificate for the SSL/TLS client.
 * The root CA certificate is crucial for verifying the server's identity during the
 * SSL/TLS handshake. If the server's certificate is not signed by this root CA or
 * is not traceable back to this root CA, the verification will fail.
 * 
 * @param bundle The root CA certificate in its binary or PEM form.
 */
void SSLClient::setCACertBundle(const uint8_t * bundle) {
  if (bundle != NULL) {
    ssl_lib_crt_bundle_set(bundle);
    _use_ca_bundle = true;
  } else {
    ssl_lib_crt_bundle_detach(NULL);
    _use_ca_bundle = false;
  }
}

/**
 * @brief Sets the client certificate for the SSL/TLS client.
 *
 * This function is used to provide the client certificate that the SSL/TLS client 
 * will use during the SSL/TLS handshake. When the server requests a client 
 * certificate for authentication, the client provides this certificate.
 *
 * @param client_ca The client certificate in its binary or PEM form.
 */
void SSLClient::setCertificate(const char *client_ca) {
  log_d("Set client CA");
  _cert = client_ca;
}

/**
 * @brief Sets the private key for the SSL/TLS client.
 *
 * This function is used to provide the private key that the SSL/TLS client will 
 * use for mutual authentication during the SSL/TLS handshake. In setups requiring
 * client authentication, the server will challenge the client to prove its identity 
 * by using this private key.
 *
 * @param private_key The private key in its binary or PEM form.
 */
void SSLClient::setPrivateKey(const char *private_key) {
  log_d("Set client PK");
  _private_key = private_key;
}

/**
 * @brief Sets the Pre-Shared Key (PSK) and identifier for SSL/TLS sessions.
 *
 * This function configures the Pre-Shared Key and its associated identifier to be
 * used in the SSL/TLS handshake. PSK is an authentication method where both sides
 * of the connection (client and server) have a shared secret key, eliminating the 
 * need for digital certificates.
 *
 * @param pskIdent The PSK identifier (usually a string that identifies which key to use).
 * @param psKey    The Pre-Shared Key in its binary form.
 */
void SSLClient::setPreSharedKey(const char *pskIdent, const char *psKey) {
  log_d("Set PSK");
  _pskIdent = pskIdent;
  _psKey = psKey;
}

/**
 * @brief Verifies the SSL/TLS certificate against a specified fingerprint and domain name.
 *
 * This function checks the certificate presented by the remote server against a given 
 * fingerprint and domain name. It ensures that the communication is genuine and not
 * susceptible to a man-in-the-middle attack.
 *
 * @param fp          The expected fingerprint of the remote server's certificate.
 * @param domain_name The expected domain name or Common Name (CN) of the remote server.
 *
 * @return Returns `true` if the fingerprint and domain name of the remote server's certificate
 * match the provided values, otherwise `false`.
 */
bool SSLClient::verify(const char* fp, const char* domain_name) {
  if (!sslclient) {
    return false;
  }

  return verify_ssl_fingerprint(sslclient, fp, domain_name);
}

/**
 * @brief Reads data from a provided stream into a dynamically allocated buffer.
 *
 * This function attempts to read the specified number of bytes from the given stream into a
 * buffer. If a previous buffer was allocated by this function, it is freed before new memory is allocated.
 * If the entire amount of requested data cannot be read from the stream, the allocated buffer is freed.
 *
 * @note The function returns a pointer to a statically held character pointer, which means subsequent 
 * calls to this function will affect the same memory location. It's up to the caller to ensure they don't
 * overwrite or double-free this memory.
 *
 * @param stream The Stream object from which data is to be read.
 * @param size   The number of bytes to read from the stream.
 *
 * @return Returns a pointer to the allocated buffer containing the read data, or nullptr if data could not 
 * be fully read or memory allocation failed.
 */
char *SSLClient::_streamLoad(Stream& stream, size_t size) {  
  char *dest = (char*)malloc(size+1);
  
  if (!dest) {
    return nullptr;
  }

  if (size != stream.readBytes(dest, size)) {
    free(dest);
    dest = nullptr;
    return nullptr;
  }

  dest[size] = '\0';
  return dest;
}

/**
 * @brief Loads the Certificate Authority (CA) certificate for the SSL client from a provided stream.
 *
 * This function reads the CA certificate data from the given stream and sets it for the 
 * SSL client. The CA certificate is used by the SSL client to verify the server's certificate.
 *
 * @param stream The Stream object from which the CA certificate is read.
 * @param size   The number of bytes to read from the stream.
 *
 * @return Returns true if the CA certificate is successfully loaded and set; otherwise returns false.
 */
bool SSLClient::loadCACert(Stream& stream, size_t size) {
  if (_CA_cert != NULL) {
    free(const_cast<char*>(_CA_cert));
  }
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCACert(dest);
    ret = true;
  }
  return ret;
}

/**
 * @brief Loads a certificate for the SSL client from a provided stream.
 *
 * This function reads the certificate data from the given stream and sets it for the 
 * SSL client. This certificate is used for client-side SSL authentication.
 *
 * @param stream The Stream object from which the certificate is read.
 * @param size   The number of bytes to read from the stream.
 *
 * @return Returns true if the certificate is successfully loaded and set; otherwise returns false.
 */
bool SSLClient::loadCertificate(Stream& stream, size_t size) {
  if (_cert != NULL) {
    free(const_cast<char*>(_cert));
  }
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCertificate(dest);
    ret = true;
  }
  return ret;
}

/**
 * @brief Loads a private key for the SSL client from a provided stream.
 *
 * This function reads the private key data from the given stream and sets it for the 
 * SSL client. This key is used for client-side SSL authentication.
 *
 * @param stream The Stream object from which the private key is read.
 * @param size   The number of bytes to read from the stream.
 *
 * @return Returns true if the private key is successfully loaded and set; otherwise returns false.
 */
bool SSLClient::loadPrivateKey(Stream& stream, size_t size) {
  if (_private_key != NULL) {
    free(const_cast<char*>(_private_key));
  }
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setPrivateKey(dest);
    ret = true;
  }
  return ret;
}

/**
 * @brief Retrieves the last SSL error description.
 *
 * This function obtains a textual representation of the last SSL error encountered 
 * and places it into the provided buffer. If there hasn't been an error, 
 * the function will return 0.
 *
 * @param buf   Pointer to the buffer where the error description should be stored.
 * @param size  Size of the provided buffer.
 *
 * @return Returns the last SSL error code. If no error has occurred, returns 0.
 */
int SSLClient::lastError(char *buf, const size_t size) {
  if (!_lastError) {
    return 0;
  }

  char error_buf[100];
  mbedtls_strerror(_lastError, error_buf, 100);
  snprintf(buf, size, "%s", error_buf);
  return _lastError;
}

/**
 * @brief Sets the timeout for the SSL handshake.
 * 
 * @param handshake_timeout The timeout in seconds.
 */
void SSLClient::setHandshakeTimeout(unsigned long handshake_timeout) {
  sslclient->handshake_timeout = handshake_timeout * 1000;
}

/**
 * @brief Sets the client for the SSLClient object.
 * 
 * @param client A pointer to the client class object. 
 */
void SSLClient::setClient(Client* client) {
    sslclient->client = client;
}

/**
 * @brief Sets the timeout for the SSLClient object.
 * 
 * @param milliseconds The timeout in milliseconds.
 */
void SSLClient::setTimeout(uint32_t milliseconds) { 
  _timeout = milliseconds; 
}

/**
 * @brief Sets the application layer protocol negotiation (ALPN) protocols.
 * 
 * @param alpn_protos A pointer to the ALPN protocols.
 */
void SSLClient::setAlpnProtocols(const char **alpn_protos) {
  _alpn_protos = alpn_protos;
}
