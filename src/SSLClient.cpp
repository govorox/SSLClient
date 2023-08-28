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
#include <errno.h>

#undef connect
#undef write
#undef read

/**
 * @brief Construct a new SSLClient::SSLClient object using the default constructor.
 */
SSLClient::SSLClient() {
  _connected = false;
  sslclient = new sslclient_context;
  ssl_init(sslclient, nullptr);
  sslclient->handshake_timeout = 120000;
  _CA_cert = NULL;
  _cert = NULL;
  _private_key = NULL;
  _pskIdent = NULL;
  _psKey = NULL;
}

/**
 * @brief Construct a new SSLClient::SSLClient object using the pointer to the specified client.
 * 
 * @param client 
 */
SSLClient::SSLClient(Client* client) {
  _connected = false;
  sslclient = new sslclient_context;
  ssl_init(sslclient, client);
  sslclient->handshake_timeout = 120000;
  _CA_cert = NULL;
  _cert = NULL;
  _private_key = NULL;
  _pskIdent = NULL;
  _psKey = NULL;
}

/**
 * @brief Destroy the SSLClient::SSLClient object.
 */
SSLClient::~SSLClient() {
  stop();
  delete sslclient;
}

/**
 * @brief Stops the SSL client.
 */
void SSLClient::stop() {
  if (sslclient->client != nullptr) {
    if (sslclient->client >= 0) {
      log_v("Stopping ssl client");
      stop_ssl_socket(sslclient, _CA_cert, _cert, _private_key);
    } else {
      log_v("stop() not called because client is < 0");
    }
  } else {
    log_v("stop() not called because client is nullptr");
  }
  _connected = false;
  _peek = -1;
}

/**
 * @brief 
 * 
 * @param ip 
 * @param port 
 * @return int 
 */
int SSLClient::connect(IPAddress ip, uint16_t port) {
  if (_pskIdent && _psKey) {
    log_v("connect with PSK");
    return connect(ip, port, _pskIdent, _psKey);
  }
  log_v("connect with CA");
  return connect(ip, port, _CA_cert, _cert, _private_key);
}

int SSLClient::connect(IPAddress ip, uint16_t port, int32_t timeout) {
  _timeout = timeout;
  return connect(ip, port);
}

int SSLClient::connect(const char *host, uint16_t port) {
  if (_pskIdent && _psKey) {
    log_v("connect with PSK");
    return connect(host, port, _pskIdent, _psKey);
  }
  log_v("connect with CA");
  return connect(host, port, _CA_cert, _cert, _private_key);
}

int SSLClient::connect(const char *host, uint16_t port, int32_t timeout) {
    _timeout = timeout;
    return connect(host, port);
}

int SSLClient::connect(IPAddress ip, uint16_t port, const char *_CA_cert, const char *_cert, const char *_private_key)
{
    return connect(ip.toString().c_str(), port, _CA_cert, _cert, _private_key);
}

int SSLClient::connect(const char *host, uint16_t port, const char *_CA_cert, const char *_cert, const char *_private_key)
{
    log_d("Connecting to %s:%d", host, port);
    if(_timeout > 0){
        sslclient->handshake_timeout = _timeout;
    }
    int ret = start_ssl_client(sslclient, host, port, _timeout, _CA_cert, _cert, _private_key, NULL, NULL);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl_client: %d", ret);
        stop();
        _connected = false;
        return 0;
    }
    log_i("SSL connection established");
    _connected = true;
    return 1;
}

int SSLClient::connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey) {
    return connect(ip.toString().c_str(), port,_pskIdent, _psKey);
}

int SSLClient::connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey) {
    log_v("start_ssl_client with PSK");
    if(_timeout > 0){
        sslclient->handshake_timeout = _timeout;
    }
    int ret = start_ssl_client(sslclient, host, port, _timeout, NULL, NULL, NULL, _pskIdent, _psKey);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl_client: %d", ret);
        stop();
        return 0;
    }
    _connected = true;
    return 1;
}

int SSLClient::peek(){
    if(_peek >= 0){
        return _peek;
    }
    _peek = timedRead();
    return _peek;
}

size_t SSLClient::write(uint8_t data)
{
    return write(&data, 1);
}

int SSLClient::read()
{
    uint8_t data = -1;
    int res = read(&data, 1);
    if (res < 0) {
        return res;
    }
    return data;
}

size_t SSLClient::write(const uint8_t *buf, size_t size)
{
    if (!_connected) {
        return 0;
    }
    int res = send_ssl_data(sslclient, buf, size);
    if (res < 0) {
        stop();
        res = 0;
    }
    return res;
}

/**
 * \brief               Reads data from the sslclient. If there is a byte peeked, it returns that byte.
 * 
 * \param buf           Buffer to read into. 
 * \param size          Size of the buffer.
 * \return int          1 if a byte has been peeked and the client is not connected.
 * \return int          < 1 if client is connected and there is an error from get_ssl_receive().
 * \return int          > 1 if res + peeked. 
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

  int res = get_ssl_receive(sslclient, buf, size);

  if (res < 0) {
    stop();
    return peeked?peeked:res; // If peeked is true return peeked, otherwise return res, i.e. data_to_read error.
  }

  return res + peeked; // Return the number of bytes read + the number of bytes peeked.
}

/**
 * \brief               Returns how many bytes of data are available to be read from the sslclient.
 *                      It takes into account both directly readable bytes and a potentially "peeked" byte.
 *                      If there's an error or the client is not connected, it handles these scenarios appropriately.
 * 
 * \return int           1 if a byte has been peeked and the client is not connected.
 * \return int          < 1 if client is connected and there is an error from data_to_read().
 * \return int          > 1 if res + peeked.
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

uint8_t SSLClient::connected()
{
    uint8_t dummy = 0;
    read(&dummy, 0);

    return _connected;
}

void SSLClient::setCACert (const char *rootCA)
{
    log_d("Set root CA");
    _CA_cert = rootCA;
}

void SSLClient::setCertificate (const char *client_ca)
{
    log_d("Set client CA");
    _cert = client_ca;
}

void SSLClient::setPrivateKey (const char *private_key)
{
    log_d("Set client PK");
    _private_key = private_key;
}

void SSLClient::setPreSharedKey(const char *pskIdent, const char *psKey) {
    log_d("Set PSK");
    _pskIdent = pskIdent;
    _psKey = psKey;
}

bool SSLClient::verify(const char* fp, const char* domain_name)
{
    if (!sslclient)
        return false;

    return verify_ssl_fingerprint(sslclient, fp, domain_name);
}

char *SSLClient::_streamLoad(Stream& stream, size_t size) {
  static char *dest = nullptr;
  if(dest) {
      free(dest);
  }
  dest = (char*)malloc(size);
  if (!dest) {
    return nullptr;
  }
  if (size != stream.readBytes(dest, size)) {
    free(dest);
    dest = nullptr;
  }
  return dest;
}

bool SSLClient::loadCACert(Stream& stream, size_t size) {
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCACert(dest);
    ret = true;
  }
  return ret;
}

bool SSLClient::loadCertificate(Stream& stream, size_t size) {
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCertificate(dest);
    ret = true;
  }
  return ret;
}

bool SSLClient::loadPrivateKey(Stream& stream, size_t size) {
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setPrivateKey(dest);
    ret = true;
  }
  return ret;
}

int SSLClient::lastError(char *buf, const size_t size)
{
    if (!_lastError) {
        return 0;
    }
    char error_buf[100];
    mbedtls_strerror(_lastError, error_buf, 100);
    snprintf(buf, size, "%s", error_buf);
    return _lastError;
}

void SSLClient::setHandshakeTimeout(unsigned long handshake_timeout)
{
    sslclient->handshake_timeout = handshake_timeout * 1000;
}

void SSLClient::setClient(Client* client){
    sslclient->client = client;
}
