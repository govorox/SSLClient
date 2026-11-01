/*
  SSLClient.h - Base class that provides Client SSL to ESP32
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

#ifndef SSLCLIENT_H
#define SSLCLIENT_H

#include "log_.h"

#ifdef PLATFORMIO
#include <Arduino.h>
#endif
#include "IPAddress.h"
#include "ssl__client.h"

class SSLClient : public Client
{
protected:
  sslclient__context *sslclient;

  int _lastError = 0;
	int _peek = -1;
  uint32_t _timeout = 0;
  bool _use_insecure = false;
  const char *_CA_cert = nullptr;
  const char *_cert = nullptr;
  const char *_private_key = nullptr;
  const char *_pskIdent = nullptr; // identity for PSK cipher suites
  const char *_psKey = nullptr; // key in hex for PSK cipher suites
  const char **_alpn_protos = nullptr;
  bool _use_ca_bundle = false;
  bool _connected = false;
  Client* _client = nullptr;

public:
  SSLClient();
  SSLClient(Client* client);
  ~SSLClient();

  int connect(IPAddress ip, uint16_t port);
  int connect(IPAddress ip, uint16_t port, int32_t timeout);
  int connect(const char *host, uint16_t port);
  int connect(const char *host, uint16_t port, int32_t timeout);
  int connect(IPAddress ip, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key);
  int connect(const char *host, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key);
  int connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey);
  int connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey);

	int peek();
  size_t write(uint8_t data);
  size_t write(const uint8_t *buf, size_t size);
  int available();
  int read();
  int read(uint8_t *buf, size_t size);
  void flush() {}
  void stop();
  uint8_t connected();
  int lastError(char *buf, const size_t size);

  void setInsecure();
  void setPreSharedKey(const char *pskIdent, const char *psKey); // psKey in Hex
  void setCACert(const char *rootCA);
  void setCertificate(const char *client_ca);
  void setPrivateKey (const char *private_key);
  void setCACertBundle(const uint8_t * bundle);
  bool loadCACert(Stream& stream, size_t size);
  bool loadCertificate(Stream& stream, size_t size);
  bool loadPrivateKey(Stream& stream, size_t size);
  bool verify(const char* fingerprint, const char* domain_name);
  void setHandshakeTimeout(unsigned long handshake_timeout);
  void setClient(Client* client);
  void setTimeout(uint32_t milliseconds);
  void setAlpnProtocols(const char **alpn_protos);
  const mbedtls_x509_crt* getPeerCertificate() { return mbedtls_ssl_get_peer_cert(&sslclient->ssl_ctx); };
  bool getFingerprintSHA256(uint8_t sha256_result[32]) { return get_peer_fingerprint(sslclient, sha256_result); }

  operator bool() {
    return connected();
  }

  bool operator==(const bool value) {
    return bool() == value;
  }

  bool operator!=(const bool value) {
    return bool() != value;
  }

private:
  char *_streamLoad(Stream& stream, size_t size);

  //friend class GprsServer;
  using Print::write;
};

#endif /* SSLClient_H */
