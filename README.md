# SSLClient Arduino Library (Version 1.2.0)

#### Available on PlatformIO registry as digitaldragon/SSLClient@1.2.0
[![PlatformIO Registry](https://badges.registry.platformio.org/packages/digitaldragon/library/SSLClient.svg)](https://registry.platformio.org/libraries/digitaldragon/SSLClient)

#### Available on Arduino Libraries registry to digitaldragon/GovoroxSSLClient@1.2.0
[![arduino-library-badge](https://www.ardu-badge.com/badge/GovoroxSSLClient.svg)](https://www.ardu-badge.com/badge/GovoroxSSLClient.svg)

## 🚀 Overview
SSLClient extends the ESP32/Arduino ecosystem to secure communication via TLS, providing a transparent SSL/TLS layer over any **Client** class instance. Leverages *mbedtls* for robust, efficient cryptographic operations, initially tailored for ESP32 but adaptable across platforms.

Based on the [WiFiClientSecure](https://github.com/espressif/arduino-esp32/tree/master/libraries/WiFiClientSecure) for Arduino/ESP32.

## 🌟 What's New in 1.2.0
**ALPN Support**: Application Layer Protocol Negotiation for efficient server communication.  
**Cert Bundles**: Simplifies management and use of multiple CA certificates.  
**Bug Fix**: Corrects byte calculation for record expansion post-handshake.
**More Examples**: Examples for the ESP32 PlatformIO for ALPN protocols, AWS, and using certificate bundles.

## ✨ Features
- Secure TLS communication.
- Based on mbedtls.
- Compatible with Arduino/ESP32 and potentially other platforms.
- Suitable for IoT applications, including AWS IoT.

## 🔧 Installation
Install via the Arduino Library Manager or PlatformIO:

Arduino IDE: Search for "SSLClient".
PlatformIO: Add `digitaldragon/SSLClient@^1.2.0` to platformio.ini.

## 🛠 Usage
### Basic Connection
```cpp
#include <SSLClient.h>

// Initialize your transport layer (e.g., WiFi, GSM)
Client transport = /* Your transport layer */;

// Create SSLClient instance
SSLClient sslClient(&transport);

// Your setup code here...
```

### AWS IoT Connectivity
```cpp
TinyGsmClient transport(modem);
SSLClient secure(&transport);

// Set up certificates
secure.setCACert(AWS_CERT_CA);
secure.setCertificate(AWS_CERT_CRT);
secure.setPrivateKey(AWS_CERT_PRIVATE);

// Connect to MQTT broker on AWS endpoint
MQTTClient mqtt = MQTTClient(256);
mqtt.begin(AWS_IOT_ENDPOINT, 8883, secure);
```
### 📚 Application Notes
The `SSLClient.cpp` file provides a comprehensive suite of functions for handling SSL/TLS connections in an Arduino environment, particularly for the ESP32. These functions can be categorized into several key areas of functionality, which are essential for understanding the library's capabilities. Here's a user guide to the functionality based on the documentation blocks of these functions:

### Error Handling
- **`_handle_error(int err, const char* function, int line)`**: This function is used internally to handle errors. It interprets the error code returned by various SSL operations and logs it for debugging purposes.

### Network Communication
- **`client_net_recv(void *ctx, unsigned char *buf, size_t len)`**: Receives data over an established SSL connection. It checks for a valid client context and returns the number of bytes received or an error code.
- **`client_net_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)`**: Similar to `client_net_recv`, but with an additional timeout parameter. It's useful for non-blocking operations.
- **`client_net_send(void *ctx, const unsigned char *buf, size_t len)`**: Sends data over an SSL connection. It ensures that the client is properly initialized and connected before sending data.

### Initialization and Cleanup
- **`ssl_init(sslclient_context *ssl_client, Client *client)`**: Initializes the SSL context with default values and sets up necessary SSL configurations.
- **`cleanup(sslclient_context *ssl_client, bool ca_cert_initialized, bool client_cert_initialized, bool client_key_initialized, int ret, const char *rootCABuff, const char *cli_cert, const char *cli_key)`**: Frees allocated resources and stops the SSL socket if an error occurred during SSL operations.

### SSL Client Start and Configuration
- **`start_ssl_client(sslclient_context *ssl_client, const char *host, uint32_t port, int timeout, const char *rootCABuff, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey)`**: Handles the entire process of starting an SSL client, including TCP connection initiation, random number generation seeding, SSL/TLS defaults setup, authentication, and SSL handshake.
- **`init_tcp_connection(sslclient_context *ssl_client, const char *host, uint32_t port)`**: Initializes a TCP connection to a remote host.
- **`seed_random_number_generator(sslclient_context *ssl_client)`**: Seeds the random number generator critical for SSL/TLS operations.
- **`set_up_tls_defaults(sslclient_context *ssl_client)`**: Sets up SSL/TLS configuration with default settings.
- **`auth_root_ca_buff(sslclient_context *ssl_client, const char *rootCABuff, bool *ca_cert_initialized, const char *pskIdent, const char *psKey)`**: Configures SSL/TLS authentication options based on provided CA certificates or pre-shared keys.
- **`auth_client_cert_key(sslclient_context *ssl_client, const char *cli_cert, const char *cli_key, bool *client_cert_initialized, bool *client_key_initialized)`**: Loads and initializes the client's certificate and private key for SSL/TLS authentication.
- **`set_hostname_for_tls(sslclient_context *ssl_client, const char *host)`**: Sets the hostname for the TLS session, which should match the Common Name (CN) in the server's certificate.

### SSL Handshake and Verification
- **`perform_ssl_handshake(sslclient_context *ssl_client, const char *cli_cert, const char *cli_key)`**: Manages the SSL/TLS handshake process.
- **`verify_server_cert(sslclient_context *ssl_client)`**: Verifies the server's certificate against the provided root CA.

### Data Transmission and Reception
- **`data_to_read(sslclient_context *ssl_client)`**: Checks if there is data available to read from the SSL connection.
- **`send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len)`**: Sends data over an established SSL connection.
- **`get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, size_t length)`**: Receives data from the SSL connection.

### Certificate Validation
- **`verify_ssl_fingerprint(sslclient_context *ssl_client, const char* fp, const char* domain_name)`**: Verifies the certificate provided by the peer against a specified SHA256 fingerprint.
- **`verify_ssl_dn(sslclient_context *ssl_client, const char* domain_name)`**: Checks if the peer certificate contains the specified domain name in its Common Name (CN) or Subject Alternative Names (SANs).

### Utility Functions
- **`parse_hex_nibble(char pb, uint8_t* res)`**: Parses a hexadecimal nibble into its binary representation.
- **`match_name(const string& name, const string& domainName

)`**: Compares a name from a certificate to a domain name to check if they match.

### Cleanup and Socket Management
- **`stop_ssl_socket(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key)`**: Stops the SSL socket and frees associated resources.

This user guide provides a comprehensive overview of each function, offering insights into how to use the SSLClient library effectively for secure communication in Arduino-based projects. Each function is designed to handle specific aspects of SSL/TLS communication, from establishing connections and handling data transmission to managing certificates and ensuring security.

## 📄 License
The library is released under GNU General Public Licence. See the LICENSE file for more details.

## 📶 Handy CSQ / RSSI / Signal Strength Mapping
| CSQ Value | RSSI (dBm)          | Description      |
|-----------|---------------------|------------------|
| 0         | -113 dBm or less    | No signal        |
| 1-2       | -111 dBm to -109 dBm| Very poor signal |
| 3-9       | -107 dBm to -93 dBm | Poor signal      |
| 10-14     | -91 dBm to -83 dBm  | Fair signal      |
| 15-19     | -81 dBm to -73 dBm  | Good signal      |
| 20-30     | -71 dBm to -53 dBm  | Very good signal |
| 31        | -51 dBm or more     | Excellent signal |

## 🖥 Contributing
Contributions are welcome! Please fork the repository and submit pull requests with your enhancements.