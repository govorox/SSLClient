# SSLClient Library for Arduino and ESP

[![govorox - SSLClient](https://img.shields.io/static/v1?label=govorox&message=SSLClient&color=green&logo=github)](https://github.com/govorox/SSLClient "Go to GitHub repo")
[![stars - SSLClient](https://img.shields.io/github/stars/govorox/SSLClient?style=social)](https://github.com/govorox/SSLClient)
[![forks - SSLClient](https://img.shields.io/github/forks/govorox/SSLClient?style=social)](https://github.com/govorox/SSLClient)

[![GitHub tag](https://img.shields.io/github/tag/govorox/SSLClient?include_prereleases=&sort=semver&color=blue)](https://github.com/govorox/SSLClient/releases/)
[![License](https://img.shields.io/badge/License-MIT-blue)](#license)
[![issues - SSLClient](https://img.shields.io/github/issues/govorox/SSLClient)](https://github.com/govorox/SSLClient/issues)

## 🚀 Overview

SSLClient extends the ESP32/Arduino ecosystem to secure communication via TLS, providing a transparent SSL/TLS layer over any **Client** class instance. Leverages *mbedtls* for robust, efficient cryptographic operations, initially tailored for ESP32 but adaptable across platforms.

Based on the [WiFiClientSecure](https://github.com/espressif/arduino-esp32/tree/master/libraries/WiFiClientSecure) for Arduino/ESP32.

## 🌟 What's New
**Major Versions 2 and 3 of MBedTLS**: Updated to support the latest versions of the MBedTLS library.  
**ALPN Support**: Application Layer Protocol Negotiation for efficient server communication.  
**Cert Bundles**: Simplifies management and use of multiple CA certificates.  
**Bug Fix**: Corrects byte calculation for record expansion post-handshake.
**More Examples**: Examples for the ESP32 PlatformIO for ALPN protocols, AWS, and using certificate bundles.

## ✨ Features

- Secure TLS communication.
- Based on **Mbed-TLS/mbedtls**.
  - **Mbed TLS 2.x**
    TLS Versions Supported: **Mbed TLS 2.x** supports `TLS 1.0`, `TLS 1.1`, and `TLS 1.2`.
    **Specifics:**
    `TLS 1.2`: Full support with a wide range of cipher suites and features.
    `TLS 1.1` and `1.0`: These versions are supported, but their use is discouraged due to security vulnerabilities and weaknesses compared to `TLS 1.2`.
  - **Mbed TLS 3.x**
    TLS Versions Supported: **Mbed TLS 3.x** supports `TLS 1.2` and `TLS 1.3`.
    **Specifics:**
    `TLS 1.2`: Continues full support with extensive cipher suites and features.
    `TLS 1.3`: Introduced in Mbed `TLS 3.x`, providing enhanced security features, improved performance, and simplified handshake process.
- Compatible with Arduino/ESP32 and potentially other platforms.
- Suitable for IoT applications, including AWS IoT.

## 🔧 Installation

Install via the Arduino Library Manager or PlatformIO plugin:

[![arduino-library-badge](https://img.shields.io/static/v1?label=Arduino%20Libraries&message=GovoroxSSLClient&color=orange&logo=arduino)](https://www.arduinolibraries.info/libraries/govorox-ssl-client "Go to Arduino Libraries")

**Arduino IDE** - search for "SSLClient"

[![PlatformIO Registry](https://badges.registry.platformio.org/packages/digitaldragon/library/SSLClient.svg)](https://registry.platformio.org/libraries/digitaldragon/SSLClient "Go to PlatformIO Registry")

**VSCode / PlatformIO** - add `digitaldragon/SSLClient@^1.3.0` to `platformio.ini`

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

### For details on the functions, see [📚 Function Notes](docs/FUNCTIONS.md)

## 🖥 Contributions Welcome

Contributions are welcome! Please fork the repository and submit pull requests with your enhancements. For more information on contributing, please refer to the [Contributing Guide](docs/CONTRIBUTING.md).

## For more details, see the [Change Log](docs/CHANGELOG.md).


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
