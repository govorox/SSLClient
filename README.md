# SSLClient Library for Arduino and ESP

[![govorox - SSLClient](https://img.shields.io/static/v1?label=govorox&message=SSLClient&color=green&logo=github)](https://github.com/govorox/SSLClient "Go to GitHub repo")
[![stars - SSLClient](https://img.shields.io/github/stars/govorox/SSLClient?style=social)](https://github.com/govorox/SSLClient)
[![forks - SSLClient](https://img.shields.io/github/forks/govorox/SSLClient?style=social)](https://github.com/govorox/SSLClient)

[![GitHub tag](https://img.shields.io/github/tag/govorox/SSLClient?include_prereleases=&sort=semver&color=blue)](https://github.com/govorox/SSLClient/releases/)
[![License](https://img.shields.io/badge/License-MIT-blue)](#license)
[![issues - SSLClient](https://img.shields.io/github/issues/govorox/SSLClient)](https://github.com/govorox/SSLClient/issues)

## Table of Contents

1. [Installation](#-installation) - How to install the library using Arduino or PlatformIO.
2. [Overview of this Library](#-overview) - An overview of the SSLClient library.
3. [What's New](#-whats-new-in-the-latest-release) - The latest features and updates.
4. [Features](#-features) - Key features of the SSLClient library.
5. [Usage](#-usage) - Basic usage examples for the SSLClient library.
6. [Overview of Functions](docs/FUNCTIONS.md) - An overview of the API for leveraging MbedTLS.
7. [Contribute](docs/CONTRIBUTING.md) - Contributions are welcome!
8. [Change Log](docs/CHANGELOG.md) - See what's new in each release.
9. [Code Guide](docs/CODEGUIDE.md) - Guidelines for contributing to the project.
10. [Signal Strength Map](docs/RSSI.md) - Useful for debugging GSM connectivity.
11. [License](#-license) - The license for the SSLClient library (open-source).

## 🔧 Installation

Install via the Arduino Library Manager or PlatformIO plugin:

[![arduino-library-badge](https://img.shields.io/static/v1?label=Arduino%20Libraries&message=GovoroxSSLClient&color=orange&logo=arduino)](https://www.arduinolibraries.info/libraries/govorox-ssl-client "Go to Arduino Libraries")

**Arduino IDE** - search for "SSLClient"

[![PlatformIO Registry](https://badges.registry.platformio.org/packages/digitaldragon/library/SSLClient.svg)](https://registry.platformio.org/libraries/digitaldragon/SSLClient "Go to PlatformIO Registry")

**VSCode / PlatformIO** - add `digitaldragon/SSLClient@^1.3.0` to `platformio.ini`

## 🚀 Overview

Originally based on the `WiFiClientSecure` for Arduino-ESP32 the SSLClient extends the ESP32/Arduino ecosystem to secure communication via TLS, providing a transparent SSL/TLS layer over any `Client` class instance. Leverages *mbedtls* for robust, efficient cryptographic operations, initially tailored for ESP32 but adaptable across platforms.

## 🌟 What's New in the Latest Release

**Major Versions 2 and 3 of MBedTLS**: Updated to support the latest version of the MBedTLS library.  

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
- Compatible with Arduino-ESP32 and potentially other platforms.
- Suitable for IoT applications, including AWS IoT.

## 🛠 Usage

### Basic Connection

```cpp
#include <SSLClient.h>

// Initialize your transport layer (e.g., WiFi, GSM)
// A Client is anything which inherits from the Arduino Client class.
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

## 📄 License

The library is released under GNU General Public Licence. See the `LICENSE` file for more details.
