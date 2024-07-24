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

<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem;">
  <a href="https://www.arduino.cc/reference/en/libraries/govoroxsslclient/" title="Go to Arduino Libraries">
    <img src="https://img.shields.io/static/v1?label=Arduino%20Libraries&message=GovoroxSSLClient&color=orange&logo=arduino" alt="arduino-library-badge">
  </a>
  <a href="https://registry.platformio.org/libraries/digitaldragon/SSLClient" title="Go to PlatformIO Registry">
    <img src="https://badges.registry.platformio.org/packages/digitaldragon/library/SSLClient.svg" alt="PlatformIO Registry">
  </a>
</div>

*Install via the Arduino IDE or PlatformIO:*

**Arduino IDE** - search for `GovoroxSSLClient` in the library manager.

**PlatformIO** - add `digitaldragon/SSLClient@^1.3.1` to `platformio.ini`.

## 🚀 Overview

Originally based on the `WiFiClientSecure` for Arduino-ESP32 the SSLClient extends the ESP32/Arduino ecosystem to secure communication via TLS, providing a transparent SSL/TLS layer over any `Client` class instance. Leverages *mbedtls* for robust, efficient cryptographic operations, initially tailored for ESP32 but adaptable across platforms.

## 🌟 What's New in the Latest Release

- **Examples for PlatformIO and Arduino IDE**: Updated examples to work with both PlatformIO and Arduino IDE for both Arduino-ESP32@2.0.17 and Arduino-ESP32@>3.0.0.

- **Major Versions 2 and 3 of MBedTLS**: Updated to support the latest version of the MBedTLS library.  

- **Feature flag for compatibility with MbedTLS v3.x.x** - Automated by `MBEDTLS_VERSION_MAJOR`.

- **Add Flag `MBEDTLS_BACKPORT`** to allow override `MBEDTLS_VERSION_MAJOR >= 3`.

- **Add workaround for W5500 Ethernet failing** due to client returning -1 when no error - switch on flag `W5500_WORKAROUND`.

- **Close the following issues:** Support for ESP32 and W5500 based Secure Ethernet for HTTPS or MQTTS? [#44](https://github.com/govorox/SSLClient/issues/85) and issue SSLClient with W5500 not working (works well with WiFi and TinyGSM) [#85](https://github.com/govorox/SSLClient/issues/85).

- **Improve documentation**

- **Add GitHub Actions workflow** to ensure PlatformIO examples compile.

- **Update GitHub Actions workflow** to run tests multiple times with feature flags set.

- **Add GitHub Actions workflow** to ensure Arduino IDE compile.

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
