[![Back to README](https://img.shields.io/badge/Back_to-_README-blue?style=for-the-badge)](../README.md)

# SSL Client Updates:

1. Added some commits of WifiSecureClient to fix some bugs.

2. Change send_ssl_data to use size_t instead of uint16_t, commit a299ddc

3. ssl_client.cpp: Fix parameter name in _handle_error, commit : 39155e7

4. Fix memory leaks when SSL/TLS connection fails, commit : f29f448

5. Fix buffer issue when writing data larger than receiving buffer, commit: 4ce6c5f

6. Fix issue where client read timeout value not being set, commit: 59ae9f0

7. Add clarity to return values for start_ssl_client and fix early termination of ssl client, commit: cc40266

8. Close issue [#30](https://github.com/govorox/SSLClient/issues/30), commit: e426936

9.  Separate concerns from start_ssl_client into singly responsible functions and unit test private API, commit: 0f1fa36

10. Close issue [#60](https://github.com/govorox/SSLClient/issues/60), Naming collision changes to make compatibile compilation with WiFiClientSecure, commit: b8a9e7e

11. `v1.2.0`

    **ALPN Support**: Application Layer Protocol Negotiation for efficient server communication.

    **Cert Bundles**: Simplifies management and use of multiple CA certificates.  
    
    **Bug Fix**: Corrects byte calculation for record expansion post-handshake.
    
    **More Examples**: Examples for the ESP32 PlatformIO for ALPN protocols, AWS, and using certificate bundles. 

12. `v1.3.0` 
    
    - Feature flag for compatibility with MbedTLS v3.x.x - Automated by MBEDTLS_VERSION_MAJOR.
    - Add Flag MBEDTLS_BACKPORT to allow override MBEDTLS_VERSION_MAJOR >= 3.
    - Add workaround for W5500 Ethernet failing due to client returning -1 when no error - switch on flag W5500_WORKAROUND.
    - closes issue Support for ESP32 and W5500 based Secure Ethernet for HTTPS or MQTTS? [#44](https://github.com/govorox/SSLClient/issues/85) and closes issue SSLClient with W5500 not working (works well with WiFi and TinyGSM) [#85](https://github.com/govorox/SSLClient/issues/85).
    - Improve documentation.
    - Add GitHub Actions workflow to ensure PlatformIO examples compile.
    - Update GitHub Actions workflow to run tests multiple times with feature flags set.
    - Add GitHub Actions workflow to ensure Arduino IDE compile.
    - Fix Arduino IDE examples to compile when using arduino-esp32 @2.0.17 - This is still broken for @3.0.2 There is a breaking change in arduino-esp32 from v3.0.0 which is causing ambiguous reference errors to byte.

13. `v1.3.1`

    - Patch to fixing compilation on Arduino IDE of examples

14. `v1.3.2`

    - Patch to update cert for https_get_sim7600 for Arduino IDE