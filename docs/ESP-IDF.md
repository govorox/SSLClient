# ESP-IDF with Arduino as a component

This integration retains the Arduino framework and its `Client` transport API.
It does not provide an Arduino-free ESP-IDF port. It uses `idf.py` and CMake;
Arduino IDE and PlatformIO are not required.

The initial build target is **ESP32**, **ESP-IDF 5.1.4**, and managed component
**espressif/arduino-esp32 3.0.2**. The manifest deliberately restricts IDF to 5.1
and pins Arduino rather than claiming compatibility with all newer versions.

## Build the smoke example

From an initialized ESP-IDF 5.1.4 terminal at the repository root:

```sh
idf.py -C examples/Esp32-ESP-IDF/component_smoke set-target esp32
idf.py -C examples/Esp32-ESP-IDF/component_smoke build
```

The component manager downloads Arduino and its dependencies using the example's
committed `dependencies.lock`. Internet access is required on the first build.
Keep the lock file when reproducing the supported build. The example uses this checkout through
`EXTRA_COMPONENT_DIRS`, so it tests the branch's source rather than a release.

The smoke application calls `initArduino()`, constructs an Arduino Wi-Fi transport
and SSLClient, and configures its timeouts. It does not connect to Wi-Fi or a TLS
server. A successful build verifies compilation/linking, not hardware operation,
certificate validation, Ethernet, or TinyGSM compatibility.

## Add to another ESP-IDF project

Place this checkout in `components/SSLClient`, or add its absolute path to
`EXTRA_COMPONENT_DIRS` before including ESP-IDF's `project.cmake`. Keep the root
`CMakeLists.txt`, `idf_component.yml`, and `src` directory together. Use the
component manager so the pinned Arduino dependency is resolved automatically.

The example's `sdkconfig.defaults` contains the required settings:

```text
CONFIG_FREERTOS_HZ=1000
# CONFIG_AUTOSTART_ARDUINO is not set
CONFIG_MBEDTLS_PSK_MODES=y
CONFIG_MBEDTLS_KEY_EXCHANGE_PSK=y
```

SSLClient currently requires at least one PSK key-exchange mode to compile even
when the application uses CA certificates. With Arduino autostart disabled, call
`initArduino()` from your C++ `extern "C" void app_main()` before using Arduino
services. Initialize the transport, system clock, and appropriate trust material
before making real TLS connections.

For independent logging, set `SSL_CLIENT_LOG_LEVEL` on the SSLClient component
target (or through a project-wide build definition) before compiling; defining it
only in the application's source does not configure the library translation units.

References: [Arduino as an ESP-IDF component](https://docs.espressif.com/projects/arduino-esp32/en/latest/esp-idf_component.html)
and [Arduino 3.0.2 dependency manifest](https://github.com/espressif/arduino-esp32/blob/3.0.2/idf_component.yml).
