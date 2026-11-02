idf_component_register(
    SRCS "src/SSLClient.cpp" "src/ssl__client.cpp" "src/certBundle.c"
    INCLUDE_DIRS "src"
    REQUIRES espressif__arduino-esp32 mbedtls
)

target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)

# Arduino supplies Client, IPAddress, timing and logging; this is not a
# standalone ESP-IDF transport implementation.
