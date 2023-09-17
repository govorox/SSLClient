#define log_d(...); printf(__VA_ARGS__); printf("\n");
#define log_i(...); printf(__VA_ARGS__); printf("\n");
#define log_w(...); printf(__VA_ARGS__); printf("\n");
#define log_e(...); printf(__VA_ARGS__); printf("\n");
#define log_v(...); printf(__VA_ARGS__); printf("\n");
#define portTICK_PERIOD_MS 1
#define vTaskDelay(x) delay(x)

#include "unity.h"
#include "Arduino.h"
#include "mocks/ESPClass.hpp"
#include "mocks/TestClient.h"
#include "ssl_client.cpp"

using namespace fakeit;

TestClient testClient;

void setUp(void) {
  ArduinoFakeReset();
  testClient.reset();
  testClient.returns("connected", (uint8_t)1); // Mock the client to return true for "connected" function
}

void tearDown(void) {}

void test_client_null_context(void) {
  unsigned char buf[100];
  int result = client_net_send(NULL, buf, sizeof(buf));
  
  TEST_ASSERT_EQUAL_INT(-1, result);
} 
    
void test_client_write_succeeds(void) {
  // Arrange
  testClient.returns("write", (size_t)1024).then((size_t)1024).then((size_t)1024);
  unsigned char buf[3072]; // 3 chunks of data

  // Act
  void* clientPtr = static_cast<void*>(&testClient);
  int result = client_net_send(clientPtr, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(3072, result);
}

void test_client_write_fails(void) {
  // Arrange
  testClient.returns("write", (size_t)1024).then((size_t)1024).then((size_t)0);
  unsigned char buf[3000]; // 3 chunks of data, but it fails on the 3rd chunk

  // Act
  int result = client_net_send(&testClient, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(MBEDTLS_ERR_NET_SEND_FAILED, result);
}

void test_zero_length_buffer(void) {
  // Arrange
  unsigned char buf[1];

  // Act
  int result = client_net_send(&testClient, buf, 0);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_single_chunk_exact(void) {
  // Arrange
  unsigned char buf[1024];
  testClient.returns("write", (size_t)1024);

  // Act
  int result = client_net_send(&testClient, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(1024, result);
}

void test_partial_write(void) {
  // Arrange
  unsigned char buf[3000];
  testClient.returns("write", (size_t)500).then((size_t)500).then((size_t)500);

  // Act
  int result = client_net_send(&testClient, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(1500, result); // Only half the buffer is sent
}

void test_disconnected_client(void) {
  // Arrange
  unsigned char buf[1000];
  testClient.reset(); // Reset the mock client
  testClient.returns("connected", (uint8_t)0); // Mock the client to return false for "connected" function

  // Act
  int result = client_net_send(&testClient, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(-2, result); // -2 indicates disconnected client
}

void run_all_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_client_null_context);
  RUN_TEST(test_client_write_succeeds);
  RUN_TEST(test_client_write_fails);
  RUN_TEST(test_zero_length_buffer);
  RUN_TEST(test_single_chunk_exact);
  RUN_TEST(test_partial_write);
  RUN_TEST(test_disconnected_client);
  UNITY_END();
}

#ifdef ARDUINO

#include <Arduino.h>

void setup() {
  delay(2000); // If using Serial, allow time for serial monitor to open
  run_all_tests();
}

void loop() {
  // Empty loop
}

#else

int main(int argc, char **argv) {
  run_all_tests();
  return 0;
}

#endif
