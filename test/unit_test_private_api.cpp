// #define EMULATOR_LOG
#include "unity.h"
#include "Arduino.h"
#include "Emulation.h"

#define portTICK_PERIOD_MS 1
#define vTaskDelay(x) delay(x)
#define pdMS_TO_TICKS(x) x

#include "mocks/ESPClass.hpp"
#include "mocks/TestClient.h"
#include "ssl__client.cpp"

using namespace fakeit;

TestClient testClient; // Mocked client
sslclient__context *testContext; // Context for tests

/**
 * @brief Set the up stop ssl socket object for these tests.
 * 
 * @param ctx The sslclient__context to set up.
 * @param client The client to set up.
 */
void setup_stop_ssl_socket(sslclient__context* ctx, Client* client) {
  ctx->ssl_conf.actual_ca_chain = (mbedtls_x509_crt*) malloc(sizeof(mbedtls_x509_crt));
  ctx->ssl_conf.actual_key_cert = &dummy_cert;
  ctx->ssl_conf.ca_chain = ctx->ssl_conf.actual_ca_chain;
  ctx->ssl_conf.key_cert = ctx->ssl_conf.actual_key_cert;
}

void setUp(void) {
  ArduinoFakeReset();
  ResetEmulators();
  testClient.reset();
  testClient.returns("connected", (uint8_t)1);
  mbedtls_mock_reset_return_values();
  testContext = new sslclient__context();
}

void tearDown(void) {
  delete testContext;
  testContext = nullptr;
}

/* Test client_net_send function */

void test_client_null_context(void) {
  // Arrange
  unsigned char buf[100];
  
  // Act
  int result = client_net_send(NULL, buf, sizeof(buf));
  
  // Assert
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
  testClient.reset();
  testClient.returns("connected", (uint8_t)0);

  // Act
  int result = client_net_send(&testClient, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(1, log_e_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(-2, result); // -2 indicates disconnected client
}

void run_client_net_send_tests(void) {
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

/* Test client_net_recv function */

void test_null_client_context(void) {
  // Arrange
  unsigned char buf[100];

  // Act
  int result = client_net_recv(NULL, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(-1, result);
}

void test_disconnected_client_client_net_recv(void) {
  // Arrange
  testClient.reset();
  testClient.returns("connected", (uint8_t)0);
  unsigned char buf[100];

  // Act
  int result = client_net_recv(&testClient, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(-2, result);
}

void test_successful_client_read(void) {
  // Arrange
  unsigned char buf[100];
  testClient.returns("read", (int)50);

  // Act
  int result = client_net_recv(&testClient, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(50, result);
}

void test_failed_client_read(void) {
  // Arrange
  unsigned char buf[100];
  testClient.returns("read", (int)0); // Mock a read failure

  // Act
  int result = client_net_recv(&testClient, buf, sizeof(buf));

  // Assert
  TEST_ASSERT_EQUAL_INT(0, result); // Expecting 0 as read() has failed
}

void run_client_net_recv_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_null_client_context);
  RUN_TEST(test_disconnected_client_client_net_recv);
  RUN_TEST(test_successful_client_read);
  RUN_TEST(test_failed_client_read);
  UNITY_END();
}

/* Test handle_error function */

void test_handle_error_no_logging_on_minus_30848(void) {
  // Arrange
  int err = -30848;

  // Act
  int result = _handle_error(err, "testFunction", 123);

  // Assert
  TEST_ASSERT_EQUAL_INT(-30848, result);
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
}

void test_handle_error_logging_with_mbedtls_error_c(void) {
  // Arrange
  int err = MBEDTLS_ERR_NET_SEND_FAILED;

  // Act
  int result = _handle_error(err, "testFunction", 123);

  // Assert
  TEST_ASSERT_EQUAL_INT(-0x004E, result);
  TEST_ASSERT_TRUE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(1, log_e_stub.timesCalled());
}

void test_handle_error_logging_without_mbedtls_error_c(void) {
  // Arrange
  int err = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE; // Some error code not being specially handled

  // Act
  int result = _handle_error(err, "testFunction", 123);

  // Assert
  TEST_ASSERT_EQUAL_INT(err, result);
  TEST_ASSERT_TRUE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(1, log_e_stub.timesCalled());
}

void run_handle_error_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_handle_error_no_logging_on_minus_30848);
  RUN_TEST(test_handle_error_logging_with_mbedtls_error_c);
  RUN_TEST(test_handle_error_logging_without_mbedtls_error_c);
  UNITY_END();
}

/* Test client_net_recv_timeout function */

void test_ctx_is_null(void) {
  // Arrange
  unsigned char buf[10];
  
  // Act
  int result = client_net_recv_timeout(nullptr, buf, 10, 1000);
  
  // Assert
  TEST_ASSERT_FALSE(log_v_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(1, log_e_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(-1, result);
}

void test_successful_read_without_delay(void) {
  // Arrange
  testClient.returns("available", (int)10);
  testClient.returns("read", (int)10);
  unsigned char buf[10];

  // Act
  int result = client_net_recv_timeout(&testClient, buf, 10, 1000);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(2, log_v_stub.timesCalled());
  TEST_ASSERT_GREATER_THAN(0, result);
}

void test_successful_read_with_delay(void) {
  // Arrange
  testClient.returns("available", (int)10);
  testClient.returns("read", (int)10);
  unsigned char buf[10];

  // Act
  int result = client_net_recv_timeout(&testClient, buf, 10, 1000);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(2, log_v_stub.timesCalled());
  TEST_ASSERT_GREATER_THAN(0, result);
}

void test_read_timeout(void) {
  // Arrange
  testClient.reset();
  testClient.returns("available", (int)0);
  testClient.returns("read", (int)0);
  unsigned char buf[10];

  // Act
  int result = client_net_recv_timeout(&testClient, buf, 10, 100);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(1, log_v_stub.timesCalled());
  TEST_ASSERT_EQUAL(MBEDTLS_ERR_SSL_WANT_READ, result);
}

void test_read_returns_zero(void) {
  // Arrange
  testClient.returns("available", (int)10);
  testClient.returns("read", (int)0);
  unsigned char buf[10];

  // Act
  int result = client_net_recv_timeout(&testClient, buf, 10, 1000);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(1, log_v_stub.timesCalled());
  TEST_ASSERT_EQUAL(MBEDTLS_ERR_SSL_WANT_READ, result);
}

void test_len_zero(void) {
  // Arrange
  unsigned char buf[10];

  // Act
  int result = client_net_recv_timeout(&testClient, buf, 0, 1000);
  
  // Assert
  TEST_ASSERT_TRUE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(0, result);
}

void run_client_net_recv_timeout_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ctx_is_null);
  RUN_TEST(test_successful_read_without_delay);
  RUN_TEST(test_successful_read_with_delay);
  RUN_TEST(test_read_timeout);
  RUN_TEST(test_read_returns_zero);
  RUN_TEST(test_len_zero);
  UNITY_END();
}

/* test ssl_init function */

void test_ssl_init_correct_initialization() {
  // Arrange / Act
  ssl_init(testContext, &testClient);
  
  // Assert
  TEST_ASSERT_EQUAL_PTR(&testClient, testContext->client);
  TEST_ASSERT_EQUAL_MEMORY(&testClient, testContext->client, sizeof(Client));
}

void test_ssl_init_mbedtls_functions_called() {
  // Arrange / Act
  ssl_init(testContext, &testClient);
  
  // Assert
  TEST_ASSERT_TRUE(mbedtls_ssl_init_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_ssl_config_init_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_ctr_drbg_init_stub.wasCalled());
}

void test_ssl_init_logging() {
  // Assert / Act
  ssl_init(testContext, &testClient);
  ArgContext args = log_v_stub.getArguments();
  
  // Assert
  TEST_ASSERT_EQUAL_STRING("Init SSL", args.resolve<std::string>(0).c_str());
}

void run_ssl_init_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ssl_init_correct_initialization);
  RUN_TEST(test_ssl_init_mbedtls_functions_called);
  RUN_TEST(test_ssl_init_mbedtls_functions_called);
  UNITY_END();
}

/* test data_to_read function */

void test_data_to_read_success() {
  // Arrange
  mbedtls_ssl_read_stub.returns("mbedtls_ssl_read", 5);
  mbedtls_ssl_get_bytes_avail_stub.returns("mbedtls_ssl_get_bytes_avail", (size_t)5);
  
  // Act
  int result = data_to_read(testContext);
  
  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 2);
  TEST_ASSERT_EQUAL(5, result); 
}

void test_data_to_read_edge_case() {
  // Arrange
  mbedtls_ssl_read_stub.returns("mbedtls_ssl_read", MBEDTLS_ERR_SSL_WANT_READ);
  mbedtls_ssl_get_bytes_avail_stub.returns("mbedtls_ssl_get_bytes_avail", (size_t)0);
  
  // Act
  int result = data_to_read(testContext);
  
  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 2);
  TEST_ASSERT_EQUAL(0, result);
}

void test_data_to_read_failure() {
  // Arrange
  mbedtls_ssl_read_stub.returns("mbedtls_ssl_read", MBEDTLS_ERR_NET_CONN_RESET);
  mbedtls_ssl_get_bytes_avail_stub.returns("mbedtls_ssl_get_bytes_avail", (size_t)0);
  
  // Act
  int result = data_to_read(testContext);
  
  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 2);
  TEST_ASSERT_EQUAL(-76, result);  // -0x004C = MBEDTLS_ERR_NET_CONN_RESET
}

void run_data_to_read_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_data_to_read_success);
  RUN_TEST(test_data_to_read_edge_case);
  RUN_TEST(test_data_to_read_failure);
  UNITY_END();
}

/* test log_failed_cert function */

void test_log_failed_cert_with_some_flags(void) {
    // Arrange
    int flags = MBEDTLS_X509_BADCERT_EXPIRED;
    
    // Act
    log_failed_cert(flags);
    
    // Assert
    TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
}

void test_log_failed_cert_with_null_flags(void) {
  // Arrange
  int flags = 0; 
  
  // Act
  log_failed_cert(flags);
  
  // Assert
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
}

void run_log_failed_cert_tests(void) {  
  UNITY_BEGIN();
  RUN_TEST(test_log_failed_cert_with_some_flags);
  RUN_TEST(test_log_failed_cert_with_null_flags);
  UNITY_END();
}

/* test cleanup function */

void test_cleanup_with_all_resources_initialized_and_no_error(void) {
  // Arrange
  bool ca_cert_initialized = true;
  bool client_cert_initialized = true;
  bool client_key_initialized = true;
  int ret = 0;

  // Act
  cleanup(testContext, ca_cert_initialized, client_cert_initialized, client_key_initialized, ret, NULL, NULL, NULL);
  
  // Assert
  TEST_ASSERT_TRUE(mbedtls_x509_crt_free_stub.timesCalled() == 2);
  TEST_ASSERT_TRUE(mbedtls_pk_free_stub.wasCalled());
  TEST_ASSERT_TRUE(log_d_stub.wasCalled());
}

void test_cleanup_with_some_resources_initialized_and_no_error(void) {
  // Arrange
  sslclient__context ssl_client;
  bool ca_cert_initialized = true;
  bool client_cert_initialized = false;
  bool client_key_initialized = true;
  int ret = 0;

  // Act
  cleanup(&ssl_client, ca_cert_initialized, client_cert_initialized, client_key_initialized, ret, NULL, NULL, NULL);
  
  // Assert
  TEST_ASSERT_TRUE(mbedtls_x509_crt_free_stub.timesCalled() == 1);
  TEST_ASSERT_TRUE(mbedtls_pk_free_stub.wasCalled());
  TEST_ASSERT_TRUE(log_d_stub.wasCalled());
}

void run_cleanup_tests() {
  UNITY_BEGIN();
  RUN_TEST(test_cleanup_with_all_resources_initialized_and_no_error);
  RUN_TEST(test_cleanup_with_some_resources_initialized_and_no_error);
  UNITY_END();
}

/* test start_ssl_client function */

void test_successful_ssl_client_start(void) {
  // Arrange
  testClient.reset();
  testContext->client = &testClient;
  testClient.returns("connect", (int)1);
  testContext->client = &testClient;
  const char *host = "example.com";
  uint32_t port = 443;
  int timeout = 1000;
  const char *rootCABuff = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  bool useRootCABundle = false;
  const char *cli_cert = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  const char *cli_key = "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----";
  const char *pskIdent = NULL;
  const char *psKey = NULL;
  
  mbedtls_ctr_drbg_seed_stub.returns("mbedtls_ctr_drbg_seed", 0);
  mbedtls_ssl_config_defaults_stub.returns("mbedtls_ssl_config_defaults", 0);
  mbedtls_x509_crt_parse_stub.returns("mbedtls_x509_crt_parse", 0);
  mbedtls_pk_parse_key_stub.returns("mbedtls_pk_parse_key", 0);
  mbedtls_ssl_conf_own_cert_stub.returns("mbedtls_ssl_conf_own_cert", 0);
  mbedtls_ssl_set_hostname_stub.returns("mbedtls_ssl_set_hostname", 0);
  mbedtls_ssl_setup_stub.returns("mbedtls_ssl_setup", 0);
  mbedtls_ssl_handshake_stub.returns("mbedtls_ssl_handshake", 0);
  mbedtls_ssl_get_record_expansion_stub.returns("mbedtls_ssl_get_record_expansion", 0);
  mbedtls_ssl_get_verify_result_stub.returns("mbedtls_ssl_get_verify_result", (uint32_t)0);

  // Act
  int result = start_ssl_client(testContext, host, port, timeout, rootCABuff, useRootCABundle, cli_cert, cli_key, pskIdent, psKey, false, nullptr);

  // Assert
  TEST_ASSERT_EQUAL(1, result);
}

void test_ssl_client_start_with_invalid_host(void) {
  // Arrange
  testClient.reset();
  testContext->client = &testClient;
  testClient.returns("connect", (int)0);
  const char *host = "example.com";
  uint32_t port = 443;
  int timeout = 1000;
  const char *rootCABuff = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  bool useRootCABundle = false;
  const char *cli_cert = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  const char *cli_key = "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----";
  const char *pskIdent = NULL;
  const char *psKey = NULL;

  // Act
  int result = start_ssl_client(testContext, "invalid_host", port, timeout, rootCABuff, useRootCABundle, cli_cert, cli_key, pskIdent, psKey, false, NULL);

  // Assert
  TEST_ASSERT_EQUAL(0, result);
}

void test_ssl_client_start_invalid_port(void) {
  // Arrange
  testClient.reset();
  testContext->client = &testClient;
  testClient.returns("connect", (int)0);
  const char *host = "example.com";
  int timeout = 1000;
  const char *rootCABuff = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  bool useRootCABundle = false;
  const char *cli_cert = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  const char *cli_key = "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----";
  const char *pskIdent = NULL;
  const char *psKey = NULL;
  uint32_t port = (uint32_t)432589743022453;
  
  // Act
  int result = start_ssl_client(testContext, host, port, timeout, rootCABuff, useRootCABundle, cli_cert, cli_key, pskIdent, psKey, false, nullptr);
  
  // Assert
  TEST_ASSERT_EQUAL(0, result);
}

void test_ssl_client_start_failed_tcp_connection(void) {
  // Arrange
  const char *host = "example.com";
  uint32_t port = 443;
  int timeout = 1000;
  const char *rootCABuff = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  bool useRootCABundle = false;
  const char *cli_cert = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  const char *cli_key = "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----";
  const char *pskIdent = NULL;
  const char *psKey = NULL;
  
  // Act - null testContext->client
  int result = start_ssl_client(testContext, host, port, timeout, rootCABuff, useRootCABundle, cli_cert, cli_key, pskIdent, psKey, false, nullptr);
  
  // Assert
  TEST_ASSERT_EQUAL(0, result);
}

void test_ssl_client_start_failed_ssl_tls_handshake(void) {
  // Arrange
  testClient.reset();
  testContext->client = &testClient;
  testClient.returns("connect", (int)1);
  testContext->client = &testClient;
  const char *host = "example.com";
  uint32_t port = 443;
  int timeout = 1000;
  const char *rootCABuff = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  bool useRootCABundle = false;
  const char *cli_cert = "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----";
  const char *cli_key = "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----";
  const char *pskIdent = NULL;
  const char *psKey = NULL;
  
  mbedtls_ctr_drbg_seed_stub.returns("mbedtls_ctr_drbg_seed", 0);
  mbedtls_ssl_config_defaults_stub.returns("mbedtls_ssl_config_defaults", 0);
  mbedtls_x509_crt_parse_stub.returns("mbedtls_x509_crt_parse", 0);
  mbedtls_pk_parse_key_stub.returns("mbedtls_pk_parse_key", 0);
  mbedtls_ssl_conf_own_cert_stub.returns("mbedtls_ssl_conf_own_cert", 0);
  mbedtls_ssl_set_hostname_stub.returns("mbedtls_ssl_set_hostname", 0);
  mbedtls_ssl_setup_stub.returns("mbedtls_ssl_setup", 0);
  mbedtls_ssl_handshake_stub.returns("mbedtls_ssl_handshake", -2);
  
  // Act
  int result = start_ssl_client(testContext, host, port, timeout, rootCABuff, useRootCABundle, cli_cert, cli_key, pskIdent, psKey, false, nullptr);
  
  // Assert
  TEST_ASSERT_EQUAL(0, result);
}

void run_start_ssl_client_tests() {
  UNITY_BEGIN();
  RUN_TEST(test_successful_ssl_client_start);
  RUN_TEST(test_ssl_client_start_with_invalid_host);
  RUN_TEST(test_ssl_client_start_invalid_port);
  RUN_TEST(test_ssl_client_start_failed_tcp_connection);
  RUN_TEST(test_ssl_client_start_failed_ssl_tls_handshake);
  UNITY_END();
}

/* test init_tcp_connection function */

void test_init_tcp_connection_SuccessfulConnection_ReturnsZero(void) {
  // Arrange
  testContext->client = &testClient;
  testClient.reset();
  testClient.returns("connect", (int)1);
  const char* host = "example.com";
  uint32_t port = 443;

  // Act
  int result = init_tcp_connection(testContext, host, port);

  // Assert
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(1, log_v_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_init_tcp_connection_NullClient_ReturnsMinusOne(void) {
  // Arrange
  const char* host = "example.com";
  uint32_t port = 443;
  testContext->client = nullptr;

  // Act
  int result = init_tcp_connection(testContext, host, port);

  // Assert
  TEST_ASSERT_FALSE(log_v_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(1, log_e_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(-1, result);
}

void test_init_tcp_connection_FailedConnection_ReturnsMinusTwo(void) {
  // Arrange
  testContext->client = &testClient;
  testClient.reset();
  testClient.returns("connect", (int)0);
  const char* host = "example.com";
  uint32_t port = 443;

  // Act
  int result = init_tcp_connection(testContext, host, port);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(1, log_e_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(-2, result);
}

void test_init_tcp_connection_EdgeCase_LargePortNumber_SuccessfulConnection(void) {
  // Arrange
  testContext->client = &testClient;
  testClient.reset();
  testClient.returns("connect", (int)1);
  const char* host = "example.com";
  uint32_t largePort = UINT32_MAX;

  // Act
  int result = init_tcp_connection(testContext, host, largePort);

  // Assert
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(1, log_v_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(0, result);
}

void run_init_tcp_connection_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_init_tcp_connection_SuccessfulConnection_ReturnsZero);
  RUN_TEST(test_init_tcp_connection_NullClient_ReturnsMinusOne);
  RUN_TEST(test_init_tcp_connection_FailedConnection_ReturnsMinusTwo);
  RUN_TEST(test_init_tcp_connection_EdgeCase_LargePortNumber_SuccessfulConnection);
  UNITY_END();
}

/* test seed_random_number_generator function */

void test_seed_random_number_generator_SuccessfulSeed_ReturnsZero(void) {
  // Arrange
  mbedtls_ctr_drbg_seed_stub.returns("mbedtls_ctr_drbg_seed", 0);

  // Act
  int result = seed_random_number_generator(testContext);

  // Assert
  TEST_ASSERT_EQUAL_INT(2, log_v_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_seed_random_number_generator_CtrDrbgSeedFails_ReturnsErrorCode(void) {
  // Arrange
  mbedtls_ctr_drbg_seed_stub.returns("mbedtls_ctr_drbg_seed", MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED);

  // Act
  int result = seed_random_number_generator(testContext);

  // Assert
  TEST_ASSERT_EQUAL_INT(2, log_v_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED, result);
}

void run_seed_random_number_generator_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_seed_random_number_generator_SuccessfulSeed_ReturnsZero);
  RUN_TEST(test_seed_random_number_generator_CtrDrbgSeedFails_ReturnsErrorCode);
  UNITY_END();
}

/* Test set_up_tls_defaults function */

void test_set_up_tls_defaults_SuccessfulSetup_ReturnsZero(void) {
  // Arrange
  mbedtls_ssl_config_defaults_stub.returns("mbedtls_ssl_config_defaults", 0);

  // Act
  int result = set_up_tls_defaults(testContext);

  // Assert
  TEST_ASSERT_EQUAL_INT(1, log_v_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_set_up_tls_defaults_FailedSetup_ReturnsErrorCode(void) {
  // Arrange
  mbedtls_ssl_config_defaults_stub.returns("mbedtls_ssl_config_defaults", -1);

  // Act
  int result = set_up_tls_defaults(testContext);

  // Assert
  TEST_ASSERT_EQUAL_INT(1, log_v_stub.timesCalled());
  TEST_ASSERT_EQUAL_INT(-1, result);
}

void run_set_up_tls_defaults_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_set_up_tls_defaults_SuccessfulSetup_ReturnsZero);
  RUN_TEST(test_set_up_tls_defaults_FailedSetup_ReturnsErrorCode);
  UNITY_END();
} 

/* test stop_ssl_socket function */

void test_stop_ssl_socket_success(void) {
  // Arrange
  test_client_stop_stub.reset();
  ssl_init(testContext, &testClient);
  setup_stop_ssl_socket(testContext, &testClient);
  log_d_stub.reset();
  
  // Act
  stop_ssl_socket(testContext, "rootCABuff_example", "cli_cert_example", "cli_key_example");

  // Assert
  TEST_ASSERT_TRUE(test_client_stop_stub.wasCalled());
  TEST_ASSERT_TRUE(log_d_stub.timesCalled() == 9);
  TEST_ASSERT_TRUE(mbedtls_x509_crt_free_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_pk_free_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_ssl_free_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_ssl_config_free_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_ctr_drbg_free_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_entropy_free_stub.wasCalled());
}

void test_stop_ssl_socket_edge_null_pointers(void) {
  // Arrange
  test_client_stop_stub.reset();
  ssl_init(testContext, &testClient);
  log_d_stub.reset();

  // Act
  stop_ssl_socket(testContext, "rootCABuff_example", "cli_cert_example", "cli_key_example");

  // Assert
  TEST_ASSERT_TRUE(test_client_stop_stub.wasCalled());
  TEST_ASSERT_TRUE(log_d_stub.timesCalled() == 7);
  TEST_ASSERT_FALSE(mbedtls_x509_crt_free_stub.wasCalled());
  TEST_ASSERT_FALSE(mbedtls_pk_free_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_ssl_free_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_ssl_config_free_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_ctr_drbg_free_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_entropy_free_stub.wasCalled());
}

void test_stop_ssl_socket_failure_will_not_double_free(void) {
  // Arrange
  test_client_stop_stub.reset();
  ssl_init(testContext, &testClient);
  testContext->client = NULL;
  log_d_stub.reset();

  // Act
  stop_ssl_socket(testContext, "rootCABuff_example", "cli_cert_example", "cli_key_example");

  // Assert
  TEST_ASSERT_FALSE(test_client_stop_stub.wasCalled());
}

void run_stop_ssl_socket_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_stop_ssl_socket_success);
  RUN_TEST(test_stop_ssl_socket_edge_null_pointers);
  RUN_TEST(test_stop_ssl_socket_failure_will_not_double_free);
  UNITY_END();
}

/* test send_ssl_data function */

void test_send_ssl_data_successful_write(void) {
  // Arrange
  testContext->client = &testClient;
  testContext->handshake_timeout = 100;
  const uint8_t data[] = "test_data";
  int len = sizeof(data) - 1; // Excluding null terminator
  mbedtls_ssl_write_stub.returns("mbedtls_ssl_write", len);

  // Act
  int ret = send_ssl_data(testContext, data, len);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 4);
  TEST_ASSERT_TRUE(mbedtls_ssl_write_stub.wasCalled());
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(len, ret);
}

void test_send_ssl_data_want_write_then_success(void) {
  // Arrange
  testContext->client = &testClient;
  testContext->handshake_timeout = 100;
  const uint8_t data[] = "test_data";
  int len = sizeof(data) - 1; // Excluding null terminator

  // First two calls to mbedtls_ssl_write will return WANT_WRITE, then it will succeed
  mbedtls_ssl_write_stub.returns("mbedtls_ssl_write", MBEDTLS_ERR_SSL_WANT_WRITE)
    .then(MBEDTLS_ERR_SSL_WANT_WRITE)
    .then(len);

  // Act
  int ret = send_ssl_data(testContext, data, len);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 4);
  TEST_ASSERT_TRUE(mbedtls_ssl_write_stub.wasCalled());
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(len, ret);
}

void test_send_ssl_data_null_context(void) {
  // Act
  int ret = send_ssl_data(NULL, NULL, 0);

  // Assert
  TEST_ASSERT_FALSE(log_v_stub.wasCalled());
  TEST_ASSERT_TRUE(mbedtls_ssl_write_stub.timesCalled() == 0);
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
  TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_send_ssl_data_mbedtls_failure(void) {
  // Arrange
  testContext->client = &testClient;
  testContext->handshake_timeout = 100;
  const uint8_t data[] = "test_data";
  int len = sizeof(data) - 1; // Excluding null terminator
  mbedtls_ssl_write_stub.returns("mbedtls_ssl_write", MBEDTLS_ERR_SSL_ALLOC_FAILED);

  // Act
  int ret = send_ssl_data(testContext, data, len);

  // Assert
  TEST_ASSERT_TRUE(ret < 0);
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 3);
  TEST_ASSERT_TRUE(mbedtls_ssl_write_stub.wasCalled());
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
}

void test_send_ssl_data_zero_length(void) {
  // Arrange
  testContext->client = &testClient;
  testContext->handshake_timeout = 100;
  const uint8_t data[] = "test_data";
  mbedtls_ssl_write_stub.returns("mbedtls_ssl_write", 0);

  // Act
  int ret = send_ssl_data(testContext, data, 0);

  // Assert
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_TRUE(mbedtls_ssl_write_stub.wasCalled());
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 3);
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
}

void test_send_ssl_data_want_read_then_success(void) {
  // Arrange
  testContext->client = &testClient;
  testContext->handshake_timeout = 100;
  const uint8_t data[] = "test_data";
  int len = sizeof(data) - 1; // Excluding null terminator

  // First two calls to mbedtls_ssl_write will return WANT_READ, then it will succeed
  mbedtls_ssl_write_stub.returns("mbedtls_ssl_write", MBEDTLS_ERR_SSL_WANT_WRITE)
    .then(MBEDTLS_ERR_SSL_WANT_WRITE)
    .then(len);

  // Act
  int ret = send_ssl_data(testContext, data, len);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 4);
  TEST_ASSERT_TRUE(mbedtls_ssl_write_stub.wasCalled());
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(len, ret);
}

void run_send_ssl_data_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_send_ssl_data_successful_write);
  RUN_TEST(test_send_ssl_data_want_write_then_success);
  RUN_TEST(test_send_ssl_data_null_context);
  RUN_TEST(test_send_ssl_data_mbedtls_failure);
  RUN_TEST(test_send_ssl_data_zero_length);
  RUN_TEST(test_send_ssl_data_want_read_then_success);
  UNITY_END();
}

/* Test get_ssl_receive function */

void test_get_ssl_receive_success(void) {
  // Arrange
  unsigned char data[1024];
  mbedtls_ssl_read_stub.returns("mbedtls_ssl_read", 1024);

  // Act
  int result = get_ssl_receive(testContext, data, sizeof(data));

  // Assert
  TEST_ASSERT_EQUAL_INT(1024, result);
}

void test_get_ssl_receive_partial_read(void) {
  // Arrange
  unsigned char data[1024];
  mbedtls_ssl_read_stub.returns("mbedtls_ssl_read", 512);

  // Act
  int result = get_ssl_receive(testContext, data, sizeof(data));

  // Assert
  TEST_ASSERT_EQUAL_INT(512, result);
}

void test_get_ssl_receive_failure_bad_input(void) {
  // Arrange
  unsigned char data[1024];
  mbedtls_ssl_read_stub.returns("mbedtls_ssl_read", MBEDTLS_ERR_SSL_BAD_INPUT_DATA);

  // Act
  int result = get_ssl_receive(testContext, data, sizeof(data));

  // Assert
  TEST_ASSERT_EQUAL_INT(MBEDTLS_ERR_SSL_BAD_INPUT_DATA, result);
}

void test_get_ssl_receive_failed_alloc(void) {
  // Arrange
  unsigned char data[1024];
  mbedtls_ssl_read_stub.returns("mbedtls_ssl_read", MBEDTLS_ERR_SSL_ALLOC_FAILED);

  // Act
  int result = get_ssl_receive(testContext, data, sizeof(data));

  // Assert
  TEST_ASSERT_EQUAL_INT(MBEDTLS_ERR_SSL_ALLOC_FAILED, result);
}

void test_get_ssl_receive_zero_length(void) {
  // Arrange
  unsigned char data[1];
  mbedtls_ssl_read_stub.returns("mbedtls_ssl_read", 0);

  // Act
  int result = get_ssl_receive(testContext, data, 0);

  // Assert
  TEST_ASSERT_EQUAL_INT(0, result);
}

void run_get_ssl_receive_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_get_ssl_receive_success);
  RUN_TEST(test_get_ssl_receive_partial_read);
  RUN_TEST(test_get_ssl_receive_failure_bad_input);
  RUN_TEST(test_get_ssl_receive_failed_alloc);
  RUN_TEST(test_get_ssl_receive_zero_length);
  UNITY_END();
}

/* test parse_hex_nibble function */

void test_parse_hex_nibble_digit(void) {
  // Arrange
  uint8_t result;

  // Act
  bool success = parse_hex_nibble('5', &result);

  // Assert
  TEST_ASSERT_TRUE(success);
  TEST_ASSERT_EQUAL_UINT8(5, result);
}

void test_parse_hex_nibble_lowercase(void) {
  // Arrange
  uint8_t result;

  // Act
  bool success = parse_hex_nibble('b', &result);

  // Assert
  TEST_ASSERT_TRUE(success);
  TEST_ASSERT_EQUAL_UINT8(11, result);
}

void test_parse_hex_nibble_uppercase(void) {
  // Arrange
  uint8_t result;

  // Act
  bool success = parse_hex_nibble('D', &result);

  // Assert
  TEST_ASSERT_TRUE(success);
  TEST_ASSERT_EQUAL_UINT8(13, result);
}

void test_parse_hex_nibble_below_range(void) {
  // Arrange
  uint8_t result;

  // Act
  bool success = parse_hex_nibble('/', &result);

  // Assert
  TEST_ASSERT_FALSE(success);
}

void test_parse_hex_nibble_between_range(void) {
  // Arrange
  uint8_t result;

  // Act
  bool success = parse_hex_nibble('h', &result);

  // Assert
  TEST_ASSERT_FALSE(success);
}

void test_parse_hex_nibble_above_range(void) {
  // Arrange
  uint8_t result;

  // Act
  bool success = parse_hex_nibble('Z', &result);

  // Assert
  TEST_ASSERT_FALSE(success);
}

void test_parse_hex_nibble_edge_smallest(void) {
  // Arrange
  uint8_t result;

  // Act
  bool success = parse_hex_nibble('0', &result);

  // Assert
  TEST_ASSERT_TRUE(success);
  TEST_ASSERT_EQUAL_UINT8(0, result);
}

void test_parse_hex_nibble_edge_largest(void) {
  // Arrange
  uint8_t result;

  // Act
  bool success = parse_hex_nibble('f', &result);

  // Assert
  TEST_ASSERT_TRUE(success);
  TEST_ASSERT_EQUAL_UINT8(15, result);
}

void run_parse_hex_nibble_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_parse_hex_nibble_digit);
  RUN_TEST(test_parse_hex_nibble_lowercase);
  RUN_TEST(test_parse_hex_nibble_uppercase);
  RUN_TEST(test_parse_hex_nibble_below_range);
  RUN_TEST(test_parse_hex_nibble_between_range);
  RUN_TEST(test_parse_hex_nibble_above_range);
  RUN_TEST(test_parse_hex_nibble_edge_smallest);
  RUN_TEST(test_parse_hex_nibble_edge_largest);
  UNITY_END();
}

/* test match_name function */

void test_match_name_exact_match(void) {
  // Arrange
  string name = "example.com";
  string domainName = "example.com";

  // Act
  bool result = match_name(name, domainName);

  // Assert
  TEST_ASSERT_TRUE(result);
}

void test_match_name_simple_wildcard_match(void) {
  // Arrange
  string name = "*.example.com";
  string domainName = "test.example.com";

  // Act
  bool result = match_name(name, domainName);

  // Assert
  TEST_ASSERT_TRUE(result);
}

void test_match_name_exact_mismatch(void) {
  // Arrange
  string name = "example1.com";
  string domainName = "example2.com";

  // Act
  bool result = match_name(name, domainName);

  // Assert
  TEST_ASSERT_FALSE(result);
}

void test_match_name_wildcard_wrong_position(void) {
  // Arrange
  string name = "test.*.example.com";
  string domainName = "test.abc.example.com";

  // Act
  bool result = match_name(name, domainName);

  // Assert
  TEST_ASSERT_FALSE(result);
}

void test_match_name_wildcard_not_beginning(void) {
  // Arrange
  string name = "te*.example.com";
  string domainName = "test.example.com";

  // Act
  bool result = match_name(name, domainName);

  // Assert
  TEST_ASSERT_FALSE(result);
}

void test_match_name_wildcard_without_subdomain(void) {
  // Arrange
  string name = "*.example.com";
  string domainName = "example.com";

  // Act
  bool result = match_name(name, domainName);

  // Assert
  TEST_ASSERT_FALSE(result);
}

void run_match_name_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_match_name_exact_match);
  RUN_TEST(test_match_name_simple_wildcard_match);
  RUN_TEST(test_match_name_exact_mismatch);
  RUN_TEST(test_match_name_wildcard_wrong_position);
  RUN_TEST(test_match_name_wildcard_not_beginning);
  RUN_TEST(test_match_name_wildcard_without_subdomain);
  UNITY_END();
}

/* test verify_ssl_fingerprint function */

void test_verify_ssl_fingerprint_short_fp(void) {
  // Arrange
  const char* short_fp = "d83c1c1f57";

  // Act
  bool result = verify_ssl_fingerprint(testContext, short_fp, nullptr);

  // Assert
  TEST_ASSERT_FALSE(result);
}

void test_verify_ssl_fingerprint_invalid_format(void) {
  // Arrange
  const char* invalid_fp = "invalid_format_fp";

  // Act
  bool result = verify_ssl_fingerprint(testContext, invalid_fp, nullptr);

  // Assert
  TEST_ASSERT_FALSE(result);
}

void test_verify_ssl_fingerprint_invalid_hex_sequence(void) {
  // Arrange
  const char* invalid_hex = "d83c1c1f574fd9e75a7848ad8fb131302c31e224ad8c2617a9b3e24e81fc44ez"; // 'z' is not a valid hex character

  // Act
  bool result = verify_ssl_fingerprint(testContext, invalid_hex, nullptr);

  // Assert
  TEST_ASSERT_FALSE_MESSAGE(result, "Expected invalid hex sequence to fail.");
}

void test_verify_ssl_fingerprint_domain_fail(void) {
  // Arrange
  mbedtls_ssl_get_peer_cert_stub.returns("mbedtls_ssl_get_peer_cert", &dummy_cert);

  const char* test_fp = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  // Act
  bool result = verify_ssl_fingerprint(testContext, test_fp, "examplecom");

  // Assert
  TEST_ASSERT_FALSE(result);
}

void test_verify_ssl_fingerprint_no_peer_cert(void) {
  // Arrange
  mbedtls_ssl_get_peer_cert_stub.returns("mbedtls_ssl_get_peer_cert", &dummy_cert);
  const char* valid_fp = "d83c1c1f574fd9e75a7848ad8fb131302c31e224ad8c2617a9b3e24e81fc44e5";

  // Act
  bool result = verify_ssl_fingerprint(testContext, valid_fp, nullptr);

  // Assert
  TEST_ASSERT_FALSE(result);
}

void run_verify_ssl_fingerprint_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_verify_ssl_fingerprint_short_fp);
  RUN_TEST(test_verify_ssl_fingerprint_invalid_format);
  RUN_TEST(test_verify_ssl_fingerprint_invalid_hex_sequence);
  RUN_TEST(test_verify_ssl_fingerprint_domain_fail);
  RUN_TEST(test_verify_ssl_fingerprint_no_peer_cert);
  UNITY_END();
}

/* test verify_ssl_dn function */

void test_verify_ssl_dn_match_in_sans(void) {
  // Arrange
  std:string domainName = "example.com";
  mbedtls_ssl_get_peer_cert_stub.returns("mbedtls_ssl_get_peer_cert", &dummy_cert_with_san);

  // Act
  bool result = verify_ssl_dn(testContext, domainName.c_str());

  // Assert
  TEST_ASSERT_TRUE_MESSAGE(result, "Expected to match domain name in SANs.");
}

void test_verify_ssl_dn_match_in_cn(void) {
  // Arrange
  std:string domainName = "example.com";
  mbedtls_ssl_get_peer_cert_stub.returns("mbedtls_ssl_get_peer_cert", &dummy_cert_with_cn);

  // Act
  bool result = verify_ssl_dn(testContext, domainName.c_str());

  // Assert
  TEST_ASSERT_TRUE_MESSAGE(result, "Expected to match domain name in CN.");
}

void test_verify_ssl_dn_no_match(void) {
  // Arrange
  std:string domainName = "example.com";
  mbedtls_ssl_get_peer_cert_stub.returns("mbedtls_ssl_get_peer_cert", &dummy_cert_without_match);

  // Act
  bool result = verify_ssl_dn(testContext, domainName.c_str());

  // Assert
  TEST_ASSERT_FALSE_MESSAGE(result, "Expected no domain name match in both SANs and CN.");
}

void test_verify_ssl_dn_empty_domain_name(void) {
  // Arrange
  std::string emptyDomainName = "";
  mbedtls_ssl_get_peer_cert_stub.returns("mbedtls_ssl_get_peer_cert", &dummy_cert_without_match);

  // Act
  bool result = verify_ssl_dn(testContext, emptyDomainName.c_str());

  // Assert
  TEST_ASSERT_FALSE_MESSAGE(result, "Expected to fail with an empty domain name.");
}

void test_verify_ssl_dn_no_peer_cert(void) {
  // Arrange
  std:string domainName = "example.com";
  mbedtls_ssl_get_peer_cert_stub.returns("mbedtls_ssl_get_peer_cert", &dummy_cert);

  // Act
  bool result = verify_ssl_dn(testContext, domainName.c_str());

  // Assert
  TEST_ASSERT_FALSE_MESSAGE(result, "Expected to fail when no peer certificate is found.");
}

void run_verify_ssl_dn_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_verify_ssl_dn_match_in_sans);
  RUN_TEST(test_verify_ssl_dn_match_in_cn);
  RUN_TEST(test_verify_ssl_dn_no_match);
  RUN_TEST(test_verify_ssl_dn_empty_domain_name);
  RUN_TEST(test_verify_ssl_dn_no_peer_cert);
  UNITY_END();
}

/* test auth_root_ca_buff function */

// TODO test insecure mode on
// TODO test rootCaBundle success
// TODO test rootCaBundle failure
// TODO test rootCaBundle edge
void test_auth_root_ca_buff_success(void) {
  // Arrange
  const char *valid_ca_buff = "<valid certificate buffer>";
  bool ca_cert_initialized = false;
  mbedtls_x509_crt_parse_stub.returns("mbedtls_x509_crt_parse", 0);

  // Act
  int result = auth_root_ca_buff(testContext, valid_ca_buff, &ca_cert_initialized, NULL, NULL, false);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, result, "Expected successful configuration.");
}

void test_auth_root_ca_buff_failure(void) {
  // Arrange
  const char *invalid_ca_buff = "<invalid certificate buffer>";
  bool ca_cert_initialized = false;
  mbedtls_x509_crt_parse_stub.returns("mbedtls_x509_crt_parse", MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE);

  // Act
  int result = auth_root_ca_buff(testContext, invalid_ca_buff, &ca_cert_initialized, NULL, NULL, false);

  // Assert
  TEST_ASSERT_EQUAL_INT_MESSAGE(MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE, result, "Expected failure in configuration.");
}

void test_auth_root_ca_buff_edge(void) {
  // Arrange
  int returnVal = -1;

  // Act
  int result = auth_root_ca_buff(testContext, NULL, NULL, "<pskIdent>", "<psKey>", false);

  // Assert
  TEST_ASSERT_EQUAL_INT(returnVal, result);
}

void test_auth_root_ca_buff_null_ssl_client(void) {
  // Arrange
  int func_ret = 0;
  int returnVal = -1;

  // Act
  int result = auth_root_ca_buff(NULL, NULL, NULL, NULL, NULL, true);

  // Assert
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 0);
  TEST_ASSERT_EQUAL_INT(returnVal, result);
}

void test_auth_root_ca_buff_invalid_ca_valid_psk(void) {
  // Arrange
  const char *invalid_ca_buff = "<invalid certificate buffer>";
  const char *valid_pskIdent = "<valid psk identity>";
  const char *valid_psKey = "<valid psk key>";
  bool ca_cert_initialized = false;
  mbedtls_x509_crt_parse_stub.returns("mbedtls_x509_crt_parse", MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE);

  // Act
  int result = auth_root_ca_buff(testContext, invalid_ca_buff, &ca_cert_initialized, valid_pskIdent, valid_psKey, false);

  // Assert
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 0);
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 1);
  TEST_ASSERT_EQUAL_INT(MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE, result);
}

void test_auth_root_ca_buff_valid_ca_valid_psk(void) {
  // Arrange
  const char *valid_ca_buff = "<valid certificate buffer>";
  const char *valid_pskIdent = "<valid psk identity>";
  const char *valid_psKey = "<valid psk key>";
  int returnVal = -1;

  // Act
  int result = auth_root_ca_buff(testContext, valid_ca_buff, NULL, valid_pskIdent, valid_psKey, false);

  // Assert
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 1);
  TEST_ASSERT_EQUAL_INT(returnVal, result);
}

void test_auth_root_ca_buff_long_psk(void) {
  // Arrange
  const char *long_psKey = "<very long psk key>";

  // Act
  int result = auth_root_ca_buff(testContext, NULL, NULL, "<valid psk identity>", long_psKey, false);

  // Assert
  TEST_ASSERT_EQUAL_INT(-1, result);
}

void test_auth_root_ca_buff_malformed_psk(void) {
  // Arrange
  const char *malformed_psKey = "<malformed psk key>";

  // Act
  int result = auth_root_ca_buff(testContext, NULL, NULL, "<valid psk identity>", malformed_psKey, false);

  // Assert
  TEST_ASSERT_EQUAL_INT(-1, result);
}

void run_auth_root_ca_buff_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_auth_root_ca_buff_success);
  RUN_TEST(test_auth_root_ca_buff_failure);
  RUN_TEST(test_auth_root_ca_buff_edge);
  RUN_TEST(test_auth_root_ca_buff_null_ssl_client);
  RUN_TEST(test_auth_root_ca_buff_invalid_ca_valid_psk);
  RUN_TEST(test_auth_root_ca_buff_valid_ca_valid_psk);
  RUN_TEST(test_auth_root_ca_buff_long_psk);
  RUN_TEST(test_auth_root_ca_buff_malformed_psk);
  UNITY_END();
}

/* test auth_client_cert_key function */

void test_auth_client_cert_key_both_null() {
  // Arrange / Act
  int result = auth_client_cert_key(testContext, NULL, NULL, nullptr, nullptr);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_auth_client_cert_key_cert_null() {
  // Arrange / Act
  int result = auth_client_cert_key(testContext, NULL, "<valid_key>", nullptr, nullptr);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_auth_client_cert_key_key_null() {
  // Arrange / Act
  int result = auth_client_cert_key(testContext, "<valid_cert>", NULL, nullptr, nullptr);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_auth_client_cert_key_valid() {
  // Arrange
  mbedtls_x509_crt_parse_stub.returns("mbedtls_x509_crt_parse", 0);
  bool cert_init = false, key_init = false;

  // Act
  int result = auth_client_cert_key(testContext, "<valid_cert>", "<valid_key>", &cert_init, &key_init);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_TRUE(cert_init);
  TEST_ASSERT_TRUE(key_init);
}

void test_auth_client_cert_key_invalid_cert() {
  // Arrange
  mbedtls_x509_crt_parse_stub.returns("mbedtls_x509_crt_parse", MBEDTLS_X509_BADCERT_NOT_TRUSTED);
  bool cert_init = false, key_init = false;

  // Act
  int result = auth_client_cert_key(testContext, "<invalid_cert>", "<valid_key>", &cert_init, &key_init);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(MBEDTLS_X509_BADCERT_NOT_TRUSTED, result);
  TEST_ASSERT_FALSE(cert_init);
}

void test_auth_client_cert_key_invalid_key() {
  // Arrange
  mbedtls_x509_crt_parse_stub.returns("mbedtls_x509_crt_parse", MBEDTLS_X509_BADCERT_NOT_TRUSTED);
  bool cert_init = false, key_init = false;

  // Act
  int result = auth_client_cert_key(testContext, "<valid_cert>", "<invalid_key>", &cert_init, &key_init);
  
  // Assert
  TEST_ASSERT_EQUAL_INT(MBEDTLS_X509_BADCERT_NOT_TRUSTED, result);
  TEST_ASSERT_FALSE(key_init);
}

void run_auth_client_cert_key_tests(void) {
  UNITY_BEGIN();
  RUN_TEST(test_auth_client_cert_key_both_null);
  RUN_TEST(test_auth_client_cert_key_cert_null);
  RUN_TEST(test_auth_client_cert_key_key_null);
  RUN_TEST(test_auth_client_cert_key_valid);
  RUN_TEST(test_auth_client_cert_key_invalid_cert);
  RUN_TEST(test_auth_client_cert_key_invalid_key);
  UNITY_END();
}

/* test set_hostname_for_tls function */

void test_set_hostname_for_tls_success(void) {
  // Arrange
  const char *host = "example.com";
  mbedtls_ssl_set_hostname_stub.returns("mbedtls_ssl_set_hostname", 0);
  mbedtls_ssl_setup_stub.returns("mbedtls_ssl_setup", 0);

  // Act
  int result = set_hostname_for_tls(testContext, host);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.wasCalled());
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_set_hostname_for_tls_null_host(void) {
  // Arrange
  mbedtls_ssl_set_hostname_stub.returns("mbedtls_ssl_set_hostname", MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
  const char *host = NULL;

  // Act
  int result = set_hostname_for_tls(testContext, host);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.wasCalled());
  TEST_ASSERT_TRUE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(MBEDTLS_ERR_SSL_BAD_INPUT_DATA, result);
}

void test_set_hostname_for_tls_empty_host(void) {
  // Arrange
  mbedtls_ssl_set_hostname_stub.returns("mbedtls_ssl_set_hostname", MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
  const char *host = "";

  // Act
  int result = set_hostname_for_tls(testContext, host);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.wasCalled());
  TEST_ASSERT_TRUE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(MBEDTLS_ERR_SSL_BAD_INPUT_DATA, result);
}

void test_set_hostname_for_tls_alloc_failed(void) {
  // Arrange
  mbedtls_ssl_set_hostname_stub.returns("mbedtls_ssl_set_hostname", MBEDTLS_ERR_SSL_ALLOC_FAILED);
  const char *host = "example.com";

  // Act
  int result = set_hostname_for_tls(testContext, host);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.wasCalled());
  TEST_ASSERT_TRUE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(MBEDTLS_ERR_SSL_ALLOC_FAILED, result);
}

void test_set_hostname_for_tls_ssl_setup_failed(void) {
  // Arrange
  mbedtls_ssl_set_hostname_stub.returns("mbedtls_ssl_set_hostname", 0);
  mbedtls_ssl_setup_stub.returns("mbedtls_ssl_setup", MBEDTLS_ERR_SSL_ALLOC_FAILED);
  const char *host = "example.com";

  // Act
  int result = set_hostname_for_tls(testContext, host);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.wasCalled());
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 0);
  TEST_ASSERT_EQUAL_INT(MBEDTLS_ERR_SSL_ALLOC_FAILED, result);
}

void run_set_hostname_for_tls_tests() {
  UNITY_BEGIN();
  RUN_TEST(test_set_hostname_for_tls_success);
  RUN_TEST(test_set_hostname_for_tls_null_host);
  RUN_TEST(test_set_hostname_for_tls_empty_host);
  RUN_TEST(test_set_hostname_for_tls_alloc_failed);
  RUN_TEST(test_set_hostname_for_tls_ssl_setup_failed);
  UNITY_END();
}

/* test set_io_callbacks function */

void test_set_io_callbacks_and_timeout_success(void) {
  // Arrange
  int successfulReturn = 0;

  // Act
  int result = set_io_callbacks_and_timeout(testContext, 5000);

  // Assert
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 2);
  TEST_ASSERT_EQUAL_INT(successfulReturn, result);
}

void test_set_io_callbacks_and_timeout_zero_timeout(void) {
  // Arrange
  int successfulReturn = 0;

  // Act
  int result = set_io_callbacks_and_timeout(testContext, 0);

  // Assert
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 2);
  TEST_ASSERT_EQUAL_INT(successfulReturn, result);
}

void test_set_io_callbacks_and_timeout_negative_timeout(void) {
  // Arrange
  int failedReturn = -2;

  // Act
  int result = set_io_callbacks_and_timeout(testContext, -5000);

  // Assert
  TEST_ASSERT_FALSE(log_v_stub.wasCalled());
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
  TEST_ASSERT_EQUAL_INT(failedReturn, result);
}

void test_set_io_callbacks_and_timeout_null_context(void) {
  // Arrange
  int failedReturn = -1;

  // Act
  int result = set_io_callbacks_and_timeout(NULL, 5000);

  // Assert
  TEST_ASSERT_EQUAL_INT(failedReturn, result);
}

void test_set_io_callbacks_and_timeout_large_timeout(void) {
  // Arrange
  int successfulReturn = 0;

  // Act
  int result = set_io_callbacks_and_timeout(testContext, INT_MAX);


  // Assert
  TEST_ASSERT_EQUAL_INT(0, result);
}

void run_set_io_callbacks_tests() {
  UNITY_BEGIN();
  RUN_TEST(test_set_io_callbacks_and_timeout_success);
  RUN_TEST(test_set_io_callbacks_and_timeout_zero_timeout);
  RUN_TEST(test_set_io_callbacks_and_timeout_negative_timeout);
  // RUN_TEST(test_set_io_callbacks_and_timeout_null_context);
  RUN_TEST(test_set_io_callbacks_and_timeout_large_timeout);
  UNITY_END();
}

/* test perform_ssl_handshake function */

void test_perform_ssl_handshake_success(void) {
  // Arrange
  const char *cli_cert = NULL;
  const char *cli_key = NULL;
  mbedtls_ssl_handshake_stub.returns("mbedtls_ssl_handshake", 0);

  // Act
  int result = perform_ssl_handshake(testContext, cli_cert, cli_key);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 1);
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_perform_ssl_handshake_timeout(void) {
  // Arrange
  const char *cli_cert = NULL;
  const char *cli_key = NULL;
  testContext->handshake_timeout = 1;
  mbedtls_ssl_handshake_stub.returns("mbedtls_ssl_handshake", MBEDTLS_ERR_SSL_WANT_READ);

  // Act
  int result = perform_ssl_handshake(testContext, cli_cert, cli_key);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 1);
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
  TEST_ASSERT_EQUAL_INT(-1, result);
}

void test_perform_ssl_handshake_cert_key_provided(void) {
  // Arrange
  const char *cli_cert = "dummy_cert";
  const char *cli_key = "dummy_key";
  mbedtls_ssl_handshake_stub.returns("mbedtls_ssl_handshake", 0);
  mbedtls_ssl_get_record_expansion_stub.returns("mbedtls_ssl_get_record_expansion", 0);

  // Act
  int result = perform_ssl_handshake(testContext, cli_cert, cli_key);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 1);
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_TRUE(log_w_stub.timesCalled() == 0);
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_perform_ssl_handshake_null_context(void) {
  // Arrange
  const char *cli_cert = NULL;
  const char *cli_key = NULL;

  // Act
  int result = perform_ssl_handshake(NULL, cli_cert, cli_key);

  // Assert
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
  TEST_ASSERT_FALSE(log_v_stub.wasCalled());
  TEST_ASSERT_EQUAL(-1, result);
}

void test_perform_ssl_handshake_record_expansion_failure(void) {
  // Arrange
  const char *cli_cert = "dummy_cert";
  const char *cli_key = "dummy_key";
  mbedtls_ssl_handshake_stub.returns("mbedtls_ssl_handshake", 0);
  mbedtls_ssl_get_record_expansion_stub.returns("mbedtls_ssl_get_record_expansion", MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE);

  // Act
  int result = perform_ssl_handshake(testContext, cli_cert, cli_key);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 1);
  TEST_ASSERT_TRUE(log_w_stub.wasCalled());
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_EQUAL_INT(0, result);
}

void run_perform_ssl_handshake_tests() {
  UNITY_BEGIN();
  RUN_TEST(test_perform_ssl_handshake_success);
  RUN_TEST(test_perform_ssl_handshake_timeout);
  RUN_TEST(test_perform_ssl_handshake_cert_key_provided);
  RUN_TEST(test_perform_ssl_handshake_null_context);
  RUN_TEST(test_perform_ssl_handshake_record_expansion_failure);
  UNITY_END();
}

/* test verify_server_cert function */

void test_verify_server_cert_success(void) {
  // Arrange
  mbedtls_ssl_get_verify_result_stub.returns("mbedtls_ssl_get_verify_result", (uint32_t)0);

  // Act
  int result = verify_server_cert(testContext);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 1);
  TEST_ASSERT_EQUAL_INT(0, result);
}

void test_verify_server_cert_fail_handshake(void) {
  // Arrange
  mbedtls_ssl_get_verify_result_stub.returns("mbedtls_ssl_get_verify_result", (uint32_t)-1u);

  // Act
  uint32_t result = verify_server_cert(testContext);

  // Assert
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 1);
  TEST_ASSERT_EQUAL((uint32_t)-1u, result);
}

void test_verify_server_cert_null_context(void) {
  // Arrange / Act
  int result = verify_server_cert(NULL);

  // Assert
  TEST_ASSERT_FALSE(log_v_stub.wasCalled());
  TEST_ASSERT_TRUE(log_e_stub.timesCalled() == 1);
  TEST_ASSERT_EQUAL(-1, result);
}

void test_verify_server_cert_mismatched_cert_key(void) {
  // Arrange
  mbedtls_ssl_get_verify_result_stub.returns("mbedtls_ssl_get_verify_result", (uint32_t)MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);

  // Act
  uint32_t result = verify_server_cert(testContext);

  // Assert
  TEST_ASSERT_FALSE(log_e_stub.wasCalled());
  TEST_ASSERT_TRUE(log_v_stub.timesCalled() == 1);
  TEST_ASSERT_EQUAL((uint32_t)MBEDTLS_ERR_X509_CERT_VERIFY_FAILED, result);
}

void run_verify_server_cert_tests() {
  UNITY_BEGIN();
  RUN_TEST(test_verify_server_cert_success);
  RUN_TEST(test_verify_server_cert_fail_handshake);
  RUN_TEST(test_verify_server_cert_null_context);
  RUN_TEST(test_verify_server_cert_mismatched_cert_key);
  UNITY_END();
}

/* End of test functions */

#ifdef ARDUINO

#include <Arduino.h>

void setup() {
  run_all_tests();
}

void loop() {}

#else

int main(int argc, char **argv) {
  run_handle_error_tests();
  run_client_net_recv_tests();
  run_client_net_recv_timeout_tests();
  run_client_net_send_tests();
  run_ssl_init_tests();
  run_log_failed_cert_tests();
  run_cleanup_tests();
  run_start_ssl_client_tests();
  run_init_tcp_connection_tests();
  run_seed_random_number_generator_tests();
  run_set_up_tls_defaults_tests();
  run_auth_root_ca_buff_tests();
  run_auth_client_cert_key_tests();
  run_set_hostname_for_tls_tests();
  run_set_io_callbacks_tests();
  run_perform_ssl_handshake_tests();
  run_verify_server_cert_tests();
  run_stop_ssl_socket_tests();
  run_data_to_read_tests();
  run_send_ssl_data_tests();
  run_get_ssl_receive_tests();
  run_parse_hex_nibble_tests();
  run_match_name_tests();
  run_verify_ssl_fingerprint_tests(); // We are currently not testing the fingerprint verification
  run_verify_ssl_dn_tests();
  return 0;
}

#endif
