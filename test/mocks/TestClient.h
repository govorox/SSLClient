#ifndef TESTCLIENT_H
#define TESTCLIENT_H

#include "Client.h"
#include "Emulator.h"
#include "FunctionEmulator.h"


FunctionEmulator test_client_stop_stub("TestClient::stop()");

class TestClient : public Client, public Emulator {
public:
  int connect(IPAddress ip, uint16_t port) override {
    return this->mock<int>("connect");
  }

  int connect(const char *host, uint16_t port) override {
    return this->mock<int>("connect");
  }

  size_t write(uint8_t byte) override {
    return this->mock<size_t>("write");
  }

  size_t write(const uint8_t *buf, size_t size) override {
    return this->mock<size_t>("write");
  }

  int available() override {
    return this->mock<int>("available");
  }

  int read() override {
    return this->mock<int>("read");
  }

  int read(uint8_t *buf, size_t size) override {
    return this->mock<int>("read");
  }

  int peek() override {
    return this->mock<int>("peek");
  }

  void flush() override {}

  void stop() override {
    test_client_stop_stub.recordFunctionCall();
  }

  uint8_t connected() override {
    return this->mock<uint8_t>("connected");
  }

  operator bool() override {
    return true; // Always true for testing
  }
};

#endif // TESTCLIENT_H
