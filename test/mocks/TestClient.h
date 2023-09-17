#ifndef TESTCLIENT_H
#define TESTCLIENT_H

#include "Client.h"
#include "Emulator.h"

class TestClient : public Client, public Emulator {
public:
  int connect(IPAddress ip, uint16_t port) override {
    return 1; // 1 means successful connection, you can change based on test requirements.
  }

  int connect(const char *host, uint16_t port) override {
    return 1;
  }

  size_t write(uint8_t byte) override {
    return 1; // 1 byte written
  }

  size_t write(const uint8_t *buf, size_t size) override {
    return this->mock<size_t>("write");
  }

  int available() override {
    return 0; // No bytes available
  }

  int read() override {
    return -1; // -1 generally indicates no bytes available
  }

  int read(uint8_t *buf, size_t size) override {
    return 0; // No bytes read
  }

  int peek() override {
    return -1; // -1 generally indicates no bytes available
  }

  void flush() override {}

  void stop() override {}

  uint8_t connected() override {
    return this->mock<uint8_t>("connected");
  }

  operator bool() override {
    return true; // Always true for testing
  }
};

#endif // TESTCLIENT_H
