#ifndef TESTCLIENT_H
#define TESTCLIENT_H

#include "Client.h"
#include "emulator.h"

class TestClient : public Client, public Emulator {
public:
    int connect(IPAddress ip, uint16_t port) override {
        // Dummy implementation
        return 1; // 1 means successful connection, you can change based on test requirements.
    }

    int connect(const char *host, uint16_t port) override {
        // Dummy implementation
        return 1;
    }

    size_t write(uint8_t byte) override {
        // Dummy implementation
        return 1; // 1 byte written
    }

    size_t write(const uint8_t *buf, size_t size) override {
        // Dummy implementation
        return this->mock<size_t>("write");
    }

    int available() override {
        // Dummy implementation
        return 0; // No bytes available
    }

    int read() override {
        // Dummy implementation
        return -1; // -1 generally indicates no bytes available
    }

    int read(uint8_t *buf, size_t size) override {
        // Dummy implementation
        return 0; // No bytes read
    }

    int peek() override {
        // Dummy implementation
        return -1; // -1 generally indicates no bytes available
    }

    void flush() override {
        // Dummy implementation, does nothing
    }

    void stop() override {
        // Dummy implementation, does nothing
    }

    uint8_t connected() override {
        // Dummy implementation
        return this->mock<uint8_t>("connected");
    }

    operator bool() override {
        // Dummy implementation
        return true; // Always true for testing
    }
};

#endif // TESTCLIENT_H
