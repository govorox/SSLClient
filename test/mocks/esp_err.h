// Mock implementation of esp_err.h

#ifndef ESP_ERR_H
#define ESP_ERR_H

#include <stdint.h>

typedef int32_t esp_err_t;

#define ESP_OK          0
#define ESP_FAIL        -1

esp_err_t esp_function() {
    // Mock implementation
    return ESP_OK;
}

#endif // ESP_ERR_H