/**
 * @file log_.h
 * @brief Log levels and macros
 * @details This file contains the log levels and macros for logging.
 * These exist to enable the library to used in different environments,
 * namely the ESP-IDF and the Arduino framework.
 */
#ifndef LOG__H_
#define LOG__H_

#ifndef SSL_CLIENT_TEST_ENVIRONMENT

#include <Arduino.h>

#ifndef LOG_LEVEL_NONE
#define LOG_LEVEL_NONE 0
#endif

#ifndef LOG_LEVEL_ERROR
#define LOG_LEVEL_ERROR 1
#endif

#ifndef LOG_LEVEL_WARN
#define LOG_LEVEL_WARN 2
#endif

#ifndef LOG_LEVEL_INFO
#define LOG_LEVEL_INFO 3
#endif

#ifndef LOG_LEVEL_DEBUG
#define LOG_LEVEL_DEBUG 4
#endif

#ifndef LOG_LEVEL_VERBOSE
#define LOG_LEVEL_VERBOSE 5
#endif

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_VERBOSE  // Change this to set the log level
#endif

#ifndef log_e
#define log_e(...) if (LOG_LEVEL >= LOG_LEVEL_ERROR) { Serial.printf("E ("); Serial.printf(__VA_ARGS__); Serial.println(")"); }
#endif

#ifndef log_w
#define log_w(...) if (LOG_LEVEL >= LOG_LEVEL_WARN) { Serial.printf("W ("); Serial.printf(__VA_ARGS__); Serial.println(")"); }
#endif

#ifndef log_i
#define log_i(...) if (LOG_LEVEL >= LOG_LEVEL_INFO) { Serial.printf("I ("); Serial.printf(__VA_ARGS__); Serial.println(")"); }
#endif

#ifndef log_d
#define log_d(...) if (LOG_LEVEL >= LOG_LEVEL_DEBUG) { Serial.printf("D ("); Serial.printf(__VA_ARGS__); Serial.println(")"); }
#endif

#ifndef log_v
#define log_v(...) if (LOG_LEVEL >= LOG_LEVEL_VERBOSE) { Serial.printf("V ("); Serial.printf(__VA_ARGS__); Serial.println(")"); }
#endif

#endif // SSL_CLIENT_TEST_ENVIRONMENT

#endif // LOG__H_