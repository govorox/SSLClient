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

// Additional library-only cap; the platform's logging level still applies.
// 0=off, 1=error, 2=warning, 3=info, 4=debug, 5=verbose.
#ifndef SSL_CLIENT_LOG_LEVEL
#define SSL_CLIENT_LOG_LEVEL 5
#endif

#define SSL_CLIENT_LOG_E(...) do { if (SSL_CLIENT_LOG_LEVEL >= 1) { log_e(__VA_ARGS__); } } while (0)
#define SSL_CLIENT_LOG_W(...) do { if (SSL_CLIENT_LOG_LEVEL >= 2) { log_w(__VA_ARGS__); } } while (0)
#define SSL_CLIENT_LOG_I(...) do { if (SSL_CLIENT_LOG_LEVEL >= 3) { log_i(__VA_ARGS__); } } while (0)
#define SSL_CLIENT_LOG_D(...) do { if (SSL_CLIENT_LOG_LEVEL >= 4) { log_d(__VA_ARGS__); } } while (0)
#define SSL_CLIENT_LOG_V(...) do { if (SSL_CLIENT_LOG_LEVEL >= 5) { log_v(__VA_ARGS__); } } while (0)

#endif // LOG__H_
