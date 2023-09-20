SSL Client Updates:

1. Added some commits of WifiSecureClient to fix some bugs.
2. Change send_ssl_data to use size_t instead of uint16_t - Commit a299ddc
3. ssl_client.cpp: Fix parameter name in _handle_error - commit : 39155e7
4. Fix memory leaks when SSL/TLS connection fails, Commit : f29f448
5. Fix buffer issue when writing data larger than receiving buffer, Commit: 4ce6c5f
6. Fix issue where client read timeout value not being set, Commit: 59ae9f0