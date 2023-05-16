SSL Client V2.0.0 Updates:

1. Added some commits of WifiSecureClient to fix some bugs.
2. Change send_ssl_data to use size_t instead of uint16_t - Commit a299ddc
3. ssl_client.cpp: Fix parameter name in _handle_error - commit : 39155e7
4. Fix memory leaks when SSL/TLS connection fails, Commit : f29f448
