SSL Client Updates:

1. Added some commits of WifiSecureClient to fix some bugs.
2. Change send_ssl_data to use size_t instead of uint16_t - Commit a299ddc
3. ssl_client.cpp: Fix parameter name in _handle_error - commit : 39155e7
4. Fix memory leaks when SSL/TLS connection fails, Commit : f29f448
5. Fix buffer issue when writing data larger than receiving buffer, Commit: 4ce6c5f
6. Fix issue where client read timeout value not being set, Commit: 59ae9f0
7. Add clarity to return values for start_ssl_client and fix early termination of ssl client, Commit: cc40266
8. Close issue [#30](https://github.com/govorox/SSLClient/issues/30), Commit: e426936
9. Separate concerns from start_ssl_client into singly responsible functions and unit test private API, commit: 0f1fa36