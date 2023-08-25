[![PlatformIO Registry](https://badges.registry.platformio.org/packages/digitaldragon/library/SSLClient.svg)](https://registry.platformio.org/libraries/digitaldragon/SSLClient)

![arduino-library-badge](https://www.ardu-badge.com/badge/GovoroxSSLClient.svg)   

[Arduino Libraries Log](https://downloads.arduino.cc/libraries/logs/github.com/govorox/SSLClient/)

### Now updated on PlatformIO registry as digitaldragon/SSLClient@1.1.2
### Updated on Arduino Libraries registry to digitaldragon/GovoroxSSLClient@1.1.2

# SSLClient Arduino library using *mbedtls* functions
The SSLClient class implements support for secure connections using TLS (SSL). It Provides a transparent SSL wrapper over existing transport object of a **Client** class.
Based on the [WiFiClientSecure](https://github.com/espressif/arduino-esp32/tree/master/libraries/WiFiClientSecure) for Arduino/ESP32.
Designed and tested on ESP32, but should be portable to other platforms.

Can be used to provide connectivity to AWS IoT via GSM client (for example **TinyGSM**)

Example usage:

```
TinyGsmClient transport(modem);
SSLClient secure(&transport);

...

// Configure certificates to be used
secure.setCACert(AWS_CERT_CA);
secure.setCertificate(AWS_CERT_CRT);
secure.setPrivateKey(AWS_CERT_PRIVATE);

...

// Establish a generic secure connection
// secure.connect(TLS_ENDPOINT, TLS_PORT);

// or connect to the MQTT broker on the AWS endpoint
MQTTClient mqtt = MQTTClient(256);
mqtt.begin(AWS_IOT_ENDPOINT, 8883, secure);
  
```
# Code Standards

## Tests
- Should follow the AAA princple.   

## Layout
- Indentation=2 spaces.
- Generally all IF blocks, SWITCH statements and LOOPS to have a line break above and below to add visibility to flow control.  
- IF statements to be written correctly with curly braces although inline IF statements are permitted.  
  
## Logging
- Log levels inside a library `verbose`, `debug`, `warning`, `error`  

## Firmware Development
- Simple control flow: no goto, setjump, longjump or recursion.  
  
- Limit all loops: set an upper limit for maximum number of iterations, set as an integer.  
  
- Do not use the Heap at all: heap and garbage collectors cannot be proven by a static code analyser. By not using heap and instead using the stack memory leaks are eliminated.  
    
- Limit function size: limit to max 60 lines and apply Single responsibility principle.  
  
- Practice Data hiding: declare variables at teh lowest scope required: reduces access, aids analysis and debugging.  
  
- Check all return values for non void functions: or cast to (void) otherwise a code review will throw it back as not correctly implemented.  
  
- Limit C preprocessor to simple declarations: why? "The C preprocessor is a poweful obfuscatino tool that can destroy code clarity and beffudle text based code checkers".  
	- expecially when conditional create more compilation targets - which then require testing. This makes code harder to scale.  
  
- Restrict pointer use: never dereference more than one layer at a time. Limit use of function pointer at all as this makes the flow control graph for programs less clear and much harder to statically analyse.  
  
- Be Pedantic!: gcc -Wall -Werror -Wpedantic  
  
- Test Test Test: using different analysers with different rule sets.
