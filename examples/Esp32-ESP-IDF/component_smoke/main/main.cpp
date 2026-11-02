#include <Arduino.h>
#include <WiFiClient.h>
#include <SSLClient.h>

extern "C" void app_main() {
  initArduino();
  Serial.begin(115200);

  WiFiClient transport;
  SSLClient secure(&transport);
  secure.setTimeout(0);
  secure.setHandshakeTimeout(30);

  Serial.println("SSLClient Arduino-as-component smoke example linked.");
  Serial.println("No network connection or certificate validation attempted.");
}
