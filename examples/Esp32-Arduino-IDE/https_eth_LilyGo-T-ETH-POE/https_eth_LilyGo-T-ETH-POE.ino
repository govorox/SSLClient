/**************************************************************
 *
 * ESP32 LilyGo-T-ETH-POE Example
 *
 * HTTPS (TLS/SLL) with CA Certificate via "ETH.h"
 * This example uses the WiFiClient class to integrate ETH functionality  
 *
 * About board:   https://github.com/Xinyuan-LilyGO/LilyGO-T-ETH-POE
 * Base example:  https://github.com/Xinyuan-LilyGO/LilyGO-T-ETH-POE/blob/master/example/eth/eth.ino
 * 
 **************************************************************/
// To make HTTP request easy: https://github.com/arduino-libraries/ArduinoHttpClient
#include <ArduinoHttpClient.h>
#include <ETH.h>
#include "WiFi.h"
#include "SSLClient.h"

// Please enter your CA certificate in ca_cert.h
#include "ca_cert.h"

// ESP32 LilyGo-T-ETH-POE Board Ethernet pins definition
#define ETH_CLK_MODE ETH_CLOCK_GPIO17_OUT
#define ETH_POWER_PIN -1
#define ETH_TYPE ETH_PHY_LAN8720
#define ETH_ADDR 1 // Update this according to the required value for v3.x.x and 0 for v2.x.x
#define ETH_MDC_PIN 23
#define ETH_MDIO_PIN 18

const char hostname[] = "www.howsmyssl.com";
int port = 443;

// Layers stack
WiFiClient eth_transport_layer;
SSLClient secure_presentation_layer(&eth_transport_layer);
HttpClient http_client = HttpClient(secure_presentation_layer, hostname, port);

static bool eth_connected = false;

// Ethernet events
#if ESP_ARDUINO_VERSION_MAJOR >= 3
void ETHEvent(WiFiEvent_t event, WiFiEventInfo_t info)
#else
void ETHEvent(WiFiEvent_t event)
#endif
{
  switch (event)
  {
  #if ESP_ARDUINO_VERSION_MAJOR >= 3
  case ARDUINO_EVENT_ETH_START:
  #else
  case SYSTEM_EVENT_ETH_START:
  #endif
    Serial.println("ETH Started");
    ETH.setHostname("esp32-ethernet");
    break;
  
  #if ESP_ARDUINO_VERSION_MAJOR >= 3
  case ARDUINO_EVENT_ETH_CONNECTED:
  #else
  case SYSTEM_EVENT_ETH_CONNECTED:
  #endif
    Serial.println("ETH Connected");
    break;
  
  #if ESP_ARDUINO_VERSION_MAJOR >= 3
  case ARDUINO_EVENT_ETH_GOT_IP:
  #else
  case SYSTEM_EVENT_ETH_GOT_IP:
  #endif
    Serial.print("ETH MAC: ");
    Serial.print(ETH.macAddress());
    Serial.print(", IPv4: ");
    Serial.print(ETH.localIP());
    if (ETH.fullDuplex())
    {
      Serial.print(", FULL_DUPLEX");
    }
    Serial.print(", ");
    Serial.print(ETH.linkSpeed());
    Serial.println("Mbps");
    eth_connected = true;
    break;

  #if ESP_ARDUINO_VERSION_MAJOR >= 3
  case ARDUINO_EVENT_ETH_DISCONNECTED:
  #else
  case SYSTEM_EVENT_ETH_DISCONNECTED:
  #endif
    Serial.println("ETH Disconnected");
    eth_connected = false;
    break;
  
  #if ESP_ARDUINO_VERSION_MAJOR >= 3
  case ARDUINO_EVENT_ETH_STOP:
  #else
  case SYSTEM_EVENT_ETH_STOP:
  #endif
    Serial.println("ETH Stopped");
    eth_connected = false;
    break;

  default:
    break;
  }
}

void setup()
{
  Serial.begin(9600);

  Serial.println("Starting ETH");
  WiFi.onEvent(ETHEvent);
  #if ESP_ARDUINO_VERSION_MAJOR >= 3
  ETH.begin(ETH_TYPE, ETH_ADDR, ETH_POWER_PIN, ETH_MDC_PIN, ETH_MDIO_PIN, ETH_CLK_MODE);
  #else
  ETH.begin(ETH_ADDR, ETH_POWER_PIN, ETH_MDC_PIN, ETH_MDIO_PIN, ETH_TYPE, ETH_CLK_MODE);
  #endif
  while (!eth_connected)
  {
    Serial.println("Connecting to ETH..");
    delay(1000);
  }
  Serial.println("Connected");

  // Add CA Certificate
  secure_presentation_layer.setCACert(root_ca);
}

void loop()
{
  Serial.println("Making GET request...");

  http_client.get("/a/check");

  int status_code = http_client.responseStatusCode();
  String response = http_client.responseBody();

  Serial.print("Status code: ");
  Serial.println(status_code);
  Serial.print("Response: ");
  Serial.println(response);

  http_client.stop();

  delay(5000);
}
