#include <Arduino.h>
#include <ArduinoHttpClient.h>
#include <PubSubClient.h>
#include <SSLClient.h>
#include <Wire.h>
#include <time.h>
#include <sys/time.h>
#include "ca_cert.h"

// Configure the SIM800L modem
#define MODEM_UART_BAUD 115200
#define MODEM_RST 5
#define MODEM_PWRKEY 4
#define MODEM_POWER_ON 23
#define MODEM_TX 27
#define MODEM_RX 26
#define I2C_SDA 21
#define I2C_SCL 22
#define LED_PIN 13
#define IP5306_ADDR 0x75
#define IP5306_REG_SYS_CTL0 0x00

// Configure the serial console for debug and the modem
#define serialMonitor Serial // Set serial for debug console (to the Serial Monitor)
#define serialModem Serial1 // Set serial for AT commands (to the SIM800 module)

// Configure TinyGSM library
#define TINY_GSM_MODEM_SIM800   // Modem is SIM800
#define TINY_GSM_RX_BUFFER 1024 // Set RX buffer to 1Kb
#include <TinyGsmClient.h>

// Configure the MQTT broker
#define MQTT_BROKER "AWS_BROKER_ENDPOINT" // e.g. a2l1dde17xdr1y-ats.iot.eu-west-1.amazonaws.com
#define MQTT_PORT 8883
#define MQTT_CLIENT_ID "SOMETHING_UNIQUE"
#define MQTT_TIMEOUT 15000 // Set timeout for SSL connection (in ms)

// Create the mqtt stack
TinyGsm modem(serialModem);
TinyGsmClient tcpClient(modem);
SSLClient ssl_client(&tcpClient);
PubSubClient mqttClient(ssl_client);

// Function prototypes

void nbConnect(void);
void callback(char *topic, byte *payload, unsigned int length);
void reconnect();
bool setupPMU();
void setupModem();
void setMQTTClientParams();
bool getIpAddress(const char* domain, char* ipAddress, size_t size);


// To use this example create your thing in AWS and get the certs downloaded. Be sure to update the ca_cert.h
// with the root CA, client certificate, and private key. The root CA is the Amazon Root CA 1.
// The client certificate and private key are the ones you downloaded from AWS IoT Core.
// The client certificate and private key are in PEM format.
// The root CA is in PEM format as well.


void setup() {
  serialMonitor.begin(115200);
  delay(100);

  if (!setupPMU()) {
    serialMonitor.println("Setting board power management error");
  }

  // Set SIM module baud rate and UART pins
  serialModem.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);
  setupModem();
  nbConnect();

  // Set the MQTT client parameters
  setMQTTClientParams();

  mqttClient.setServer(MQTT_BROKER, MQTT_PORT); 
  mqttClient.setCallback(callback);
}

void loop() {
  // We maintain connectivity with the broker
  if (!mqttClient.connected()) {
    reconnect();
  }
  // We are listening to the events
  mqttClient.loop();
  delay(10000);
}

/**
 * @brief Set the MQTT client parameters.
 * Sets the CA certificate, client certificate, and private key for the MQTT client.
 * Sets the timeout for the SSL connection.
 */
void setMQTTClientParams(void) {
  //log_i("root ca data: %s", root_ca);
  //log_i("certificate_data: %s", certificate_data);
  //log_i("privatekey_data: %s", privatekey_data);
  ssl_client.setCACert(root_ca);
  ssl_client.setCertificate(client_cert_pem);
  ssl_client.setPrivateKey(client_private_key_pem);
  ssl_client.setTimeout(MQTT_TIMEOUT);
}

/**
 * @brief Connect to the network and wait for the network to be available.
 */
void nbConnect() {
  unsigned long start = millis();
  log_i("Initializing modem...");
  while (!modem.init()) {
    log_i("waiting....%s", String((millis() - start) / 1000).c_str());
  };
  start = millis();
  log_i("Waiting for network...");
  while (!modem.waitForNetwork()) {
    log_i("waiting....%s", String((millis() - start) / 1000).c_str());
  }
  log_i("success");
}

/**
 * @brief Callback function for the MQTT client.
 * 
 * @param topic  
 * @param payload 
 * @param length 
 */
void callback(char *topic, byte *payload, unsigned int length) {
  Serial.print("Message arrived [");
  Serial.print(topic);
  Serial.print("] ");
  for (int i = 0; i < length; i++) {
    Serial.print((char)payload[i]);
  }
  Serial.println();
}

/**
 * @brief Stay connected to the MQTT broker
 */
void reconnect() {
  ssl_client.setCACert(root_ca);
  ssl_client.setCertificate(client_cert_pem);
  ssl_client.setPrivateKey(client_private_key_pem);
  ssl_client.setTimeout(MQTT_TIMEOUT);

  // Loop until we're reconnected
  while (!mqttClient.connected()) {
    Serial.println("Attempting MQTT connection...");
    // Attempt to connect
    if (mqttClient.connect(MQTT_CLIENT_ID)) {
    Serial.println("-----------------------------------connected-----------------------");
    mqttClient.subscribe("#");
    } else {
      Serial.print("failed, rc=");
      Serial.print(mqttClient.state());
      Serial.println("...try again in 5 seconds");
      delay(5000);
    }
  }
}

/**
 * @brief Setup the IP5306 PMU for the SIM800L board
 * Power configuration for SIM800L_IP5306_VERSION_20190610 (v1.3) board
 * 
 * @return true 
 * @return false 
 */
bool setupPMU() {
  bool en = true;
  Wire.begin(I2C_SDA, I2C_SCL);
  Wire.beginTransmission(IP5306_ADDR);
  Wire.write(IP5306_REG_SYS_CTL0);
  if (en) {
    Wire.write(0x37);
  } else {
    Wire.write(0x35);
  }
  return Wire.endTransmission() == 0;
}

/**
 * @brief Initialize the modem and connect to the network.
 * 
 */
void setupModem() {
  pinMode(MODEM_RST, OUTPUT);
  pinMode(MODEM_PWRKEY, OUTPUT);
  pinMode(MODEM_POWER_ON, OUTPUT);
  pinMode(LED_PIN, OUTPUT);

  // Reset pin high
  digitalWrite(MODEM_RST, HIGH);

  // Turn on the Modem power first
  digitalWrite(MODEM_POWER_ON, HIGH);

  // Pull down PWRKEY for more than 1 second according to manual requirements
  digitalWrite(MODEM_PWRKEY, HIGH);
  delay(200);
  digitalWrite(MODEM_PWRKEY, LOW);
  delay(1200);
  digitalWrite(MODEM_PWRKEY, HIGH);

  // Initialize the indicator as an output
  digitalWrite(LED_PIN, LOW);

  // Initialize modem
  serialMonitor.print("Initializing modem...");
  if (!modem.init()) {
    serialMonitor.print(" fail... restarting modem...");
    setupModem();
    // Restart takes quite some time
    // Use modem.init() if you don't need the complete restart
    if (!modem.restart()) {
      serialMonitor.println(" fail... even after restart");
      return;
    }
  }
  serialMonitor.println(" OK");

  // General information
  String name = modem.getModemName();
  Serial.println("Modem Name: " + name);
  String modem_info = modem.getModemInfo();
  Serial.println("Modem Info: " + modem_info);

  // Wait for network availability
  serialMonitor.print("Waiting for network...");
  if (!modem.waitForNetwork(240000L)) {
    serialMonitor.println(" fail");
    delay(10000);
    return;
  }
  serialMonitor.println(" OK");
  
  // Connect to the GPRS network
  serialMonitor.print("Connecting to network...");
  if (!modem.isNetworkConnected()) {
    serialMonitor.println(" fail");
    delay(10000);
    return;
  }
  serialMonitor.println(" OK");

  // Connect to APN
  serialMonitor.print(F("Connecting to APN: "));
  serialMonitor.print("giffgaff.com");
  if (!modem.gprsConnect("giffgaff.com", "gg", "p")) {
    serialMonitor.println(" fail");
    delay(10000);
    return;
  }
  digitalWrite(LED_PIN, HIGH);
  serialMonitor.println(" OK");

  // More info..
  serialMonitor.println("");
  String ccid = modem.getSimCCID();
  serialMonitor.println("CCID: " + ccid);
  String imei = modem.getIMEI();
  serialMonitor.println("IMEI: " + imei);
  String cop = modem.getOperator();
  serialMonitor.println("Operator: " + cop);
  IPAddress local = modem.localIP();
  serialMonitor.println("Local IP: " + String(local));
  int csq = modem.getSignalQuality();
  serialMonitor.println("Signal quality: " + String(csq));
  // Check for IP address
  modem.sendAT(GF("+CIFSR")); // Get local IP address

  char ipAddress[32];

  if (getIpAddress(MQTT_BROKER, ipAddress, sizeof(MQTT_BROKER))) {
      serialMonitor.print("IP Address for ");
      serialMonitor.print(MQTT_BROKER);
      serialMonitor.print(" is ");
      serialMonitor.println(ipAddress);
  } else {
      serialMonitor.println("Failed to retrieve IP address");
  }

  // If successful, close the TCP connection and proceed
  modem.sendAT(GF("+CIPCLOSE"));
  modem.waitResponse();

  serialMonitor.println("Modem initialized and server reachable.");
}

/**
 * @brief Get the Ip Address object
 * This is akin to the ping command in Linux,
 * it is good to check if the server is reachable.
 * 
 * @param domain  
 * @param ipAddress 
 * @param size  
 * @return true 
 * @return false 
 */
bool getIpAddress(const char* domain, char* ipAddress, size_t size) {
  char cmd[64];
  snprintf(cmd, sizeof(cmd), "+CDNSGIP=\"%s\"", domain);
  modem.sendAT(cmd);

  char response[128];
  unsigned long start = millis();
  bool gotResponse = false;

  while (millis() - start < 10000L) {
    if (modem.stream.available()) {
      size_t len = modem.stream.readBytesUntil('\n', response, sizeof(response) - 1);
      response[len] = '\0'; // Null-terminate the string
      if (strstr(response, "+CDNSGIP:")) {
        gotResponse = true;
        break;
      }
    }
  }

  if (gotResponse) {
    // Assuming the response format is +CDNSGIP: 1,"domain","IP1","IP2"
    char* startChar = strchr(response, '"');
    if (startChar != NULL) {
      startChar = strchr(startChar + 1, '"');
      if (startChar != NULL) {
        startChar = strchr(startChar + 1, '"');
        if (startChar != NULL) {
          char* endChar = strchr(startChar + 1, '"');
          if (endChar != NULL && endChar > startChar && (size_t)(endChar - startChar - 1) < size) {
            strncpy(ipAddress, startChar + 1, endChar - startChar - 1);
            ipAddress[endChar - startChar - 1] = '\0'; // Ensure null-termination
            return true;
          }
        }
      }
    }
  }

  ipAddress[0] = '\0'; // Ensure the buffer is set to empty string if no IP found
  return false;
}
