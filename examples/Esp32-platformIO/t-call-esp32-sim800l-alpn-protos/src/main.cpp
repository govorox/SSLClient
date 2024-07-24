#include <Arduino.h>
#include <SSLClient.h>
#include <ArduinoHttpClient.h>
#include "ca_cert.h"
#include <Wire.h>
#include <string>

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
#define serialMonitor Serial // Set serial for debug console (to the Serial Monitor)
#define serialModem Serial1 // Set serial for AT commands (to the SIM800 module)

// Configure TinyGSM library
#define TINY_GSM_MODEM_SIM800   // Modem is SIM800
#define TINY_GSM_RX_BUFFER 1024 // Set RX buffer to 1Kb
#include <TinyGsmClient.h>

// Your GPRS credentials (leave empty, if missing)
const char apn[] = "";          // Your APN
const char gprs_user[] = "";    // User
const char gprs_pass[] = "";    // Password
const char simPIN[] = "";       // SIM card PIN code, if any

const char hostname[] = "www.howsmyssl.com";
int port = 443;

const char *alpn_protos[] = { "h2", "http/1.1", NULL }; // Example list, preferring HTTP/2
// const char *alpn_protos[] = { "mqtt", NULL }; // Example list, preferring MQTT
// const char *alpn_protos[] = { "h2", NULL }; // Example list, preferring gRPC
// const char *alpn_protos[] = { "ssh", NULL }; // Example list, preferring SSH
// const char *alpn_protos[] = { "webrtc", NULL }; // Example list, preferring WebRTC

// Layers stack
TinyGsm modem(serialModem);
TinyGsmClient gsmTransportLayer(modem);
SSLClient securePresentationLayer(&gsmTransportLayer);
HttpClient httpClient = HttpClient(securePresentationLayer, hostname, port);

// Function prototypes
bool setupPMU();
void setupModem();


// To use this example ensure to obtain a valid root CA certificate and replace the content of the ca_cert.h file
// with the content of the root CA certificate in PEM format.


void setup() {
  serialMonitor.begin(115200);
  delay(100);

  if (!setupPMU()) {
    serialMonitor.println("Setting board power management error");
  }

  // Set SIM module baud rate and UART pins
  serialModem.begin(MODEM_UART_BAUD, SERIAL_8N1, MODEM_RX, MODEM_TX);

  // Add CA Certificate
  securePresentationLayer.setCACert(root_ca);

  // Set ALPN list
  securePresentationLayer.setAlpnProtocols(alpn_protos);

  // SIM modem initial setup
  setupModem();
}

void loop() {
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

  // Unlock your SIM card with a PIN if needed
  if (strlen(simPIN) && modem.getSimStatus() != 3) {
    modem.simUnlock(simPIN);
  }

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
  serialMonitor.print(apn);
  if (!modem.gprsConnect(apn, gprs_user, gprs_pass)) {
    serialMonitor.println(" fail");
    delay(10000);
    return;
  }
  digitalWrite(LED_PIN, HIGH);
  serialMonitor.println(" OK");

  // More info..
  Serial.println("");
  String ccid = modem.getSimCCID();
  Serial.println("CCID: " + ccid);
  String imei = modem.getIMEI();
  Serial.println("IMEI: " + imei);
  String cop = modem.getOperator();
  Serial.println("Operator: " + cop);
  IPAddress local = modem.localIP();
  Serial.println("Local IP: " + String(local));
  int csq = modem.getSignalQuality();
  Serial.println("Signal quality: " + String(csq));

  /// HTTP Test
  if (modem.isGprsConnected()) {
    Serial.println("");
    Serial.println("Making GET request");
    httpClient.get("/a/check");

    int status_code = httpClient.responseStatusCode();
    std::string response = httpClient.responseBody().c_str();

    Serial.print("Status code: ");
    Serial.println(status_code);
    Serial.print("Response: ");
    Serial.println(response.c_str());

    httpClient.stop();
  } else {
    Serial.println("...not connected");
  }

  // Disconnect GPRS
  modem.gprsDisconnect();
  serialMonitor.println("GPRS disconnected");
  digitalWrite(LED_PIN, LOW);

  //Turn off the modem (if use, you need run setupModem() again)
  //modem.poweroff();
  //serialMonitor.println("Modem poweroff");
  //delay(1000);
  //setupModem();

  delay(15000);
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
 * @brief Setup the SIM800L modem
 * @note This function is used to setup the SIM800L modem
 * from the power on state. It will pull down the PWRKEY
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
}
