/**************************************************************
 *
 * ESP32 LilyGo-T-Call-SIM800 Example
 *
 * HTTPS (TLS/SLL) with CA Certificate via "TinyGsm.h": https://github.com/vshymanskyy/TinyGSM
 * Tested on SIM800L_IP5306_VERSION_20190610 (v1.3) (R14.18)
 *
 * About board: https://github.com/Xinyuan-LilyGO/LilyGo-T-Call-SIM800
 * About SIM800L_IP5306 v1.3: https://github.com/Xinyuan-LilyGO/LilyGo-T-Call-SIM800/blob/master/doc/SIM800L_IP5306.MD    
 * Base example: https://github.com/Xinyuan-LilyGO/LilyGo-T-Call-SIM800/tree/master/examples/Arduino_TinyGSM  
 * 
 **************************************************************/
#include <Wire.h>
#include "SSLClient.h"
//To make http request esay: https://github.com/arduino-libraries/ArduinoHttpClient
#include <ArduinoHttpClient.h>

//Please enter your CA certificate in ca_cert.h
#include "ca_cert.h"

// ESP32 LilyGo-T-Call-SIM800 SIM800L_IP5306_VERSION_20190610 (v1.3) pins definition
#define MODEM_RST 5
#define MODEM_PWRKEY 4
#define MODEM_POWER_ON 23
#define MODEM_TX 27
#define MODEM_RX 26
#define I2C_SDA 21
#define I2C_SCL 22
#define LED_GPIO 13
#define LED_ON HIGH
#define LED_OFF LOW
#define IP5306_ADDR 0x75
#define IP5306_REG_SYS_CTL0 0x00

// Set serial for debug console (to the Serial Monitor)
#define SerialMon Serial
// Set serial for AT commands (to the SIM800 module)
#define SerialAT Serial1

// Configure TinyGSM library
#define TINY_GSM_MODEM_SIM800   // Modem is SIM800
#define TINY_GSM_RX_BUFFER 1024 // Set RX buffer to 1Kb

// Include after TinyGSM definitions
#include <TinyGsmClient.h>

// Your GPRS credentials (leave empty, if missing)
const char apn[] = "";       // Your APN
const char gprs_user[] = ""; // User
const char gprs_pass[] = ""; // Password
const char simPIN[] = "";    // SIM card PIN code, if any

const char hostname[] = "www.howsmyssl.com";
int port = 443;

//Layers stack
TinyGsm sim_modem(SerialAT);
TinyGsmClient gsm_transpor_layer(sim_modem);
SSLClient secure_presentation_layer(&gsm_transpor_layer);
HttpClient http_client = HttpClient(secure_presentation_layer, hostname, port);

// Power configuration for SIM800L_IP5306_VERSION_20190610 (v1.3) board
bool setupPMU()
{
  bool en = true;
  Wire.begin(I2C_SDA, I2C_SCL);
  Wire.beginTransmission(IP5306_ADDR);
  Wire.write(IP5306_REG_SYS_CTL0);
  if (en)
  {
    Wire.write(0x37);
  }
  else
  {
    Wire.write(0x35);
  }
  return Wire.endTransmission() == 0;
}

// Modem initial setup (cold start)
void setupModem()
{
  pinMode(MODEM_RST, OUTPUT);
  pinMode(MODEM_PWRKEY, OUTPUT);
  pinMode(MODEM_POWER_ON, OUTPUT);

  // Reset pin high
  digitalWrite(MODEM_RST, HIGH);

  // Turn on the Modem power first
  digitalWrite(MODEM_POWER_ON, HIGH);

  // Pull down PWRKEY for more than 1 second according to manual requirements
  digitalWrite(MODEM_PWRKEY, HIGH);
  delay(100);
  digitalWrite(MODEM_PWRKEY, LOW);
  delay(1000);
  digitalWrite(MODEM_PWRKEY, HIGH);

  // Initialize the indicator as an output
  pinMode(LED_GPIO, OUTPUT);
  digitalWrite(LED_GPIO, LED_OFF);
}

void setup()
{
  SerialMon.begin(9600);
  delay(10);

  // Start power management
  if (!setupPMU())
  {
    Serial.println("Setting power error");
  }

  //Add CA Certificate
  secure_presentation_layer.setCACert(root_ca);

  // Modem initial setup
  setupModem();

  // Set SIM module baud rate and UART pins
  SerialAT.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);
}

void loop()
{
  SerialMon.println("Initializing modem...");
  // Restart takes quite some time
  //modem.restart();
  // Use modem.init() if you don't need the complete restart
  sim_modem.init();

  // Get moden info
  String modem_info = sim_modem.getModemInfo();
  SerialMon.print("Modem: ");
  SerialMon.println(modem_info);

  // Unlock your SIM card with a PIN if needed
  if (strlen(simPIN) && sim_modem.getSimStatus() != 3)
  {
    sim_modem.simUnlock(simPIN);
  }

  // Wait for network availability
  SerialMon.print("Waiting for network...");
  if (!sim_modem.waitForNetwork(240000L))
  {
    SerialMon.println(" fail");
    delay(10000);
    return;
  }
  SerialMon.println(" OK");
  // Connect to the GPRS network
  if (sim_modem.isNetworkConnected())
  {
    SerialMon.println("GPRS Network connected");
  }
  digitalWrite(LED_GPIO, LED_ON);

  // Connect to APN
  SerialMon.print(F("Connecting to APN: "));
  SerialMon.print(apn);
  if (!sim_modem.gprsConnect(apn, gprs_user, gprs_pass))
  {
    SerialMon.println(" fail");
    delay(10000);
    return;
  }
  SerialMon.println(" OK");

  // Make HTTP Get request
  Serial.println("Making GET request...");
  http_client.get("/a/check");

  int status_code = http_client.responseStatusCode();
  String response = http_client.responseBody();

  Serial.print("Status code: ");
  Serial.println(status_code);
  Serial.print("Response: ");
  Serial.println(response);

  http_client.stop();

  // Disconnect GPRS
  sim_modem.gprsDisconnect();
  SerialMon.println("GPRS disconnected");
  digitalWrite(LED_GPIO, LED_OFF);

  //Turn off the moden (if use, you need run setupModem() again)
  //sim_modem.poweroff();
  //SerialMon.println("Modem poweroff");

  delay(10000);
}
