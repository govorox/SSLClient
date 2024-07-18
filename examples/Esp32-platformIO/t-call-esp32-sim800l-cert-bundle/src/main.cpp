#include <Arduino.h>
#include <SSLClient.h>
#include <Wire.h>

#define MODEM_UART_BAUD 9600
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

// Layers stack
TinyGsm modem(serialModem);
TinyGsmClient gsmTransportLayer(modem);
SSLClient securePresentationLayer(&gsmTransportLayer);

// * Certificate bundle with 41 most used root certificates
extern const uint8_t ca_cert_bundle_start[] asm("_binary_data_crt_x509_crt_bundle_bin_start");
extern const uint8_t ca_cert_bundle_end[] asm("_binary_data_crt_x509_crt_bundle_bin_end");

// Function prototypes
void usbRead();
void testGET(const char* host, uint16_t port, const char* resource = nullptr);
void setupModem();
bool setupPMU();

void setup() {
  serialMonitor.begin(115200);
  delay(100);

  if (!setupPMU()) {
    serialMonitor.println("Setting board power management error");
  }

  // Set SIM module baud rate and UART pins
  serialModem.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);

  // Set certificate bundle to SSL client
  securePresentationLayer.setCACertBundle(ca_cert_bundle_start);

  // SIM modem initial setup
  setupModem();

  // Enable PSRAM
  psramInit();

  // Initialize SIM800
  log_i("Initializing modem...");
  modem.restart();
}

void loop() {
  usbRead();
}

/**
 * @brief Read from the USB serial monitor
 * 
 */
void usbRead() {
  if (serialMonitor.available()) {
    char c = serialMonitor.read();

    if (c == '\r' || c == '\n') {
      log_i("-> \\%c", c == '\r' ? 'r' : 'n');
    } else {
      log_i("-> %c", c);
    }

    switch (c) {
      // Connect SIM800 to the network
      case '0': {
        log_i("Connecting to network...");

        if (!modem.waitForNetwork()) {
          log_e("Failed to connect to network");
          return;
        }

        if (!modem.gprsConnect(apn, gprs_user, gprs_pass)) {
          log_e("Failed to connect to MODEM_APN");
          return;
        }

        log_i("Modem connected!");
      } break;
      case '1': {
        testGET("vsh.pp.ua", 443, "/TinyGSM/logo.txt");
      } break;
      case '2': {
        testGET("api.my-ip.io", 443, "/ip.json");
      } break;
      case '3': {
        testGET("ifconfig.me", 443, "/ip");
      } break;
      case '4': {
        testGET("www.howsmyssl.com", 443, "/a/check");
      } break;
    }
  }
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

/**
 * @brief Perform a GET request to the specified host and port
 * 
 * @param host The host to connect to
 * @param port The port to connect to
 * @param resource The resource to request
 */
void testGET(const char* host, uint16_t port, const char* resource) {
  if (!securePresentationLayer.connect(host, port)) {
    log_e("Failed to connect to server");
    return;
  }

  // GET request
  log_i("Performing HTTPS GET request...");
  securePresentationLayer.printf(
    "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\n",
    resource == nullptr ? "/" : resource,
    host
  );

  // Wait a little to receive some data
  uint32_t start = millis();
  while (securePresentationLayer.connected() && !securePresentationLayer.available() && ((millis() - start) < 10000L)) {
    delay(10);
  }

  log_d("Server response:");

  unsigned long startMillis = millis();
  unsigned int timeout = 5000;

  // Read the response while data is available or until timeout
  while ((millis() - startMillis < timeout)) {
    while (securePresentationLayer.available()) {
      char c = securePresentationLayer.read();
      if (c >= 0 && c < 128) {
        serialMonitor.print(c);
      }
    }
  }

  securePresentationLayer.stop();
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
