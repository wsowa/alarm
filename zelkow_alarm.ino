#include "credentials.h"
#include <WiFiClientSecure.h>
SET_LOOP_TASK_STACK_SIZE(48 * 1024);
#include <ArduinoHttpClient.h>
#include <ArduinoJson.h>
#include <time.h>
#include <string.h>
#include <esp_sleep.h>
#include <driver/adc.h>
#include "driver/gpio.h"
#include <Base64URL.h>
#include <ESP32AnalogRead.h>
#include "esp_tls.h"
#include "esp_random.h"
#include "mbedtls/pem.h"
#include "esp_sntp.h"
#include "soc/rtc_wdt.h"
#include "esp_int_wdt.h"
#include "esp_task_wdt.h"
#include <Wire.h>

#define WDT_TIMEOUT_MARGIN 600

#define WATCHDOG_TIMEOUT() ((config.sleepInterval > config.hibernationTime ? config.sleepInterval : config.hibernationTime)+WDT_TIMEOUT_MARGIN)*1000

#define MODEM_GPIO_PIN 27
#define CAMERAS_GPIO_PIN 12
#define LIGHTS_GPIO_PIN 13
#define SIREN_GPIO_PIN 14

#define TEMPERATURE_ADC_GPIO_PIN 36
#define BATT_VOLTAGE_ADC_GPIO_PIN 39

#define SDA_PIN GPIO_NUM_32
#define SCL_PIN GPIO_NUM_33

#define I2C_FREQ_HZ 9600
#define SHTC3_ADDR 0x70
#define SHTC3_MEASURE_CMD 0x7866 // normal mode, no stretching

#define MEASURMENT_SLEEP_TIME_MSEC 11

gpio_num_t sensorPins[] = {GPIO_NUM_16, GPIO_NUM_17, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_22, GPIO_NUM_23 };
#define SENSORS_NUMBER (sizeof(sensorPins)/sizeof(gpio_num_t))

char* sensorNames[] = {
  "Ogrod%20tyl",
  "Wejscie",
  "Brama",
  "Z%20tylu",
  "Taras",
  "Ogrod%20przod"
};

#define ADC_SAMPLES 10

#define NTP_RESYNC_INTERVAL 1800

#define TOKEN_TTL_SEC 3600
#define TOKEN_TTL_MARGIN 60

#define MAX_GET_ATTEMPTS 2

const char* ntpServer = "pool.ntp.org";

char googleApiToken[1025];

#define NOTIFICATIONS_BUFFER_SIZE 20
#define NOTIFICATION_LENGTH 30
char notificationsBuffer[NOTIFICATIONS_BUFFER_SIZE][NOTIFICATION_LENGTH];
uint8_t stashedNotifications = 0;

ESP32AnalogRead adc;

struct configData {
  uint sleepInterval;
  uint hibernationTime;
  uint alarmKeepAwakeTime;
  uint alarmHibernationInhibitTime;
  uint alarmLightsOnTime;
  uint alarmBlinkingTime;
  uint blinkingIntervalMs;
  uint alarmCamerasOnTime;
  uint lightsMode;
  uint camerasMode;
  uint activeSensors;
  uint notificationsInterval;
  uint networkWatchdogTimeout;
  uint restartInterval;
};

#define LIGHTS_MODE_AUTO 0
#define LIGHTS_MODE_OFF 1
#define LIGHTS_MODE_BLINKING 2
#define LIGHTS_MODE_ON 3

#define CAMERAS_MODE_AUTO 0
#define CAMERAS_MODE_OFF 1
#define CAMERAS_MODE_ON 2

#define PRINTF_BINARY_PATTERN_INT8 "%c%c%c%c%c%c"
#define PRINTF_BYTE_TO_BINARY_INT8(i)    \
    (((i) & 0x20ll) ? '1' : '0'), \
    (((i) & 0x10ll) ? '1' : '0'), \
    (((i) & 0x08ll) ? '1' : '0'), \
    (((i) & 0x04ll) ? '1' : '0'), \
    (((i) & 0x02ll) ? '1' : '0'), \
    (((i) & 0x01ll) ? '1' : '0')
    
volatile configData config = {
  .sleepInterval = 30,
  .hibernationTime = 0,
  .alarmKeepAwakeTime = 310,
  .alarmHibernationInhibitTime = 900,
  .alarmLightsOnTime = 300,
  .alarmBlinkingTime = 30,
  .blinkingIntervalMs = 500,
  .alarmCamerasOnTime = 300,
  .lightsMode = LIGHTS_MODE_AUTO,
  .camerasMode = CAMERAS_MODE_AUTO,
  .activeSensors = 0b111111,
  .notificationsInterval = 300,
  .networkWatchdogTimeout = 3600,
  .restartInterval = 24*3600
};

volatile unsigned long alarmTriggeredTime = 0;
volatile unsigned long lastNetworkRead = 0;
volatile unsigned long lastNotificationSendTime = 0;

volatile uint alarmLightsState = LIGHTS_MODE_OFF;
volatile uint alarmCamerasState = CAMERAS_MODE_OFF;
volatile int newAlarmTriggered = 0;
bool sirenState = false;
bool configUpdated = false;

void setupSerial() {
  Serial.begin(115200);
  while (!Serial) {
    delay(100);
  }
}

void connectToWifi() {
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print("\nConnecting to ");
    Serial.print(ssid);
    WiFi.disconnect(true);
    WiFi.begin(ssid, password);
    int i = 0 ;
    while (WiFi.status() != WL_CONNECTED && i < 100) {
      delay(100);
      Serial.print(".");
      i++;
    }
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("TIMEOUT");
      continue;
    }
    Serial.println();
    Serial.print("Connected as ");
    Serial.println(WiFi.localIP());
  }
}

time_t getLocalTime() {
  time_t now;
  time(&now);
  tm t = * localtime(&now);
  uint8_t localHour = t.tm_hour;
  t =  * gmtime(&now);
  uint8_t utcHour = t.tm_hour;
  uint8_t diff = (localHour-utcHour+24)%24;
  return now+3600*diff;
}

void logRemotely(String l) {
  int r = refreshToken();
  if (r != 0) {
    Serial.println("Failed to refresh token");
    return;
  }
  WiFiClientSecure client;
  client.setInsecure();
  HttpClient http(client, sheetsHost, 443);

  time_t localTime = getLocalTime();
  
  String body = "{\"range\": \"Log\",\"majorDimension\": \"ROWS\",\"values\": [[\"=ROW()\",\"=EPOCHTODATE(" + String(localTime) + ")\",\"" + l + "\"]]}";
  String path = String(appendLogPath) + "&access_token=" + googleApiToken;
  r = http.post(path, "application/json", body);

  if (r != 0) {
    Serial.println("ERROR on POST from " + path + " : " + String(r));
    return;
  }

  int httpCode = http.responseStatusCode();
  if (httpCode != 200) {
    Serial.println("Non 200 on POST from " + path + " : " + String(httpCode));
    Serial.println(http.responseBody());
    return;
  }
}

int RS256Sign(char *output, size_t *outputLen, void *secret, size_t secretLen, void *toSign, size_t toSignLen) {

  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  const char *pers = "rsa_sign_pss";
  int r;

  mbedtls_entropy_init(&entropy);
  mbedtls_pk_init(&pk);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  if ((r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 (const unsigned char *) pers,
                                 strlen(pers))) != 0) {
    mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", r);
    return r;
  }

  if (r = mbedtls_pk_parse_key(&pk, (const unsigned char *)secret, secretLen + 1, NULL, NULL) != 0) {
    mbedtls_printf("  ! mbedtls_pk_parse_public_keyfile returned %d\n\n", r);
    return r;
  }


  unsigned char hash[64];
  r = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *) toSign, toSignLen, hash);

  if (r != 0) {
    Serial.printf("Error mbedtls_md: 0x%x\n", -r);
    return r;
  }

  unsigned char pkSigned[512];
  size_t signedLen;

  r = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, (const unsigned char*)hash, 0, pkSigned, &signedLen, mbedtls_ctr_drbg_random, &ctr_drbg);

  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  if (r != 0) {
    Serial.printf("Error mbedtls_pk_sign: 0x%x\n", -r);
    return r;
  }

  Base64URL::base64urlEncode(pkSigned, signedLen, output, outputLen);

  return 0;
}

int generateJwt(time_t now, char* jwt) {
  char key[] = PRIV_KEY;
  char* headerBase64url = "eyJhbGciOiAiUlMyNTYiLCJ0eXAiOiJKV1QifQ";

  char buff1[512], buff2[512];

  char* payload = buff1;
  sprintf(payload, "{\"iss\":\"" SERVICE_ACCOUNT "\",\"scope\":\"https://www.googleapis.com/auth/spreadsheets\",\"aud\":\"https://oauth2.googleapis.com/token\",\"exp\":%d,\"iat\":%d}", now + TOKEN_TTL_SEC, now);

  char* payloadBase64url = buff2;
  Base64URL::base64urlEncode(payload, strlen(payload), payloadBase64url, NULL);

  char toSign[512];
  sprintf(toSign, "%s.%s", headerBase64url, payloadBase64url);

  char *signature = buff2;
  size_t signLen = 512;

  int r = RS256Sign(signature, &signLen, key, strlen(key), toSign, strlen(toSign));
  if (r != 0) {
    Serial.printf("RS256Sign failed: %d\n", r);
    return r;;
  }

  sprintf(jwt, "%s.%s", toSign, signature);

  return 0;

}

int refreshToken() {
  static time_t tokenExpiryDate = 0;

  time_t now;
  time(&now);


  if (now >= tokenExpiryDate) {
    Serial.println("Requesting new token");

    char jwt[1024];
    jwt[0] = 'x'; jwt[1] = '\n'; jwt[2] = '\0';

    int r = generateJwt(now, jwt);
    if (r != 0) {
      Serial.printf("generateJwt failed: %d\n", r);
      return r;
    }

    WiFiClientSecure client;
    client.setInsecure();
    HttpClient http(client, tokenHost, 443);
    String body = String("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=") + jwt ;

    r = http.post(tokenPath, "application/x-www-form-urlencoded", body);

    if (r != 0) {
      Serial.println("ERROR on POST from " + String(tokenPath) + " : " + String(r));
      return r;
    }

    int httpCode = http.responseStatusCode();
    if (httpCode != 200) {
      Serial.println("Non 200 on POST from " + String(tokenPath) + " : " + String(httpCode));
      Serial.println(http.responseBody());
      return httpCode;
    }

    StaticJsonDocument<1500> doc;
    DeserializationError error = deserializeJson(doc, http.responseBody());

    if (error) {
      Serial.print(F("token json deserialization failed: "));
      Serial.println(error.f_str());
      return -1;
    } else if (!doc.containsKey("access_token")) {
      Serial.println("No access_token field in json");
      return -1;
    } else if (!doc.containsKey("expires_in")) {
      Serial.println("No expires_in field in json");
      return -1;
    }

    int expiry = doc["expires_in"];
    strcpy(googleApiToken, doc["access_token"]);

    tokenExpiryDate = now + expiry - TOKEN_TTL_MARGIN;
  } else {
    Serial.printf("Token still valid: %d now: %d\n", tokenExpiryDate, now);
  }
  return 0;
}

bool updateConfig() {
  WiFiClientSecure client;
  client.setInsecure();
  HttpClient http(client, sheetsHost, 443);

  int i;
  for (i = 0; i < MAX_GET_ATTEMPTS; i++) {

    int r = http.get(readConfigPath);
    if (r != 0) {
      Serial.println("ERROR on GET from " + String(readConfigPath) + " : " + String(r));
      logRemotely("ERROR on GET from " + String(readConfigPath) + " : " + String(r));
      delay (100);
      continue;
    }

    int httpCode = http.responseStatusCode();
    if (httpCode != 200) {
      Serial.println("Non 200 on GET from " + String(readConfigPath) + " : " + String(httpCode));
      logRemotely("Non 200 on GET from " + String(readConfigPath) + " : " + String(httpCode));
      delay (100);
      continue;
    }

    break;
  }
  if (i == MAX_GET_ATTEMPTS) return false;

  StaticJsonDocument<1500> doc;
  DeserializationError error = deserializeJson(doc, http.responseBody());

  if (error || !doc.containsKey("values")) {
    Serial.print(F("config json deserialization failed: "));
    Serial.println(error.f_str());
    logRemotely("Invalid config JSON: " + String(error.f_str()));
    return false;
  }

  JsonArray values = doc["values"];
  for (JsonArray pair : values) {
    const char* k = pair[0];
    const char* v = pair[1];

    updateConfigAttribute(k, v);
  }

  printConfig();
  return true;
}

void setSirenOut(bool val) {
  digitalWrite(SIREN_GPIO_PIN, !val); // connected to optocoupler so low = enabled
}

void setLightsOut(bool val) {
  digitalWrite(LIGHTS_GPIO_PIN, !val); // connected to optocoupler so low = enabled
}

void setCamerasOut(bool val) {
  digitalWrite(CAMERAS_GPIO_PIN, !val); // connected to optocoupler so low = enabled
}

void setModemOut(bool val) {
  digitalWrite(MODEM_GPIO_PIN, val); // connected to optocoupler so high = enabled
}

void setSiren(bool newState) {
  if (sirenState != newState) {
    sirenState = newState;
    setSirenOut(newState);
  }
}

void setLightsMode(uint mode) {
  if (mode != config.lightsMode) {
    config.lightsMode = mode;
  }
}

void setCamerasMode(uint mode) {
  if (mode != config.camerasMode) {
    config.camerasMode = mode;
  }
}

void updateConfigAttribute(const char* k, const char* v) {
  if (!strcmp(k, "reboot")) {
    if (!strcasecmp(v, "TRUE")) {
      restart("Reboot from config!");
    }
  }
  else if (!strcmp(k, "sirenOn")) {
    setSiren(!strcasecmp(v, "TRUE") || !strcasecmp(v, "ON"));
  }
  else if (!strcmp(k, "lightsMode")) {
    uint mode = 0xFF;
    if (!strcasecmp(v, "AUTO")) mode = LIGHTS_MODE_AUTO;
    else if (!strcasecmp(v, "ON")) mode = LIGHTS_MODE_ON;
    else if (!strcasecmp(v, "OFF")) mode = LIGHTS_MODE_OFF;
    else if (!strcasecmp(v, "BLINKING")) mode = LIGHTS_MODE_BLINKING;
    else {
      Serial.printf("Invalid lightsMode %s\n", v);
      logRemotely("Invalid lightsMode " + String(v));
    }
    if (mode != 0xFF) setLightsMode(mode);
  }
  else if (!strcmp(k, "camerasMode")) {
    uint mode = 0xFF;
    if (!strcasecmp(v, "AUTO")) mode = CAMERAS_MODE_AUTO;
    else if (!strcasecmp(v, "ON")) mode = CAMERAS_MODE_ON;
    else if (!strcasecmp(v, "OFF")) mode = CAMERAS_MODE_OFF;
    else {
      Serial.printf("Invalid camerasMode %s\n", v);
      logRemotely("Invalid camerasMode " + String(v));
    }
    if (mode != 0xFF) setCamerasMode(mode);
  }
  else if (!strcmp(k, "sleepInterval")) {
    config.sleepInterval = atoi(v);
  }
  else if (!strcmp(k, "hibernationTime")) {
    config.hibernationTime = atoi(v);
  }
  else if (!strcmp(k, "alarmKeepAwakeTime")) {
    config.alarmKeepAwakeTime = atoi(v);
  }
  else if (!strcmp(k, "alarmHibernationInhibitTime")) {
    config.alarmHibernationInhibitTime = atoi(v);
  }
  else if (!strcmp(k, "alarmLightsOnTime")) {
    config.alarmLightsOnTime = atoi(v);
  }
  else if (!strcmp(k, "alarmBlinkingTime")) {
    config.alarmBlinkingTime = atoi(v);
  }
  else if (!strcmp(k, "blinkingIntervalMs")) {
    config.blinkingIntervalMs = atoi(v);
  }
  else if (!strcmp(k, "alarmCamerasOnTime")) {
    config.alarmCamerasOnTime = atoi(v);
  }
  else if (!strcmp(k, "activeSensors")) {
    config.activeSensors = std::stoi(v, nullptr,2);
  }
  else if (!strcmp(k, "notificationsInterval")) {
    config.notificationsInterval = atoi(v);
  }
  else if (!strcmp(k, "networkWatchdogTimeout")) {
    config.networkWatchdogTimeout = atoi(v);
  }
  else if (!strcmp(k, "restartInterval")) {
    config.restartInterval = atoi(v);
  }
  else {
    Serial.printf("Unknown config key %s with value %s\n", k, v);
    logRemotely("Unknown config key " + String(k) + " with value " + String(v));
  }
}

void printConfig() {
  char *lightsMode, *camerasMode;

  switch (config.lightsMode) {
    case LIGHTS_MODE_AUTO: lightsMode = "AUTO"; break;
    case LIGHTS_MODE_OFF: lightsMode = "OFF"; break;
    case LIGHTS_MODE_BLINKING: lightsMode = "BLINKING"; break;
    case LIGHTS_MODE_ON: lightsMode = "ON"; break;
    default: lightsMode = "UNKNOWN";
  }

  switch (config.camerasMode) {
    case CAMERAS_MODE_AUTO: camerasMode = "AUTO"; break;
    case CAMERAS_MODE_OFF: camerasMode = "OFF"; break;
    case CAMERAS_MODE_ON: camerasMode = "ON"; break;
    default: camerasMode = "UNKNOWN";

  }

  Serial.printf("Config: sleepInterval=%d, hibernationTime=%d, alarmKeepAwakeTime=%d, alarmHibernationInhibitTime=%d, alarmLightsOnTime=%d, alarmBlinkingTime=%d, blinkingIntervalMs=%d, alarmCamerasOnTime=%d, lightsMode=%s(%d), camerasMode=%s(%d), activeSensors=" PRINTF_BINARY_PATTERN_INT8 ", notificationsInterval=%d, networkWatchdogTimeout=%d, restartInterval=%d\n",
                config.sleepInterval, config.hibernationTime, config.alarmKeepAwakeTime, config.alarmHibernationInhibitTime, config.alarmLightsOnTime, config.alarmBlinkingTime, config.blinkingIntervalMs, config.alarmCamerasOnTime, lightsMode, config.lightsMode, camerasMode, config.camerasMode, PRINTF_BYTE_TO_BINARY_INT8(config.activeSensors), config.notificationsInterval, config.networkWatchdogTimeout, config.restartInterval);
}

void setupGpio() {
  pinMode(MODEM_GPIO_PIN, OUTPUT); digitalWrite(MODEM_GPIO_PIN, HIGH); // connected to N-channel mosfet so high = enabled
  pinMode(CAMERAS_GPIO_PIN, OUTPUT); digitalWrite(CAMERAS_GPIO_PIN, HIGH); // connected to optocoupler so low = enabled
  pinMode(LIGHTS_GPIO_PIN, OUTPUT); digitalWrite(LIGHTS_GPIO_PIN, HIGH); // connected to optocoupler so low = enabled
  pinMode(SIREN_GPIO_PIN, OUTPUT); digitalWrite(SIREN_GPIO_PIN, HIGH); // connected to optocoupler so low = enabled

  for (int i=0; i<SENSORS_NUMBER; i++) {
    pinMode(sensorPins[i], INPUT_PULLDOWN);
  }

  pinMode(SDA_PIN, INPUT_PULLUP);
  pinMode(SCL_PIN, INPUT_PULLUP);
}

void ntpCallback(struct timeval *tv) {
  Serial.println("NTP SYNC");
}

void setWatchdog() {
  rtc_wdt_protect_off();
  rtc_wdt_set_stage(RTC_WDT_STAGE0, RTC_WDT_STAGE_ACTION_RESET_RTC);
  rtc_wdt_set_time(RTC_WDT_STAGE0, WATCHDOG_TIMEOUT());
  rtc_wdt_enable();
  CLEAR_PERI_REG_MASK(RTC_CNTL_WDTCONFIG0_REG, RTC_CNTL_WDT_PAUSE_IN_SLP);
  rtc_wdt_protect_on();
  Serial.printf("Watchdog set to %d ms\n", WATCHDOG_TIMEOUT());
}

void resetWatchdog() {
  rtc_wdt_protect_off();
  rtc_wdt_feed();
  rtc_wdt_protect_on();
  Serial.println("Watchdog timer restarted");
}

void setup() {
  setCpuFrequencyMhz(80);
  setupSerial();
  setupGpio();
  configTzTime("CET-1CEST,M3.5.0,M10.5.0/3", ntpServer);
  sntp_set_time_sync_notification_cb(ntpCallback);

  setWatchdog();

  TaskHandle_t task;
  xTaskCreatePinnedToCore(gpioTask, /* Function to implement the task */
                          "gpioTask", /* Name of the task */
                          8 * 1024, /* Stack size in words */
                          NULL,  /* Task input parameter */
                          1,  /* Priority of the task */
                          &task,  /* Task handle. */
                          xPortGetCoreID()); /* Core where the task should run */

  connectToWifi();
  struct tm timeinfo;
  getLocalTime(&timeinfo);

  Wire.begin(SDA_PIN, SCL_PIN, I2C_FREQ_HZ);

  Serial.println("Startup");
  logRemotely("Startup");
}

bool isBlinking() {
  return config.lightsMode == LIGHTS_MODE_BLINKING || (config.lightsMode == LIGHTS_MODE_AUTO && alarmLightsState == LIGHTS_MODE_BLINKING);
}

void driveOutputs() {
  static unsigned long blinkTime = 0;
  static bool blinkState = false;
  if (config.camerasMode == CAMERAS_MODE_ON || (config.camerasMode == CAMERAS_MODE_AUTO && alarmCamerasState == CAMERAS_MODE_ON)) {
      setCamerasOut(true);
    } else {
      setCamerasOut(false);
    }

    if (config.lightsMode == LIGHTS_MODE_ON || (config.lightsMode == LIGHTS_MODE_AUTO && alarmLightsState == LIGHTS_MODE_ON)) {
      setLightsOut(true);
    } else if (isBlinking()) {
      unsigned long now = millis();
      if (now >= blinkTime + config.blinkingIntervalMs) {
        blinkTime = now;
        blinkState = !blinkState;
        setLightsOut(blinkState);
      }
    } else {
      setLightsOut(false);
    }
}

bool isSensorActive(int i) {
  return ((1<<i) & config.activeSensors) != 0;
}

void readInputs() {
  for (int i=0; i<SENSORS_NUMBER; i++) {
    if (isSensorActive(i) && !digitalRead(sensorPins[i])) alarmTriggered(i+1);
  }
}

void restart(char * logMsg) {
  Serial.println(logMsg);
  Serial.flush();
  ESP.restart();
}

void checkForReboot() {
  unsigned long now = millis()/1000;
  if (now > lastNetworkRead + config.networkWatchdogTimeout) {
    restart("NETWORK WATCHDOG TIMEOUT!!!");
  } else if (now > config.restartInterval) {
    restart("Periodic restart");
  }
}

void gpioTask(void * p) {
  while (true) {
    handleAlarmTimeTick();
    driveOutputs();
    readInputs();
    checkForReboot();
    delay(20);
  }
}

bool canSleep() {
  unsigned long now = millis()/1000;
  return (now > alarmTriggeredTime + config.alarmKeepAwakeTime) && config.sleepInterval > 0 && !isBlinking() && newAlarmTriggered == 0;
}

bool canHibernate() {
  unsigned long now = millis()/1000;
  return (now > alarmTriggeredTime + config.alarmHibernationInhibitTime) && (config.hibernationTime > 0) && configUpdated;
}

void sleep() {
  uint32_t sleepTime;
  
  if (canHibernate()) {
    sendStashedNotifications();
    lastNotificationSendTime = 0;

    sleepTime = config.hibernationTime;
    char buff[32];
    snprintf(buff, 31, "Hibernating for %d sec", sleepTime);
    Serial.println(buff);
    logRemotely(buff);
   
    WiFi.disconnect(true);  // Disconnect from the network
    WiFi.mode(WIFI_OFF);    // Switch WiFi off
    setModemOut(false); 
    configUpdated = false;
  } else {
    sleepTime = config.sleepInterval;
    Serial.printf("Sleeping for %d sec\n", sleepTime);
    
    WiFi.disconnect(true);  // Disconnect from the network
    WiFi.mode(WIFI_OFF);    // Switch WiFi off
  }

  esp_sleep_enable_timer_wakeup(sleepTime * 1000000ull);
  
  for (int i=0; i<SENSORS_NUMBER; i++) {
    if (isSensorActive(i)) gpio_wakeup_enable(sensorPins[i], GPIO_INTR_LOW_LEVEL);
    else gpio_wakeup_disable(sensorPins[i]);
  }
  
  esp_sleep_enable_gpio_wakeup();
  
  for (int i=0; i<SENSORS_NUMBER; i++) {
    if (isSensorActive(i)) gpio_hold_en(sensorPins[i]);
    else gpio_hold_dis(sensorPins[i]);
  }

  Serial.flush();
  delay(100);
  if (newAlarmTriggered == 0) {
    esp_light_sleep_start();
    esp_sleep_wakeup_cause_t cause = esp_sleep_get_wakeup_cause();
    setModemOut(true);
    delay(200);
    Serial.printf("Wakeup cause: %d\n", cause);
  } else {
    setModemOut(true);
    Serial.println("Sleep cancelled due to alarm");
  }
}

void resyncNtp() {
  static uint32_t lastSync = 0;
  uint32_t now = millis()/1000;

  if (now > lastSync + NTP_RESYNC_INTERVAL) {
    lastSync = now;
    sntp_restart();
    struct tm timeinfo;
    getLocalTime(&timeinfo);
  }
}

int16_t getTemperature(uint16_t raw) {
  return -4500+17500*raw/65536;
}
uint16_t getHumidity(uint16_t raw) {
  return raw*10000/65536;
}

void readI2CSensor(int16_t * temp, uint16_t * rh) {
  Wire.beginTransmission(SHTC3_ADDR); // transmit to device #4
  Wire.write((SHTC3_MEASURE_CMD >> 8) & 0xFF);
  Wire.write(SHTC3_MEASURE_CMD & 0xFF);
  Wire.endTransmission();

  delay(MEASURMENT_SLEEP_TIME_MSEC);

  uint8_t bytesReceived = Wire.requestFrom(SHTC3_ADDR, 5);
  Serial.printf("Read %d bytes from I2C\n", bytesReceived);
  if(bytesReceived) { //If received more than zero bytes
    uint8_t buff[5];
    Wire.readBytes(buff, 5);
    *temp = getTemperature((buff[0] << 8) | buff[1]);
    *rh = getHumidity((buff[3] << 8) | buff[4]);
  }
}

void readAdcSensors(uint32_t *tempMv, uint32_t *battMv) {
  for (int i=0; i<ADC_SAMPLES; i++) {
    adc.attach(TEMPERATURE_ADC_GPIO_PIN);
    *tempMv += adc.readMiliVolts();
    adc.attach(BATT_VOLTAGE_ADC_GPIO_PIN);
    *battMv += adc.readMiliVolts();
  }
  *tempMv = *tempMv / ADC_SAMPLES;
  *battMv = *battMv / ADC_SAMPLES;
}

void loop() {
  connectToWifi();
  resyncNtp();

  handleAlarmTriggerAndNotifications();
  configUpdated = updateConfig();

  setWatchdog();

  if (configUpdated) {
    lastNetworkRead = millis() / 1000;
  }

  uint32_t tempMv = 0, battMv = 0;
  int16_t temp = 0;
  uint16_t rh = 0;
  readAdcSensors(&tempMv, &battMv);
  readI2CSensor(&temp, &rh);

  char buff[96];
  snprintf(buff, 95, "Alive... Batt ADC=%dmV, Temp ADC=%dmV, Temp=%d, RH=%d, uptime=%ds", battMv, tempMv, temp, rh, millis() / 1000);
  Serial.println(buff);
  logRemotely(buff);

  if (canSleep()) sleep();
  else delay (100);

  resetWatchdog();
}

volatile void alarmTriggered(int sensor) {
  alarmTriggeredTime = millis()/1000;
  newAlarmTriggered = sensor;
  if (alarmLightsState == LIGHTS_MODE_OFF) alarmLightsState = LIGHTS_MODE_BLINKING;
  alarmCamerasState = CAMERAS_MODE_ON;
}

void handleAlarmTimeTick() {
  unsigned long now = millis()/1000;
  if (alarmLightsState == LIGHTS_MODE_BLINKING && now > alarmTriggeredTime + config.alarmBlinkingTime) {
    if (now < alarmTriggeredTime + config.alarmLightsOnTime) alarmLightsState = LIGHTS_MODE_ON;
    else alarmLightsState = LIGHTS_MODE_OFF;
  } else if (alarmLightsState == LIGHTS_MODE_ON && now > alarmTriggeredTime + config.alarmLightsOnTime) {
    alarmLightsState = LIGHTS_MODE_OFF;
  }

  if (alarmCamerasState == CAMERAS_MODE_ON && now > alarmTriggeredTime + config.alarmCamerasOnTime) {
    alarmCamerasState = CAMERAS_MODE_OFF;
  }
}

void handleAlarmTriggerAndNotifications() {
  int sensor = 0;
  if (newAlarmTriggered) {
    sensor = newAlarmTriggered;
    newAlarmTriggered = 0;
  }

  if (sensor) {
    bool success = notifyAlarmTriggered(sensor);

    if (!success && newAlarmTriggered == 0) {
      newAlarmTriggered = sensor;
    }

    char buff[32];
    snprintf(buff, 30, "ALARM TRIGGERED!!! (%d)", sensor);
    Serial.println(buff);
    logRemotely(buff);
  }

  unsigned long now = millis() / 1000;
  if (now > lastNotificationSendTime + config.notificationsInterval) {
    sendStashedNotifications();
  }
}

bool notifyAlarmTriggered(int sensor) {
  char notification[NOTIFICATION_LENGTH];
  writeNotification(notification, sensor);

  if (config.notificationsInterval > 0 && lastNotificationSendTime > 0) {
    Serial.printf("Stashing notification: %s\n", notification);
    stashNotification(notification);
    return true;
  } else {
    Serial.printf("Sending notification: %s\n", notification);
    return sendNotification(notification, NOTIFICATION_LENGTH);
  }
}

bool sendNotification(char* message, uint len) {
    WiFiClientSecure client;
    client.setInsecure();
    HttpClient http(client, triggerHost, 443);

    char path[128+len];
    sprintf(path, alarmPath, message);

    int i = 0;
    for (; i < MAX_GET_ATTEMPTS; i++) {
      int r = http.get(path);
      if (r != 0) {
        Serial.println("SEND NOTIFICATION - ERROR on GET from " + String(path) + " : " + String(r));
        logRemotely("SEND NOTIFICATION - ERROR on GET from " + String(path) + " : " + String(r));
        delay(100);
        continue;
      }
 
      int httpCode = http.responseStatusCode();
      if (httpCode != 200) {
        Serial.println("SEND NOTIFICATION - Non 200 on GET from " + String(path) + " : " + String(httpCode));
        logRemotely("SEND NOTIFICATION - Non 200 on GET from " + String(path) + " : " + String(httpCode));
        delay(100);
        continue;
      }
      lastNotificationSendTime = millis() / 1000;
      return true;
    }
    return false;
}

void writeNotification(char *notification, int sensor) {
  time_t now;
  time(&now);
  tm t = * localtime(&now);
  uint8_t h = t.tm_hour;
  uint8_t m = t.tm_min;
  uint8_t s = t.tm_sec;

  sprintf(notification, "%02d:%02d:%02d:%%20%s", h,m,s, sensorNames[sensor-1]);
}

void stashNotification(char * notification) {
  strncpy(notificationsBuffer[stashedNotifications % NOTIFICATIONS_BUFFER_SIZE], notification, NOTIFICATION_LENGTH);
  stashedNotifications++;
}

void sendStashedNotifications() {
  if (stashedNotifications > 0) {
    Serial.printf("Sending %d stahsed notifications\n", stashedNotifications);
    char msg[NOTIFICATIONS_BUFFER_SIZE * NOTIFICATION_LENGTH + 30];
    uint offset = sprintf(msg, "%d%%20stashed%%20notifications:", stashedNotifications);
    uint8_t startIndex = stashedNotifications > NOTIFICATIONS_BUFFER_SIZE ? stashedNotifications % NOTIFICATIONS_BUFFER_SIZE : 0;
    uint8_t n = stashedNotifications < NOTIFICATIONS_BUFFER_SIZE ? stashedNotifications : NOTIFICATIONS_BUFFER_SIZE;

    for(uint8_t i = 0; i<n;i++) {
      offset += sprintf(msg+offset, "%%0A%s",notificationsBuffer[(i+startIndex) % NOTIFICATIONS_BUFFER_SIZE]);
    }
    sendNotification(msg, offset);
    stashedNotifications = 0;
  }
}

// TODO: ota
