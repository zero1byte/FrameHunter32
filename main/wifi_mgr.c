/**
 * @file  wifi_mgr.c
 * @brief Wi-Fi driver lifecycle management and AP scanner — implementation.
 */

#include "wifi_mgr.h"

#include <stdio.h>
#include <stdbool.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"

#define TAG "WIFI_MGR"

/* ============================================================
   MODULE STATE
   ============================================================ */

static bool g_inited  = false;
static bool g_started = false;

/* ============================================================
   PRIVATE HELPERS
   ============================================================ */

static const char *auth_mode_str(wifi_auth_mode_t mode)
{
    switch (mode) {
        case WIFI_AUTH_OPEN:            return "Open";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA-PSK";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2-Personal";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Enterprise";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3-Personal";
        default:                        return "Unknown";
    }
}

/* ============================================================
   PUBLIC API
   ============================================================ */

esp_err_t wifi_mgr_init(void)
{
    if (g_inited) return ESP_OK;

    esp_err_t err;

    err = esp_netif_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "netif_init: %s", esp_err_to_name(err));
        return err;
    }

    err = esp_event_loop_create_default();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "event_loop_create: %s", esp_err_to_name(err));
        return err;
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wifi_init: %s", esp_err_to_name(err));
        return err;
    }

    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_mode STA: %s", esp_err_to_name(err));
        return err;
    }

    g_inited = true;
    return ESP_OK;
}

esp_err_t wifi_mgr_start(void)
{
    if (g_started) return ESP_OK;

    esp_err_t err = esp_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wifi_start: %s", esp_err_to_name(err));
        return err;
    }

    g_started = true;
    return ESP_OK;
}

esp_err_t wifi_mgr_stop(void)
{
    if (!g_started) return ESP_OK;

    esp_err_t err = esp_wifi_stop();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wifi_stop: %s", esp_err_to_name(err));
        return err;
    }

    g_started = false;
    return ESP_OK;
}

void wifi_mgr_scan_and_print(void)
{
    esp_err_t err;

    if ((err = wifi_mgr_init())  != ESP_OK) { printf("Wi-Fi init failed.\n");  return; }
    if ((err = wifi_mgr_start()) != ESP_OK) { printf("Wi-Fi start failed.\n"); return; }

    printf("Scanning for networks...\n");

    wifi_scan_config_t scan_cfg = {0};
    err = esp_wifi_scan_start(&scan_cfg, true /* blocking */);
    if (err != ESP_OK) {
        printf("Scan failed: %s\n", esp_err_to_name(err));
        wifi_mgr_stop();
        return;
    }

    uint16_t          count = WIFI_MGR_MAX_APS;
    wifi_ap_record_t  records[WIFI_MGR_MAX_APS];

    err = esp_wifi_scan_get_ap_records(&count, records);
    if (err != ESP_OK) {
        printf("get_ap_records failed: %s\n", esp_err_to_name(err));
        wifi_mgr_stop();
        return;
    }

    printf("\nFound %d network(s):\n", count);
    for (uint16_t i = 0; i < count; i++) {
        printf("\n[%2u] SSID     : %s\n",   i + 1, records[i].ssid);
        printf("     BSSID    : %02X:%02X:%02X:%02X:%02X:%02X\n",
               records[i].bssid[0], records[i].bssid[1], records[i].bssid[2],
               records[i].bssid[3], records[i].bssid[4], records[i].bssid[5]);
        printf("     Channel  : %d\n",      records[i].primary);
        printf("     Security : %s\n",      auth_mode_str(records[i].authmode));
        printf("     RSSI     : %d dBm\n",  records[i].rssi);
    }
    printf("\n");

    /* Return driver to idle so a subsequent sniffer run can take over */
    wifi_mgr_stop();
}