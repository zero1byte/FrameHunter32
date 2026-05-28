/**
 * @file  wifi_mgr.h
 * @brief Wi-Fi driver lifecycle management and AP scanner.
 *
 * Wraps esp_wifi_init / start / stop with idempotency guards so that
 * the sniffer and scan commands can share the same underlying driver
 * without double-initialisation crashes.
 */

#pragma once

#include <stdint.h>
#include "esp_err.h"
#include "esp_wifi.h"

/** Maximum access points returned by a single scan. */
#define WIFI_MGR_MAX_APS   20

/**
 * @brief Initialise the Wi-Fi subsystem (idempotent).
 *
 * Calls esp_netif_init, esp_event_loop_create_default, esp_wifi_init,
 * and esp_wifi_set_mode(STA).  Safe to call multiple times; subsequent
 * calls return ESP_OK immediately.
 *
 * @return ESP_OK on success, or the first error encountered.
 */
esp_err_t wifi_mgr_init(void);

/**
 * @brief Start the Wi-Fi driver (idempotent).
 *
 * @return ESP_OK on success.
 */
esp_err_t wifi_mgr_start(void);

/**
 * @brief Stop the Wi-Fi driver (idempotent).
 *
 * @return ESP_OK on success.
 */
esp_err_t wifi_mgr_stop(void);

/**
 * @brief Run an active scan and print results to stdout.
 *
 * Internally calls wifi_mgr_start(), scans, prints SSID / BSSID /
 * channel / security / RSSI for each found AP, then calls
 * wifi_mgr_stop() so the driver is idle for a subsequent sniffer run.
 */
void wifi_mgr_scan_and_print(void);