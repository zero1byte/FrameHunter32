/**
 * @file  cli.c
 * @brief UART command-line interface — implementation.
 *
 * Responsibilities:
 *   - Read characters from stdin and assemble command lines.
 *   - Parse command + optional arguments (--ssid / --channel / --bssid).
 *   - Maintain persistent sniffer_cfg_t across runs (omitted args keep
 *     their previous value; defaults: channel 6, no SSID/BSSID filter).
 *   - Orchestrate the two-phase sniffer: set correct promiscuous filter
 *     mask for each phase and block until capture completes.
 */

#include "cli.h"
#include "sniffer.h"
#include "wifi_mgr.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"

/* ============================================================
   PERSISTENT CONFIGURATION
   ============================================================ */

/**
 * Active sniffer configuration.
 * Survives across multiple sniffer invocations; omitted CLI arguments
 * leave the corresponding field unchanged.
 */
static sniffer_cfg_t g_cfg = {
    .ssid      = {0},
    .channel   = 6,
    .bssid     = {0},
    .bssid_set = false,
};

/* ============================================================
   PRIVATE UTILITIES
   ============================================================ */

static void print_prompt(void)
{
    printf("\nesp32> ");
    fflush(stdout);
}

static void print_mac(const char *label, const uint8_t mac[6])
{
    printf("%s %02X:%02X:%02X:%02X:%02X:%02X\n",
           label,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ============================================================
   COMMAND HANDLERS
   ============================================================ */

static void cmd_help(void)
{
    printf("\n=== ESP32 WPA2 Handshake Sniffer ===\n");
    printf("Commands:\n");
    printf("  help\n");
    printf("      Print this message.\n\n");
    printf("  scan\n");
    printf("      Active scan — list nearby APs with SSID, BSSID,\n");
    printf("      channel, security type and RSSI.\n\n");
    printf("  sniffer [--ssid <name>] [--channel <1-13>]\n");
    printf("          [--bssid <XX:XX:XX:XX:XX:XX>]\n");
    printf("      Two-phase blocking capture:\n");
    printf("        Phase 1  Hunt a beacon matching --ssid on --channel.\n");
    printf("        Phase 2  Capture the WPA2 4-way EAPOL handshake\n");
    printf("                 (EtherType 0x888E) from that AP's BSSID.\n");
    printf("      Omitted arguments keep their previous value.\n");
    printf("      Defaults: channel 6, no SSID/BSSID filter.\n\n");
    printf("      After capture, paste the output into capture.txt then:\n");
    printf("        text2pcap -F pcap -l 105 capture.txt out.pcap\n");
    printf("        aircrack-ng out.pcap -w /usr/share/wordlists/rockyou.txt\n\n");
    printf("  config\n");
    printf("      Show the current sniffer settings.\n\n");
}

static void cmd_config(void)
{
    printf("\n[config] Current settings:\n");
    printf("  Channel : %d\n", g_cfg.channel);
    printf("  SSID    : %s\n", strlen(g_cfg.ssid) ? g_cfg.ssid : "(any)");
    if (g_cfg.bssid_set) print_mac("  BSSID   :", g_cfg.bssid);
    else                 printf("  BSSID   : (any)\n");
    printf("\n");
}

static void cmd_scan(void) { wifi_mgr_scan_and_print(); }

/**
 * @brief Orchestrate the two-phase capture session.
 *
 * The function blocks in a poll loop until SNIFFER_PHASE_COMPLETE.
 * On detecting the BEACON_HUNT → EAPOL_CAPTURE transition it switches
 * the promiscuous filter mask from MGMT-only to DATA-only HERE (in the
 * CLI task), NOT inside the callback.  This avoids calling driver APIs
 * from within the Wi-Fi task context, which can cause instability.
 *
 * Sequence:
 *   1. sniffer_reset()     — clear state, load config
 *   2. Set filter MGMT     — let Phase 1 beacons through
 *   3. esp_wifi_set_promiscuous(true) + register callback
 *   4. Poll loop:
 *      a. Detect phase change → switch filter to DATA, print learned BSSID
 *      b. Print live EAPOL counter
 *      c. Exit when phase == COMPLETE
 *   5. Tear down promiscuous mode
 *   6. sniffer_dump_text2pcap()
 */
static void cmd_sniffer(void)
{
    printf("\n[sniffer] Configuration:\n");
    printf("  Channel : %d\n", g_cfg.channel);
    printf("  SSID    : %s\n", strlen(g_cfg.ssid) ? g_cfg.ssid : "(any)");
    if (g_cfg.bssid_set) print_mac("  BSSID   :", g_cfg.bssid);
    else                 printf("  BSSID   : (auto from beacon)\n");

    /* ---- Initialise Wi-Fi driver ------------------------------------ */
    if (wifi_mgr_init() != ESP_OK) {
        printf("Wi-Fi init failed.\n");
        return;
    }

    /* ---- Reset capture state for this run --------------------------- */
    sniffer_reset(&g_cfg);

    /* ---- Phase 1 filter: management frames only --------------------- */
    wifi_promiscuous_filter_t mgmt_filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&mgmt_filter));

    if (wifi_mgr_start() != ESP_OK) {
        printf("Wi-Fi start failed.\n");
        return;
    }

    ESP_ERROR_CHECK(esp_wifi_set_channel(g_cfg.channel, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_rx_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    printf("\n[Phase 1] Hunting beacon"
           "%s on channel %d ...\n",
           strlen(g_cfg.ssid) ? " for SSID" : "",
           g_cfg.channel);
    if (strlen(g_cfg.ssid)) printf("          SSID = \"%s\"\n", g_cfg.ssid);

    /* ---- Blocking poll loop ----------------------------------------- */
    sniffer_phase_t last_phase = SNIFFER_PHASE_BEACON_HUNT;

    while (1) {
        sniffer_phase_t phase = sniffer_get_phase();

        /* ---- Phase 1 → Phase 2 transition ---- */
        if (phase == SNIFFER_PHASE_EAPOL_CAPTURE &&
            last_phase == SNIFFER_PHASE_BEACON_HUNT)
        {
            const uint8_t *b = sniffer_learned_bssid();
            printf("\n[Phase 1] Beacon captured!\n");
            printf("          BSSID : %02X:%02X:%02X:%02X:%02X:%02X\n",
                   b[0], b[1], b[2], b[3], b[4], b[5]);
            printf("[Phase 2] Capturing EAPOL 4-way handshake"
                   " (need %d frames)...\n", MAX_EAPOL_FRAMES);

            /* Switch filter to DATA-only.  Done HERE, not in the callback,
             * to keep driver API calls out of the Wi-Fi task context.   */
            wifi_promiscuous_filter_t data_filter = {
                .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA,
            };
            esp_wifi_set_promiscuous_filter(&data_filter);
            last_phase = SNIFFER_PHASE_EAPOL_CAPTURE;
        }

        /* ---- Live EAPOL progress ---- */
        if (phase == SNIFFER_PHASE_EAPOL_CAPTURE) {
            printf("\r  EAPOL frames: %d / %d  ",
                   sniffer_eapol_count(), MAX_EAPOL_FRAMES);
            fflush(stdout);
        }

        /* ---- Exit condition ---- */
        if (phase == SNIFFER_PHASE_COMPLETE) break;

        vTaskDelay(pdMS_TO_TICKS(100));
    }

    printf("\r  EAPOL frames: %d / %d  -- done.\n\n",
           sniffer_eapol_count(), MAX_EAPOL_FRAMES);

    /* ---- Tear down promiscuous mode --------------------------------- */
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);

    /* ---- Dump in text2pcap format ----------------------------------- */
    sniffer_dump_text2pcap();
    /* Prompt is printed by cli_task() after we return */
}

/* ============================================================
   ARGUMENT PARSER + DISPATCHER
   ============================================================ */

/**
 * @brief Parse one command line and dispatch to the appropriate handler.
 *
 * Parsing strategy: strtok() replaces delimiters in-place, so the first
 * token (saved as @c cmd) must be used for dispatch — not the original
 * @p input pointer (which is corrupted after the first strtok call).
 *
 * Arguments update g_cfg before the command handler runs.  Omitted
 * arguments are not touched, so the last-set value persists.
 *
 * @param input  Null-terminated command line (will be modified by strtok).
 */
static void cli_dispatch(char *input)
{
    char *cmd   = NULL;
    char *token = strtok(input, " ");

    while (token != NULL) {

        if (cmd == NULL) {
            cmd = token;

        } else if (strcmp(token, "--ssid") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                strncpy(g_cfg.ssid, token, MAX_SSID_LEN);
                g_cfg.ssid[MAX_SSID_LEN] = '\0';
                printf("[config] SSID    -> \"%s\"\n", g_cfg.ssid);
            }

        } else if (strcmp(token, "--channel") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                int ch = atoi(token);
                if (ch >= CHANNEL_MIN && ch <= CHANNEL_MAX) {
                    g_cfg.channel = (uint8_t)ch;
                    printf("[config] Channel -> %d\n", g_cfg.channel);
                } else {
                    printf("Invalid channel — must be %d-%d.\n",
                           CHANNEL_MIN, CHANNEL_MAX);
                }
            }

        } else if (strcmp(token, "--bssid") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                unsigned int tmp[6];
                if (sscanf(token, "%02x:%02x:%02x:%02x:%02x:%02x",
                           &tmp[0], &tmp[1], &tmp[2],
                           &tmp[3], &tmp[4], &tmp[5]) == 6) {
                    for (int i = 0; i < 6; i++)
                        g_cfg.bssid[i] = (uint8_t)tmp[i];
                    g_cfg.bssid_set = true;
                    print_mac("[config] BSSID   ->", g_cfg.bssid);
                } else {
                    printf("Invalid BSSID — expected XX:XX:XX:XX:XX:XX.\n");
                }
            }
        }

        token = strtok(NULL, " ");
    }

    /* Dispatch on the saved first token, not the corrupted input buffer */
    if      (cmd == NULL)                    { /* empty line — ignore */ }
    else if (strcmp(cmd, "help")    == 0)    cmd_help();
    else if (strcmp(cmd, "scan")    == 0)    cmd_scan();
    else if (strcmp(cmd, "sniffer") == 0)    cmd_sniffer();
    else if (strcmp(cmd, "config")  == 0)    cmd_config();
    else    printf("Unknown command '%s'. Type 'help'.\n", cmd);
}

/* ============================================================
   CLI TASK
   ============================================================ */

void cli_task(void *pv)
{
    char buffer[CLI_BUFFER_SIZE];
    int  idx = 0;
    char c;

    cmd_help();
    print_prompt();

    while (1) {
        if (read(STDIN_FILENO, &c, 1) > 0) {

            if (c == '\n' || c == '\r') {
                if (idx > 0) {
                    buffer[idx] = '\0';
                    printf("\n");
                    cli_dispatch(buffer);
                    idx = 0;
                }
                print_prompt();

            } else if (c == '\b' || c == 127 || c == 8) { /* Backspace */
                if (idx > 0) {
                    idx--;
                    printf("\b \b");
                    fflush(stdout);
                }

            } else if (idx < CLI_BUFFER_SIZE - 1) {
                buffer[idx++] = c;
                printf("%c", c);
                fflush(stdout);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}