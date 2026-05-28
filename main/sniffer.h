/**
 * @file  sniffer.h
 * @brief Two-phase 802.11 capture engine.
 *
 * Phase 1 — BEACON HUNT
 *   Listens on MGMT frames only.  Accepts the first beacon whose SSID IE
 *   matches the configured target.  Stores the beacon frame and extracts
 *   the AP BSSID for use in Phase 2.
 *
 * Phase 2 — EAPOL CAPTURE
 *   Switches the promiscuous filter to DATA frames only.  Accepts frames
 *   carrying EtherType 0x888E (IEEE 802.1X / EAPOL) from the learned BSSID.
 *   Stops after MAX_EAPOL_FRAMES frames, advancing to PHASE_COMPLETE.
 *
 * The dump function emits text2pcap-compatible output.  Workflow:
 *   text2pcap -F pcap -l 105 capture.txt out.pcap
 *   aircrack-ng out.pcap -w wordlist.txt
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi.h"

/* ============================================================
   COMPILE-TIME LIMITS
   ============================================================ */

#define MAX_BEACON_FRAMES   1   /**< One beacon per session (AP identification) */
#define MAX_EAPOL_FRAMES    4   /**< Full 4-way handshake (M1–M4)               */
#define MAX_SNIFF_PACKETS   (MAX_BEACON_FRAMES + MAX_EAPOL_FRAMES)
#define MAX_FRAME_SIZE      512
#define MAX_SSID_LEN        32

/* ============================================================
   TYPES
   ============================================================ */

/**
 * @brief Capture phase — drives both the callback logic and the
 *        promiscuous filter mask selection in the CLI polling loop.
 */
typedef enum {
    SNIFFER_PHASE_BEACON_HUNT   = 0, /**< Waiting for matching beacon      */
    SNIFFER_PHASE_EAPOL_CAPTURE = 1, /**< Beacon stored; hunting EAPOL     */
    SNIFFER_PHASE_COMPLETE      = 2, /**< MAX_EAPOL_FRAMES stored; done    */
} sniffer_phase_t;

/**
 * @brief Per-session capture configuration.
 *
 * Populated by the CLI argument parser and passed to sniffer_reset().
 * Fields not supplied by the user retain their previous value.
 */
typedef struct {
    char    ssid[MAX_SSID_LEN + 1]; /**< Target SSID; "" = accept any      */
    uint8_t channel;                /**< 802.11 channel to listen on       */
    uint8_t bssid[6];               /**< Manual BSSID override             */
    bool    bssid_set;              /**< true when --bssid was supplied    */
} sniffer_cfg_t;

/* ============================================================
   PUBLIC API
   ============================================================ */

/**
 * @brief Reset all internal capture state and load a new configuration.
 *
 * Must be called before registering sniffer_rx_cb() with
 * esp_wifi_set_promiscuous_rx_cb().  Clears the frame buffer, resets
 * counters, and sets the phase back to SNIFFER_PHASE_BEACON_HUNT.
 *
 * @param cfg  Pointer to the desired session configuration.
 */
void sniffer_reset(const sniffer_cfg_t *cfg);

/**
 * @brief Promiscuous RX callback.
 *
 * Pass directly to esp_wifi_set_promiscuous_rx_cb().  Runs in the
 * Wi-Fi driver task — no blocking calls, no printf.
 */
void sniffer_rx_cb(void *buf, wifi_promiscuous_pkt_type_t pkt_type);

/**
 * @brief Return the current capture phase.
 *
 * Safe to call from any task; the variable is written only from the
 * Wi-Fi driver task (single writer, single reader on ESP32).
 */
sniffer_phase_t sniffer_get_phase(void);

/** @brief Total frames stored in the capture buffer so far. */
int sniffer_frame_count(void);

/** @brief EAPOL frames stored so far (subset of sniffer_frame_count). */
int sniffer_eapol_count(void);

/**
 * @brief BSSID learned from the first matching beacon.
 *
 * Valid only after sniffer_get_phase() returns SNIFFER_PHASE_EAPOL_CAPTURE
 * or SNIFFER_PHASE_COMPLETE.
 *
 * @return Pointer to a 6-byte array (module-internal storage, do not free).
 */
const uint8_t *sniffer_learned_bssid(void);

/**
 * @brief Dump all captured frames to stdout in text2pcap(1) format.
 *
 * Frames are emitted as hex blocks separated by blank lines.
 * Lines starting with '#' are comments ignored by text2pcap.
 * Hardware FCS (4 bytes) is stripped before storage, so Wireshark
 * receives clean 802.11 frames with DLT 105.
 */
void sniffer_dump_text2pcap(void);