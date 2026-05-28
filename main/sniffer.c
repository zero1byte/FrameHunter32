/**
 * @file  sniffer.c
 * @brief Two-phase 802.11 capture engine — implementation.
 */

#include "sniffer.h"

#include <string.h>
#include <stdio.h>

/* ============================================================
   PRIVATE CONSTANTS
   ============================================================ */

/** 802.11 management subtype for Beacon. */
#define SUBTYPE_BEACON      8

/**
 * Byte offset where Information Elements begin inside a beacon or
 * probe-response frame:  24 B MAC header + 12 B fixed beacon fields.
 */
#define BEACON_IE_OFFSET    36

/** EtherType for IEEE 802.1X (EAPOL). */
#define ETHERTYPE_EAPOL     0x888E

/* ============================================================
   PRIVATE TYPES
   ============================================================ */

/** One captured raw 802.11 frame (FCS already stripped). */
typedef struct {
    uint16_t length;
    uint8_t  payload[MAX_FRAME_SIZE];
} frame_t;

/* ============================================================
   MODULE STATE  (all static — not visible outside this file)
   ============================================================ */

static sniffer_cfg_t   g_cfg;
static frame_t         g_frames[MAX_SNIFF_PACKETS];
static int             g_frame_count   = 0;
static int             g_eapol_count   = 0;
static sniffer_phase_t g_phase         = SNIFFER_PHASE_BEACON_HUNT;
static uint8_t         g_learned_bssid[6] = {0};

/* ============================================================
   PRIVATE HELPERS
   ============================================================ */

/**
 * @brief Walk the IE list and extract the SSID (tag 0x00).
 *
 * @param[in]  payload   Raw frame bytes.
 * @param[in]  len       FCS-stripped frame length.
 * @param[out] out_ssid  Caller buffer, at least MAX_SSID_LEN+1 bytes.
 * @return true  if SSID IE found and copied.
 * @return false if no SSID IE present (out_ssid[0] == '\0').
 */
static bool extract_ssid_ie(const uint8_t *payload, int len,
                             char out_ssid[MAX_SSID_LEN + 1])
{
    out_ssid[0] = '\0';
    int pos = BEACON_IE_OFFSET;

    while (pos + 2 <= len) {
        uint8_t tag     = payload[pos];
        uint8_t tag_len = payload[pos + 1];

        if (pos + 2 + tag_len > len) break;   /* IE overruns frame */

        if (tag == 0x00) {
            uint8_t n = (tag_len > MAX_SSID_LEN) ? MAX_SSID_LEN : tag_len;
            memcpy(out_ssid, &payload[pos + 2], n);
            out_ssid[n] = '\0';
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

/**
 * @brief Copy a frame into the next free buffer slot, stripping the 4-byte FCS.
 *
 * rx_ctrl.sig_len includes the trailing hardware CRC32.
 * DLT 105 (raw 802.11, no FCS) requires those bytes to be absent,
 * otherwise Wireshark parses the CRC as frame body → "Malformed Packet".
 *
 * @param payload  Raw frame bytes from promiscuous pkt->payload.
 * @param raw_len  pkt->rx_ctrl.sig_len (includes 4-byte FCS).
 * @return true if stored, false if buffer is already full.
 */
static bool store_frame(const uint8_t *payload, uint16_t raw_len)
{
    if (g_frame_count >= MAX_SNIFF_PACKETS) return false;

    uint16_t len = (raw_len > 4) ? (raw_len - 4) : raw_len;
    if (len > MAX_FRAME_SIZE) len = MAX_FRAME_SIZE;

    g_frames[g_frame_count].length = len;
    memcpy(g_frames[g_frame_count].payload, payload, len);
    g_frame_count++;
    return true;
}

/**
 * @brief Resolve the BSSID from an 802.11 data frame.
 *
 * The correct address field depends on the ToDS/FromDS bits:
 *
 *  DS bits │ Addr1 [4..9]  │ Addr2 [10..15] │ Addr3 [16..21]
 *  ────────┼───────────────┼────────────────┼───────────────
 *  00      │ DA            │ SA             │ BSSID
 *  01 →AP  │ BSSID         │ SA (STA)       │ DA
 *  10 ←AP  │ DA (STA)      │ BSSID          │ SA
 *  11 WDS  │ RA            │ TA             │ DA
 *
 * BUG FIX: original code always used payload[16] (Addr3), which is only
 * the BSSID in the 00 (IBSS) case.  In infrastructure traffic
 * (ToDS=1,FromDS=0 or ToDS=0,FromDS=1) the BSSID is in a different field.
 *
 * @param payload  Frame bytes (at least 22 bytes assumed).
 * @return Pointer into payload — no allocation, no copy.
 */
static const uint8_t *data_frame_bssid(const uint8_t *payload)
{
    switch (payload[1] & 0x03) {
        case 0x01: return &payload[4];   /* ToDS=1, FromDS=0 → BSSID = Addr1 */
        case 0x02: return &payload[10];  /* ToDS=0, FromDS=1 → BSSID = Addr2 */
        default:   return &payload[16];  /* IBSS (0x00) or WDS (0x03) → Addr3 */
    }
}

/* ============================================================
   PUBLIC API
   ============================================================ */

void sniffer_reset(const sniffer_cfg_t *cfg)
{
    memcpy(&g_cfg, cfg, sizeof(sniffer_cfg_t));
    memset(g_frames,        0, sizeof(g_frames));
    memset(g_learned_bssid, 0, sizeof(g_learned_bssid));
    g_frame_count = 0;
    g_eapol_count = 0;
    /* BUG FIX: original code never reset ssid_identifier_frame between
     * sniffer runs, so the second invocation skipped beacon hunt entirely
     * and tried to capture EAPOL with an all-zero BSSID filter.        */
    g_phase = SNIFFER_PHASE_BEACON_HUNT;
}

sniffer_phase_t    sniffer_get_phase(void)       { return g_phase;         }
int                sniffer_frame_count(void)     { return g_frame_count;   }
int                sniffer_eapol_count(void)     { return g_eapol_count;   }
const uint8_t     *sniffer_learned_bssid(void)   { return g_learned_bssid; }

/* ============================================================
   PROMISCUOUS RX CALLBACK
   ============================================================ */

/**
 * @brief Handle one incoming frame.
 *
 * Runs in the Wi-Fi driver task context — must be fast, no blocking,
 * no printf.  The IRAM_ATTR placement avoids flash cache miss penalties
 * during high-throughput capture.
 *
 * State machine:
 *
 *  ┌─────────────────┐  beacon matches SSID   ┌──────────────────┐
 *  │ BEACON_HUNT     │ ─────────────────────► │ EAPOL_CAPTURE    │
 *  │ (MGMT filter)   │   store beacon,         │ (DATA filter)    │
 *  └─────────────────┘   learn BSSID           └──────┬───────────┘
 *                                                      │ 4 EAPOL stored
 *                                                      ▼
 *                                              ┌──────────────────┐
 *                                              │ COMPLETE         │
 *                                              └──────────────────┘
 *
 * The filter mask change (MGMT → DATA) is performed by the CLI polling
 * loop on detecting the phase transition, NOT here, to avoid calling
 * driver APIs from within the callback.
 */
void sniffer_rx_cb(void *buf, wifi_promiscuous_pkt_type_t pkt_type)
{
    if (g_phase == SNIFFER_PHASE_COMPLETE) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;

    /* Discard hardware receive errors */
    if (pkt->rx_ctrl.rx_state != 0) return;

    const uint8_t *payload = pkt->payload;
    uint16_t raw_len = pkt->rx_ctrl.sig_len;

    /* Frame-Control fields */
    uint16_t fc      = payload[0] | ((uint16_t)payload[1] << 8);
    uint8_t  fc_type = (fc >> 2) & 0x3;   /* 0=Mgmt  1=Ctrl  2=Data */
    uint8_t  subtype = (fc >> 4) & 0x0F;

    /* Strip the 4-byte hardware FCS before any length-based checks.
     * sig_len includes the trailing CRC32 appended by the ESP32 radio.
     * DLT 105 expects frames without FCS; keeping them causes Wireshark
     * to flag every frame as "Malformed Packet".                       */
    uint16_t clean_len = (raw_len > 4) ? (raw_len - 4) : raw_len;

    /* ================================================================
       PHASE 1 — BEACON HUNT
       Accept only management beacons whose SSID matches the target.
       ================================================================ */
    if (g_phase == SNIFFER_PHASE_BEACON_HUNT)
    {
        /* BUG FIX: original code had no hard pkt_type / fc_type guard here,
         * so data and control frames leaked through during beacon hunt.  */
        if (pkt_type != WIFI_PKT_MGMT) return;
        if (fc_type  != 0)             return;  /* management class only */
        if (subtype  != SUBTYPE_BEACON) return;

        /* ---- SSID filter ----
         * BUG FIX: original code lacked the strlen() guard.  When g_cfg.ssid
         * is "" (no --ssid given), strcmp returned nonzero for every real
         * SSID, filtering ALL beacons and leaving the sniffer stuck.   */
        if (strlen(g_cfg.ssid) > 0) {
            char ssid_buf[MAX_SSID_LEN + 1];
            bool has_ssid = extract_ssid_ie(payload, clean_len, ssid_buf);
            if (!has_ssid || strcmp(ssid_buf, g_cfg.ssid) != 0) return;
        }

        /* ---- Optional manual BSSID override ---- */
        /* In a beacon: BSSID is at Addr3 [16..21] (also == Addr2 / SA) */
        if (g_cfg.bssid_set) {
            if (memcmp(&payload[16], g_cfg.bssid, 6) != 0) return;
        }

        /* ---- Beacon matches — store it and learn BSSID ---- */
        store_frame(payload, raw_len);

        /* BUG FIX: original code used g_cfg.bssid (may be all-zeros) for
         * EAPOL filtering.  We now populate g_learned_bssid from the beacon
         * so Phase 2 filters on the real AP BSSID even without --bssid.  */
        memcpy(g_learned_bssid, &payload[16], 6);

        /* Transition — CLI polling loop will see the phase change and
         * immediately switch the filter mask to DATA-only.             */
        g_phase = SNIFFER_PHASE_EAPOL_CAPTURE;
        return;
    }

    /* ================================================================
       PHASE 2 — EAPOL CAPTURE
       Accept 802.11 DATA frames from the learned BSSID carrying
       EtherType 0x888E (IEEE 802.1X).
       ================================================================ */
    if (g_phase == SNIFFER_PHASE_EAPOL_CAPTURE)
    {
        /* BUG FIX: original code had no hard DATA-type guard during this
         * phase; management retransmissions slipped through.           */
        if (pkt_type != WIFI_PKT_DATA) return;
        if (fc_type  != 2)             return;  /* data class only */

        /* ---- BSSID filter using learned value from beacon ------------
         * BUG FIX: original DS-bits logic always read payload[16] (Addr3)
         * regardless of ToDS/FromDS, which is only the BSSID in IBSS mode.
         * Infrastructure traffic (ToDS=1 or FromDS=1) puts BSSID in a
         * different address field.  data_frame_bssid() handles all cases. */
        const uint8_t *frame_bssid = data_frame_bssid(payload);
        if (memcmp(frame_bssid, g_learned_bssid, 6) != 0) return;

        /* ---- Compute 802.11 MAC header length -----------------------
         * Base 24 B, plus optional fields:
         *   +2 B QoS Control   when subtype bit-3 is set (QoS Data)
         *   +6 B Address-4     when ToDS==1 AND FromDS==1 (4-addr WDS) */
        int hdr_len = 24;
        if (subtype & 0x8)               hdr_len += 2;
        if ((payload[1] & 0x03) == 0x03) hdr_len += 6;

        /* Need: hdr_len + 6 B LLC/SNAP + 2 B EtherType */
        if (clean_len < (uint16_t)(hdr_len + 8)) return;

        /* ---- EtherType check at LLC+6 ---- */
        uint16_t ethertype = ((uint16_t)payload[hdr_len + 6] << 8)
                           |            payload[hdr_len + 7];
        if (ethertype != ETHERTYPE_EAPOL) return;

        if (!store_frame(payload, raw_len)) return;
        g_eapol_count++;

        if (g_eapol_count >= MAX_EAPOL_FRAMES) {
            g_phase = SNIFFER_PHASE_COMPLETE;
        }
    }
}

/* ============================================================
   HEX DUMP — text2pcap FORMAT
   ============================================================ */

void sniffer_dump_text2pcap(void)
{
    printf("\n");
    printf("# =======================================================\n");
    printf("# ESP32 WPA2 Handshake Capture\n");
    printf("# Frames : %d  (1 beacon + %d EAPOL)\n",
           g_frame_count, g_eapol_count);
    printf("# FCS    : stripped (4 bytes removed per frame)\n");
    printf("# DLT    : 105 (IEEE 802.11 raw, no radiotap, no FCS)\n");
    printf("#\n");
    printf("# Convert to pcap:\n");
    printf("#   text2pcap -F pcap -l 105 capture.txt out.pcap\n");
    printf("#\n");
    printf("# Crack with aircrack-ng:\n");
    printf("#   aircrack-ng out.pcap -w /usr/share/wordlists/rockyou.txt\n");
    printf("# =======================================================\n");

    for (int i = 0; i < g_frame_count; i++) {
        const frame_t *f     = &g_frames[i];
        const char    *label = (i == 0) ? "Beacon" : "EAPOL";
        printf("# Frame %d  [%s]  %d bytes\n", i + 1, label, f->length);

        for (int j = 0; j < f->length; j++) {
            if (j % 16 == 0) printf("%06x ", j);
            printf("%02x ", f->payload[j]);
            if ((j % 16 == 15) || (j == f->length - 1)) printf("\n");
        }
        printf("\n");  /* blank line = frame boundary for text2pcap */
    }

    printf("# =======================================================\n");
    printf("# End of capture\n");
    printf("# =======================================================\n\n");
}