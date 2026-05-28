/**
 * @file  cli.h
 * @brief UART command-line interface task.
 *
 * Provides an interactive shell over UART0 with the following commands:
 *
 *   help
 *   scan
 *   sniffer [--ssid <name>] [--channel <1-13>] [--bssid <XX:XX:XX:XX:XX:XX>]
 *   config
 *
 * The sniffer command blocks the CLI task for the duration of the capture
 * and prints results in text2pcap format before returning to the prompt.
 */

#pragma once

/** UART receive buffer size (bytes). */
#define CLI_BUFFER_SIZE  128

/** Valid 802.11 channel range. */
#define CHANNEL_MIN       1
#define CHANNEL_MAX      13

/**
 * @brief FreeRTOS CLI task entry point.
 *
 * Usage:
 *   xTaskCreate(cli_task, "cli_task", 4096, NULL, 5, NULL);
 *
 * @param pv  Unused (pass NULL).
 */
void cli_task(void *pv);