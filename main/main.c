/**
 * @file  main.c
 * @brief Application entry point.
 *
 * Configures UART0, initialises NVS, then spawns the CLI task.
 * All application logic lives in cli.c / sniffer.c / wifi_mgr.c.
 */

#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "nvs_flash.h"
#include "esp_err.h"
#include "driver/uart.h"

#include "cli.h"

void app_main(void)
{
    /* ---- UART 0 (serial monitor / IDF console) ---- */
    const uart_config_t uart_cfg = {
        .baud_rate  = 115200,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
    };
    uart_param_config(UART_NUM_0, &uart_cfg);
    uart_set_pin(UART_NUM_0,
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    /* ---- NVS (Non-Volatile Storage — required by Wi-Fi driver) ----
     * Erase and reinitialise if the partition is full or was written
     * by a different firmware version.                               */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* ---- Spawn CLI task ---- */
    xTaskCreate(cli_task, "cli_task", 4096, NULL, 5, NULL);
}