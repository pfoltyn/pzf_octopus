// fakencp: turns the Pico into a raw USB<->UART pipe on the ESP32's *EZSP* UART
// so a host script (ncptalk.py fakencp) can impersonate the MGM210P NCP to the
// ESP32. The real NCP is left disconnected (its traces are already cut). The
// goal: answer the ESP's boot handshake and, on getSecurityKeyStatus, lie
// "KEY_NOT_SET" to try to provoke the host into sending setSecurityKey (which
// carries the 16-byte key in plaintext).
//
// Wiring (Pico <-> ESP32, directions from the ESP's point of view):
//   Pico GP9  <-  ESP EZSP TX    (Pico receives host->NCP)     [PIO UART RX]
//   Pico GP8  ->  ESP EZSP RX    (Pico transmits NCP->host)    [PIO UART TX]
//   Pico GP14 ->  ESP CTS in     (drive LOW = "host, you may send")
//   Pico GP11 <-  ESP RTS out    (host "ready to receive"; gates our TX)
//   Pico GP6  <-  ESP console TX (tap, boot-banner gating only)
//   Pico GND  -   ESP GND
//
// 115200 8N1. GP8 == ESP GPIO12/MTDI flash-voltage strap: it MUST stay high-Z
// through ESP reset, or the ESP boot-loops ("invalid header"). We keep GP8
// high-Z until 250 ms after the ROM banner "ets Jul" appears on the console
// tap, then engage the TX driver. 1200-baud touch -> BOOTSEL.
//
// USB is a *pure raw* byte pipe of the ESP EZSP link only (no tagging), so the
// host-side ASH reader sees a clean stream. LED on = engaged.

#include <stdint.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "tusb.h"
#include "pico/bootrom.h"
#include "pio_uart.pio.h"

#define BAUD     115200
#define PIN_RX   9      // from ESP EZSP TX   (read)
#define PIN_TX   8      // to   ESP EZSP RX   (drive; == ESP MTDI strap -> gated)
#define PIN_CTS  14     // to   ESP CTS in    (drive low = host may send)
#define PIN_RTS  11     // from ESP RTS out   (gates our TX to the ESP)
#define PIN_DBG  6      // from ESP console   (boot-banner gating)

static PIO p_rx = pio0;     // uart_rx on GP9 + console tap on GP6
static PIO p_tx = pio1;     // uart_tx on GP8
static uint sm_rx, sm_tap, sm_tx;

static void rx_init(PIO p, uint sm, uint pin, uint off) {
    pio_sm_config r = uart_rx_program_get_default_config(off);
    sm_config_set_in_pins(&r, pin);
    sm_config_set_jmp_pin(&r, pin);
    sm_config_set_in_shift(&r, true, true, 8);
    sm_config_set_fifo_join(&r, PIO_FIFO_JOIN_RX);
    sm_config_set_clkdiv(&r, (float)clock_get_hz(clk_sys) / (8.0f * BAUD));
    pio_sm_set_consecutive_pindirs(p, sm, pin, 1, false);
    pio_gpio_init(p, pin);
    gpio_pull_up(pin);
    pio_sm_init(p, sm, off, &r);
    pio_sm_set_enabled(p, sm, true);
}

static void tx_init(PIO p, uint sm, uint pin, uint off) {
    pio_sm_config c = uart_tx_program_get_default_config(off);
    sm_config_set_out_shift(&c, true, false, 32);
    sm_config_set_out_pins(&c, pin, 1);
    sm_config_set_sideset_pins(&c, pin);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_TX);
    sm_config_set_clkdiv(&c, (float)clock_get_hz(clk_sys) / (8.0f * BAUD));
    pio_sm_set_pins_with_mask(p, sm, 1u << pin, 1u << pin);   // idle high (when driven)
    pio_sm_set_pindirs_with_mask(p, sm, 0, 1u << pin);        // start HIGH-Z (gated off)
    pio_gpio_init(p, pin);
    pio_sm_init(p, sm, off, &c);
    pio_sm_set_enabled(p, sm, true);
}

static void engage_tx(bool on) {
    pio_sm_set_consecutive_pindirs(p_tx, sm_tx, PIN_TX, 1, on);
    gpio_put(PICO_DEFAULT_LED_PIN, on);
}

void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *c) {
    (void)itf;
    if (c->bit_rate == 1200) reset_usb_boot(0, 0);
}

int main(void) {
    set_sys_clock_khz(120000, true);

    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    gpio_put(PICO_DEFAULT_LED_PIN, 0);

    // CTS to ESP: assert low ("host, you may send"). GPIO14 is not an ESP strap,
    // so it is safe to drive from reset.
    gpio_init(PIN_CTS);
    gpio_put(PIN_CTS, 0);
    gpio_set_dir(PIN_CTS, GPIO_OUT);

    // ESP RTS input (host "ready to receive"); active low.
    gpio_init(PIN_RTS);
    gpio_set_dir(PIN_RTS, GPIO_IN);
    gpio_pull_up(PIN_RTS);

    uint off_rx = pio_add_program(p_rx, &uart_rx_program);
    sm_rx  = pio_claim_unused_sm(p_rx, true); rx_init(p_rx, sm_rx,  PIN_RX,  off_rx);
    sm_tap = pio_claim_unused_sm(p_rx, true); rx_init(p_rx, sm_tap, PIN_DBG, off_rx);

    uint off_tx = pio_add_program(p_tx, &uart_tx_program);
    sm_tx = pio_claim_unused_sm(p_tx, true); tx_init(p_tx, sm_tx, PIN_TX, off_tx);

    tud_init(0);

    static const char BANNER[] = "ets Jul";
    int mi = 0;
    uint32_t boot_ms = 0;
    bool engaged = false;

    while (true) {
        tud_task();

        // ESP EZSP TX (GP9) -> USB  (raw)
        while (!pio_sm_is_rx_fifo_empty(p_rx, sm_rx) && tud_cdc_write_available() >= 1) {
            uint8_t b = (uint8_t)(pio_sm_get(p_rx, sm_rx) >> 24);
            tud_cdc_write_char((char)b);
        }
        tud_cdc_write_flush();

        // USB -> ESP EZSP RX (GP8), only once engaged and while the ESP asserts RTS.
        if (engaged && tud_cdc_available() && gpio_get(PIN_RTS) == 0) {
            uint8_t buf[64];
            uint32_t n = tud_cdc_read(buf, sizeof(buf));
            for (uint32_t i = 0; i < n; i++)
                pio_sm_put_blocking(p_tx, sm_tx, (uint32_t)buf[i]);
        }

        // Console tap (GP6): watch for the ROM banner, then engage TX 250 ms later.
        while (!pio_sm_is_rx_fifo_empty(p_rx, sm_tap)) {
            uint8_t b = (uint8_t)(pio_sm_get(p_rx, sm_tap) >> 24);
            if (b == (uint8_t)BANNER[mi]) {
                if (++mi == (int)sizeof(BANNER) - 1) {
                    mi = 0;
                    boot_ms = to_ms_since_boot(get_absolute_time());
                    if (engaged) { engage_tx(false); engaged = false; }  // new boot -> re-gate
                }
            } else {
                mi = (b == (uint8_t)BANNER[0]) ? 1 : 0;
            }
        }
        if (!engaged && boot_ms
            && to_ms_since_boot(get_absolute_time()) - boot_ms > 250) {
            engage_tx(true);
            engaged = true;
        }
    }
}
