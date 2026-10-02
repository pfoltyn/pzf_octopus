// espbridge: turns the Pico into a USB<->UART bridge for the ESP32 UART0,
// with esptool-compatible auto-reset so `esptool.py` can enter download mode
// and read eFuses. Passive sniffing is unaffected; reflash picosniff to go back.
//
// Wiring (in addition to the existing sniffer taps):
//   Pico GP6  <-  ESP32 UART0 TX   (Pico receives)      [already connected]
//   Pico GP7  ->  ESP32 UART0 RX   (Pico transmits)      [already connected]
//   Pico GP14 <-> ESP32 EN  / CHIP_PU  (reset, open-drain)   [ADD THIS WIRE]
//   Pico GP15 <-> ESP32 IO0 / BOOT     (strap,  open-drain)  [ADD THIS WIRE]
//   Pico GND  -   ESP32 GND                               [already connected]
//
// EN and IO0 are driven open-drain (drive LOW, release HIGH) so they never
// fight the board's own pull-ups or auto-reset circuit.

#include <stdint.h>
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "tusb.h"
#include "pio_uart.pio.h"

#define PIN_RX   6          // from ESP32 TX
#define PIN_TX   7          // to   ESP32 RX
#define PIN_EN   14         // ESP32 EN  (open-drain)
#define PIN_IO0  15         // ESP32 IO0 (open-drain)

static PIO pio = pio0;
static uint sm_tx, sm_rx, off_tx, off_rx;
static uint32_t cur_baud = 115200;

static void uart_set_baud(uint32_t baud) {
    if (baud < 300 || baud > 6000000) return;
    cur_baud = baud;
    float div = (float)clock_get_hz(clk_sys) / (8.0f * baud);
    pio_sm_set_clkdiv(pio, sm_tx, div);
    pio_sm_set_clkdiv(pio, sm_rx, div);
    pio_sm_clear_fifos(pio, sm_rx);
}

static void uart_init_pio(void) {
    // TX
    off_tx = pio_add_program(pio, &uart_tx_program);
    sm_tx = pio_claim_unused_sm(pio, true);
    pio_sm_config c = uart_tx_program_get_default_config(off_tx);
    sm_config_set_out_shift(&c, true, false, 32);   // shift right, no autopull
    sm_config_set_out_pins(&c, PIN_TX, 1);
    sm_config_set_sideset_pins(&c, PIN_TX);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_TX);
    pio_sm_set_pins_with_mask(pio, sm_tx, 1u << PIN_TX, 1u << PIN_TX);
    pio_sm_set_pindirs_with_mask(pio, sm_tx, 1u << PIN_TX, 1u << PIN_TX);
    pio_gpio_init(pio, PIN_TX);
    pio_sm_init(pio, sm_tx, off_tx, &c);
    pio_sm_set_enabled(pio, sm_tx, true);

    // RX
    off_rx = pio_add_program(pio, &uart_rx_program);
    sm_rx = pio_claim_unused_sm(pio, true);
    pio_sm_config r = uart_rx_program_get_default_config(off_rx);
    sm_config_set_in_pins(&r, PIN_RX);
    sm_config_set_jmp_pin(&r, PIN_RX);
    sm_config_set_in_shift(&r, true, true, 8);      // shift right, autopush @ 8
    sm_config_set_fifo_join(&r, PIO_FIFO_JOIN_RX);
    pio_sm_set_consecutive_pindirs(pio, sm_rx, PIN_RX, 1, false);
    pio_gpio_init(pio, PIN_RX);
    gpio_pull_up(PIN_RX);
    pio_sm_init(pio, sm_rx, off_rx, &r);
    pio_sm_set_enabled(pio, sm_rx, true);

    uart_set_baud(cur_baud);
}

// Open-drain: level 1 = release (input, external pull-up), level 0 = drive low.
static void od_set(uint pin, bool high) {
    if (high) {
        gpio_set_dir(pin, GPIO_IN);
    } else {
        gpio_put(pin, 0);
        gpio_set_dir(pin, GPIO_OUT);
    }
}

static void od_init(uint pin) {
    gpio_init(pin);
    gpio_put(pin, 0);
    gpio_set_dir(pin, GPIO_IN);      // released (high) at boot
}

// esptool ClassicReset drives DTR->IO0, RTS->EN through a transistor network.
// The resulting ESP32 pin levels reduce to:
//   EN  low  only when (rts && !dtr)   IO0 low only when (dtr && !rts)
void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts) {
    (void)itf;
    od_set(PIN_EN,  !(rts && !dtr));
    od_set(PIN_IO0, !(dtr && !rts));
}

void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *coding) {
    (void)itf;
    uart_set_baud(coding->bit_rate);
}

int main(void) {
    set_sys_clock_khz(120000, true);
    od_init(PIN_EN);
    od_init(PIN_IO0);
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);

    uart_init_pio();
    tud_init(0);

    while (true) {
        tud_task();

        // USB -> ESP32
        if (tud_cdc_available()) {
            uint8_t buf[64];
            uint32_t n = tud_cdc_read(buf, sizeof(buf));
            for (uint32_t i = 0; i < n; i++)
                pio_sm_put_blocking(pio, sm_tx, (uint32_t)buf[i]);
            gpio_xor_mask(1u << PICO_DEFAULT_LED_PIN);
        }
        // ESP32 -> USB
        while (!pio_sm_is_rx_fifo_empty(pio, sm_rx) && tud_cdc_write_available() >= 1) {
            uint8_t b = (uint8_t)(pio_sm_get(pio, sm_rx) >> 24);
            tud_cdc_write_char((char)b);
        }
        tud_cdc_write_flush();
    }
}
