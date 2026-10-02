// ncpbridge: USB<->UART bridge to the MGM210P (Zigbee NCP) side of the cut
// Octopus Mini link, so a host script on the Mac can speak ASH/EZSP directly
// to the NCP. The ESP32 side is left isolated (traces already cut).
//
// Wiring (Pico <-> NCP), directions from the NCP's point of view:
//   Pico GP2 -> NCP RX   (Pico transmits to NCP)      [PIO UART TX]
//   Pico GP3 <- NCP TX   (Pico receives from NCP)      [PIO UART RX]
//   Pico GP4 <- NCP RTS  (NCP "ready to receive", active low) [read, gates TX]
//   Pico GP5 -> NCP CTS  (host "you may send", active low)    [driven low = ready]
//   Pico GND -  NCP GND
//
// 115200 8N1. GP6-GP11 (the ESP32 side) are left as inputs / untouched.

#include <stdint.h>
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "tusb.h"
#include "pico/bootrom.h"
#include "pio_uart.pio.h"

#define PIN_TX   2          // to   NCP RX (drive)
#define PIN_RX   3          // from NCP TX (read)
#define PIN_RTS  12         // (unused)
#define PIN_CTS  4          // NCP flow input (assert low = NCP may send)

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
    off_tx = pio_add_program(pio, &uart_tx_program);
    sm_tx = pio_claim_unused_sm(pio, true);
    pio_sm_config c = uart_tx_program_get_default_config(off_tx);
    sm_config_set_out_shift(&c, true, false, 32);
    sm_config_set_out_pins(&c, PIN_TX, 1);
    sm_config_set_sideset_pins(&c, PIN_TX);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_TX);
    pio_sm_set_pins_with_mask(pio, sm_tx, 1u << PIN_TX, 1u << PIN_TX);
    pio_sm_set_pindirs_with_mask(pio, sm_tx, 1u << PIN_TX, 1u << PIN_TX);
    pio_gpio_init(pio, PIN_TX);
    pio_sm_init(pio, sm_tx, off_tx, &c);
    pio_sm_set_enabled(pio, sm_tx, true);

    off_rx = pio_add_program(pio, &uart_rx_program);
    sm_rx = pio_claim_unused_sm(pio, true);
    pio_sm_config r = uart_rx_program_get_default_config(off_rx);
    sm_config_set_in_pins(&r, PIN_RX);
    sm_config_set_jmp_pin(&r, PIN_RX);
    sm_config_set_in_shift(&r, true, true, 8);
    sm_config_set_fifo_join(&r, PIO_FIFO_JOIN_RX);
    pio_sm_set_consecutive_pindirs(pio, sm_rx, PIN_RX, 1, false);
    pio_gpio_init(pio, PIN_RX);
    gpio_pull_up(PIN_RX);
    pio_sm_init(pio, sm_rx, off_rx, &r);
    pio_sm_set_enabled(pio, sm_rx, true);

    uart_set_baud(cur_baud);
}

void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *coding) {
    (void)itf;
    if (coding->bit_rate == 1200) {      // baud-touch: reboot to USB bootloader
        reset_usb_boot(0, 0);
    }
    uart_set_baud(coding->bit_rate);
}

// DTR controls the NCP CTS line so we can sweep polarity live:
//   DTR asserted   -> CTS driven LOW  (assert: "NCP, you may send")
//   DTR deasserted -> CTS driven HIGH
// CTS held low (asserted) statically; DTR is ignored.
void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts) {
    (void)itf; (void)dtr; (void)rts;
    gpio_put(PIN_CTS, 0);
}

int main(void) {
    set_sys_clock_khz(120000, true);

    // NCP flow control.
    gpio_init(PIN_CTS);
    gpio_put(PIN_CTS, 0);            // assert CTS: NCP may always send to us
    gpio_set_dir(PIN_CTS, GPIO_OUT);
    gpio_init(PIN_RTS);
    gpio_set_dir(PIN_RTS, GPIO_IN);
    gpio_pull_up(PIN_RTS);

    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);

    uart_init_pio();
    tud_init(0);

    while (true) {
        tud_task();

        // USB -> NCP, honouring the NCP's RTS (active low).
        if (tud_cdc_available()) {
            uint8_t buf[64];
            uint32_t n = tud_cdc_read(buf, sizeof(buf));
            for (uint32_t i = 0; i < n; i++) {
                pio_sm_put_blocking(pio, sm_tx, (uint32_t)buf[i]);
            }
            gpio_xor_mask(1u << PICO_DEFAULT_LED_PIN);
        }
        // NCP -> USB
        while (!pio_sm_is_rx_fifo_empty(pio, sm_rx) && tud_cdc_write_available() >= 1) {
            uint8_t b = (uint8_t)(pio_sm_get(pio, sm_rx) >> 24);
            tud_cdc_write_char((char)b);
        }
        tud_cdc_write_flush();
    }
}
