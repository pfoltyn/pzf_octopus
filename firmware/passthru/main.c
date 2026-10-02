// passthru (v3): faithful level-mirror MITM replicating the 4 working jumpers,
// plus logging taps. Each module OUTPUT is mirrored (full PIO speed, ~25 ns) to
// the paired module INPUT — exactly like a direct wire, baud-agnostic, and it
// preserves the RTS/CTS handshake toggles that store-and-forward erased.
//
// Confirmed net pairing / directions (from cap_boot analysis):
//   GP9  (ESP TX  out) --mirror--> GP2  (NCP RX  in)     data ESP->NCP
//   GP3  (NCP TX  out) --mirror--> GP8  (ESP RX  in)     data NCP->ESP
//   GP10 (ESP RTS out) --mirror--> GP5  (NCP CTS in)     flow ESP->NCP
//   GP4  (NCP RTS out) --mirror--> GP11 (ESP CTS in)     flow NCP->ESP
//
// Logging taps (pio1 UART-RX, do not affect mirroring): GP9=ESP->NCP (dir 0x00),
// GP3=NCP->ESP (dir 0x01), GP6=ESP debug console (dir 0x02). USB log = [dir,byte].
// 1200-baud touch reboots to BOOTSEL.

#include <stdint.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "tusb.h"
#include "pico/bootrom.h"
#include "pio_uart.pio.h"

#define BAUD 115200

// {input (module output, read), output (module input, driven)}
static const uint8_t MIRRORS[4][2] = {
    {9, 2},    // ESP TX  -> NCP RX
    {3, 8},    // NCP TX  -> ESP RX
    {15, 14}, // NCP CTS(GP15,out) -> ESP CTS(GP14,in)
    {11, 4}, // ESP RTS(GP11,out) -> NCP RTS(GP4,in)
};
// Logging taps: {input pin, dir tag}
static const uint8_t TAPS[3][2] = { {9, 0x00}, {3, 0x01}, {6, 0x02} };

static PIO pio_m = pio0;
static PIO pio_t = pio1;
static uint tap_sm[3];

void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *c) {
    (void)itf; if (c->bit_rate == 1200) reset_usb_boot(0, 0);
}

static void mirror_init(uint sm, uint in_pin, uint out_pin, uint off) {
    pio_gpio_init(pio_m, out_pin);
    pio_sm_set_consecutive_pindirs(pio_m, sm, out_pin, 1, false);  // start HIGH-Z
    pio_sm_config c = mirror_program_get_default_config(off);
    sm_config_set_in_pins(&c, in_pin);
    sm_config_set_out_pins(&c, out_pin, 1);
    pio_sm_init(pio_m, sm, off, &c);
    pio_sm_set_enabled(pio_m, sm, true);
}

// Incremental bring-up: only the mirrors whose bit is set in ACTIVE drive their
// output; the rest stay HIGH-Z so their (still-jumpered) line is untouched.
// bit0=GP9->GP2 (ESP->NCP data), bit1=GP3->GP8 (NCP->ESP data, GP8=strap!),
// bit2=GP10->GP5 (ESP RTS->NCP CTS), bit3=GP4->GP11 (NCP RTS->ESP CTS).
#define ACTIVE 0xF
static void mirrors_set(bool drive) {
    for (int i = 0; i < 4; i++)
        pio_sm_set_consecutive_pindirs(pio_m, i, MIRRORS[i][1], 1,
                                       drive && (ACTIVE & (1 << i)));
}

static void tap_init(uint sm, uint in_pin, uint off) {
    pio_sm_config r = uart_rx_program_get_default_config(off);
    sm_config_set_in_pins(&r, in_pin);
    sm_config_set_jmp_pin(&r, in_pin);
    sm_config_set_in_shift(&r, true, true, 8);
    sm_config_set_fifo_join(&r, PIO_FIFO_JOIN_RX);
    sm_config_set_clkdiv(&r, (float)clock_get_hz(clk_sys) / (8.0f * BAUD));
    pio_sm_set_consecutive_pindirs(pio_t, sm, in_pin, 1, false);
    pio_sm_init(pio_t, sm, off, &r);
    pio_sm_set_enabled(pio_t, sm, true);
}

static void log_byte(uint8_t dir, uint8_t b) {
    if (tud_cdc_write_available() >= 2) {
        uint8_t rec[2] = {dir, b};
        tud_cdc_write(rec, 2);
    }
}

int main(void) {
    set_sys_clock_khz(120000, true);

    // Mirror input pulls match each line's idle: data lines (idx 0,1) idle HIGH
    // (UART) -> pull-up; flow lines (idx 2,3: ESP/NCP RTS) idle LOW/asserted
    // -> pull-down, so an undriven line reads "clear to send" not "busy".
    for (int i = 0; i < 4; i++) {
        uint in = MIRRORS[i][0];
        gpio_init(in); gpio_set_dir(in, GPIO_IN);
        if (i < 2) gpio_pull_up(in); else gpio_pull_down(in);
    }
    gpio_init(6); gpio_set_dir(6, GPIO_IN); gpio_pull_up(6);   // debug tap input
    gpio_init(PICO_DEFAULT_LED_PIN); gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);
    gpio_put(PICO_DEFAULT_LED_PIN, 1);

    uint off_m = pio_add_program(pio_m, &mirror_program);
    for (int i = 0; i < 4; i++)
        mirror_init(i, MIRRORS[i][0], MIRRORS[i][1], off_m);

    uint off_t = pio_add_program(pio_t, &uart_rx_program);
    for (int i = 0; i < 3; i++) {
        tap_sm[i] = pio_claim_unused_sm(pio_t, true);
        tap_init(tap_sm[i], TAPS[i][0], off_t);
    }

    tud_init(0);
    // Robust engage gating: watch the ESP console (GP6) for the boot banner
    // "ets Jul". Each time we see it, an ESP reset just happened -> disengage
    // (HIGH-Z) so its straps are untouched, and (re)arm a timer. If the ESP
    // stays up 2.5 s without another banner, engage the mirrors. Floating noise
    // (Mini off) never spells the banner, so we stay hands-off until it boots.
    static const char BANNER[] = "ets Jul";
    int mi = 0;
    uint32_t boot_ms = 0;
    bool engaged = false;
    while (true) {
        tud_task();
        for (int i = 0; i < 3; i++)
            while (!pio_sm_is_rx_fifo_empty(pio_t, tap_sm[i])) {
                uint8_t b = (uint8_t)(pio_sm_get(pio_t, tap_sm[i]) >> 24);
                if (i == 2) {                    // console: match boot banner
                    if (b == (uint8_t)BANNER[mi]) {
                        if (++mi == (int)sizeof(BANNER) - 1) {
                            mi = 0;
                            boot_ms = to_ms_since_boot(get_absolute_time());
                            if (engaged) { mirrors_set(false); engaged = false; }
                        }
                    } else {
                        mi = (b == (uint8_t)BANNER[0]) ? 1 : 0;
                    }
                }
                log_byte(TAPS[i][1], b);
            }
        if (!engaged && boot_ms &&
            to_ms_since_boot(get_absolute_time()) - boot_ms > 250) {
            mirrors_set(true);
            engaged = true;
            log_byte(0x03, 0x01);                // marker: mirrors engaged
        }
        // Periodic flow-line snapshot (dir 0x04): bit0=GP4 NCP_RTS(in),
        // bit1=GP10 ESP_RTS(in), bit2=GP5 NCP_CTS(out), bit3=GP11 ESP_CTS(out),
        // bit4=engaged.
        static uint32_t last_flow = 0;
        uint32_t now = to_ms_since_boot(get_absolute_time());
        if (now - last_flow >= 200) {
            last_flow = now;
            uint8_t f = (gpio_get(11) << 0) | (gpio_get(15) << 1) |
                        (gpio_get(4) << 2) | (gpio_get(14) << 3) |
                        (engaged << 4);
            log_byte(0x04, f);
        }
        tud_cdc_write_flush();
    }
}
