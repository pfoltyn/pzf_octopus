// rewrite: transparent MITM that DOWNGRADES the EZSP version command on the
// ESP->NCP link, to test how the NCP reacts to a lower protocol version.
//
// The ESP->NCP data line is store-and-forwarded (PIO UART RX on GP9 -> parse
// ASH frame -> if it's the EZSP `version` command, rewrite desiredProtocolVersion
// -> PIO UART TX on GP2). The other 3 lines stay as fast level-mirrors, so the
// NCP's replies reach the ESP directly and ASH timing is preserved.
//
//   GP9 (ESP TX)  -> [rewrite] -> GP2 (NCP RX)     ESP->NCP data (rewritten)
//   GP3 (NCP TX)  --mirror-->    GP8 (ESP RX)      NCP->ESP data
//   GP15(NCP CTS) --mirror-->    GP14(ESP CTS)     flow
//   GP11(ESP RTS) --mirror-->    GP4 (NCP RTS)     flow
//   GP6 = ESP debug console (tap, boot-banner gating)
//
// USB log [dir,byte]: 0x00 ESP->NCP(orig), 0x01 NCP->ESP, 0x02 console,
// 0x03 engaged, 0x05 = version rewrite event (followed by old,new bytes).
// 1200-baud touch -> BOOTSEL.

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "tusb.h"
#include "pico/bootrom.h"
#include "pio_uart.pio.h"

#define BAUD            115200
#define TARGET_VERSION  8        // <-- downgrade desiredProtocolVersion to this

#define ESP_TX 9   // rewrite RX (in)
#define NCP_RX 2   // rewrite TX (out)
// mirrors: {in, out}
static const uint8_t MIR[3][2] = { {3, 8}, {15, 14}, {11, 4} };
#define DBG 6

static PIO pm = pio0;     // mirrors + rewrite RX
static PIO pt = pio1;     // rewrite TX + taps
static uint sm_mir[3], sm_rx9, sm_tx2, sm_tap3, sm_tap6;

// ---- ASH helpers ----
static uint16_t crc16(const uint8_t *d, int n) {
    uint16_t c = 0xFFFF;
    for (int i = 0; i < n; i++) { c ^= d[i] << 8; for (int k = 0; k < 8; k++) c = (c & 0x8000) ? (c << 1) ^ 0x1021 : (c << 1); }
    return c;
}
static void ash_rand(uint8_t *d, int n) {
    uint8_t r = 0x42;
    for (int i = 0; i < n; i++) { d[i] ^= r; r = (r & 1) ? ((r >> 1) ^ 0xB8) : (r >> 1); }
}

void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *c) { (void)itf; if (c->bit_rate == 1200) reset_usb_boot(0, 0); }

static void log_byte(uint8_t dir, uint8_t b) {
    if (tud_cdc_write_available() >= 2) { uint8_t r[2] = {dir, b}; tud_cdc_write(r, 2); }
}

// PIO setup helpers
static void mirror_init(PIO p, uint sm, uint in_pin, uint out_pin, uint off) {
    pio_gpio_init(p, out_pin);
    pio_sm_set_consecutive_pindirs(p, sm, out_pin, 1, false);   // start HIGH-Z (gated)
    pio_sm_config c = mirror_program_get_default_config(off);
    sm_config_set_in_pins(&c, in_pin); sm_config_set_out_pins(&c, out_pin, 1);
    pio_sm_init(p, sm, off, &c); pio_sm_set_enabled(p, sm, true);
}
static void tx_init(PIO p, uint sm, uint pin, uint off) {
    pio_sm_config c = uart_tx_program_get_default_config(off);
    sm_config_set_out_shift(&c, true, false, 32);
    sm_config_set_out_pins(&c, pin, 1); sm_config_set_sideset_pins(&c, pin);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_TX);
    sm_config_set_clkdiv(&c, (float)clock_get_hz(clk_sys) / (8.0f * BAUD));
    pio_sm_set_pins_with_mask(p, sm, 1u << pin, 1u << pin);
    pio_sm_set_pindirs_with_mask(p, sm, 0, 1u << pin);          // start HIGH-Z (gated)
    pio_gpio_init(p, pin);
    pio_sm_init(p, sm, off, &c); pio_sm_set_enabled(p, sm, true);
}
static void rx_init(PIO p, uint sm, uint pin, uint off) {
    pio_sm_config r = uart_rx_program_get_default_config(off);
    sm_config_set_in_pins(&r, pin); sm_config_set_jmp_pin(&r, pin);
    sm_config_set_in_shift(&r, true, true, 8); sm_config_set_fifo_join(&r, PIO_FIFO_JOIN_RX);
    sm_config_set_clkdiv(&r, (float)clock_get_hz(clk_sys) / (8.0f * BAUD));
    pio_sm_set_consecutive_pindirs(p, sm, pin, 1, false);
    pio_gpio_init(p, pin); gpio_pull_up(pin);
    pio_sm_init(p, sm, off, &r); pio_sm_set_enabled(p, sm, true);
}

// Engage/disengage the driven outputs (ESP-side straps: GP8,GP14; + GP4,GP2).
static void engage(bool on) {
    pio_sm_set_consecutive_pindirs(pm, sm_mir[0], MIR[0][1], 1, on);  // GP8
    pio_sm_set_consecutive_pindirs(pm, sm_mir[1], MIR[1][1], 1, on);  // GP14
    pio_sm_set_consecutive_pindirs(pm, sm_mir[2], MIR[2][1], 1, on);  // GP4
    pio_sm_set_pindirs_with_mask(pt, sm_tx2, on ? (1u << NCP_RX) : 0, 1u << NCP_RX); // GP2
}

static void tx_byte(uint8_t b) { pio_sm_put_blocking(pt, sm_tx2, b); }

// Forward one received ASH frame (raw stuffed bytes, no flag) to the NCP,
// rewriting the version command if present. Returns via tx_byte + flag.
static void forward_frame(const uint8_t *raw, int n) {
    // de-stuff
    uint8_t body[160]; int bn = 0; bool esc = false;
    for (int i = 0; i < n && bn < (int)sizeof(body); i++) {
        uint8_t b = raw[i];
        if (esc) { body[bn++] = b ^ 0x20; esc = false; }
        else if (b == 0x7D) esc = true;
        else body[bn++] = b;
    }
    bool rewritten = false;
    if (bn >= 3 && (body[0] & 0x80) == 0) {          // DATA frame
        int plen = bn - 3;                            // payload len (minus ctrl + 2 CRC)
        if (plen == 4) {
            uint8_t ez[4]; memcpy(ez, body + 1, 4); ash_rand(ez, 4);   // de-randomize
            if (ez[2] == 0x00) {                      // frameId 0x00 = version cmd
                uint8_t oldv = ez[3];
                ez[3] = TARGET_VERSION;
                uint8_t nb[7]; nb[0] = body[0];
                memcpy(nb + 1, ez, 4); ash_rand(nb + 1, 4);            // re-randomize
                uint16_t c = crc16(nb, 5); nb[5] = c >> 8; nb[6] = c & 0xFF;
                // stuff + send
                for (int i = 0; i < 7; i++) {
                    uint8_t b = nb[i];
                    if (b == 0x7E || b == 0x7D || b == 0x11 || b == 0x13 || b == 0x18 || b == 0x1A) { tx_byte(0x7D); tx_byte(b ^ 0x20); }
                    else tx_byte(b);
                }
                tx_byte(0x7E);
                log_byte(0x05, oldv); log_byte(0x05, TARGET_VERSION);
                rewritten = true;
            }
        }
    }
    if (!rewritten) { for (int i = 0; i < n; i++) tx_byte(raw[i]); tx_byte(0x7E); }
}

int main(void) {
    set_sys_clock_khz(120000, true);
    gpio_init(DBG); gpio_set_dir(DBG, GPIO_IN); gpio_pull_up(DBG);
    // mirror inputs: data pull-up, flow pull-down
    gpio_init(3);  gpio_pull_up(3);
    gpio_init(15); gpio_pull_down(15);
    gpio_init(11); gpio_pull_down(11);
    gpio_init(PICO_DEFAULT_LED_PIN); gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT); gpio_put(PICO_DEFAULT_LED_PIN, 1);

    uint off_mir = pio_add_program(pm, &mirror_program);
    uint off_rx_m = pio_add_program(pm, &uart_rx_program);
    for (int i = 0; i < 3; i++) { sm_mir[i] = pio_claim_unused_sm(pm, true); mirror_init(pm, sm_mir[i], MIR[i][0], MIR[i][1], off_mir); }
    sm_rx9 = pio_claim_unused_sm(pm, true); rx_init(pm, sm_rx9, ESP_TX, off_rx_m);

    uint off_tx = pio_add_program(pt, &uart_tx_program);
    uint off_rx_t = pio_add_program(pt, &uart_rx_program);
    sm_tx2 = pio_claim_unused_sm(pt, true); tx_init(pt, sm_tx2, NCP_RX, off_tx);
    sm_tap3 = pio_claim_unused_sm(pt, true); rx_init(pt, sm_tap3, 3, off_rx_t);
    sm_tap6 = pio_claim_unused_sm(pt, true); rx_init(pt, sm_tap6, DBG, off_rx_t);

    tud_init(0);
    static const char BANNER[] = "ets Jul"; int mi = 0;
    uint32_t boot_ms = 0; bool engaged = false;
    uint8_t frame[160]; int fn = 0;

    while (true) {
        tud_task();
        // ESP->NCP: receive, assemble frame, rewrite, forward
        while (!pio_sm_is_rx_fifo_empty(pm, sm_rx9)) {
            uint8_t b = (uint8_t)(pio_sm_get(pm, sm_rx9) >> 24);
            log_byte(0x00, b);
            if (b == 0x7E) { if (fn && engaged) forward_frame(frame, fn); fn = 0; }
            else if (b == 0x1A) { fn = 0; if (engaged) tx_byte(0x1A); }
            else if (b == 0x11 || b == 0x13) { if (engaged) tx_byte(b); }
            else if (fn < (int)sizeof(frame)) frame[fn++] = b;
        }
        // NCP->ESP tap (log only; data goes via the mirror)
        while (!pio_sm_is_rx_fifo_empty(pt, sm_tap3))
            log_byte(0x01, (uint8_t)(pio_sm_get(pt, sm_tap3) >> 24));
        // console tap: log + banner gating
        while (!pio_sm_is_rx_fifo_empty(pt, sm_tap6)) {
            uint8_t b = (uint8_t)(pio_sm_get(pt, sm_tap6) >> 24);
            if (b == (uint8_t)BANNER[mi]) { if (++mi == (int)sizeof(BANNER) - 1) { mi = 0; boot_ms = to_ms_since_boot(get_absolute_time()); if (engaged) { engage(false); engaged = false; } } }
            else mi = (b == (uint8_t)BANNER[0]) ? 1 : 0;
            log_byte(0x02, b);
        }
        if (!engaged && boot_ms && to_ms_since_boot(get_absolute_time()) - boot_ms > 250) {
            engage(true); engaged = true; log_byte(0x03, 0x01);
        }
        tud_cdc_write_flush();
    }
}
