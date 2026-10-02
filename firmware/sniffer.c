// picosniff: 6-channel passive logic sniffer for GP2..GP7.
//
// PIO samples the pins at a fixed rate into a DMA ring buffer. The CPU
// run-length encodes the samples and streams only the changes over USB CDC.
//
// Host commands (ASCII):
//   ?          print info line
//   R<hz>\n    set sample rate (default 4000000)
//   S          start streaming
//   X          stop streaming
//   B          reboot into the USB bootloader (for reflashing)
//
// Stream: header "\xA5\x5APT" + u32 rate (LE) + u8 channels + u8 first GPIO,
// then events: varint(delta_samples << 2 | kind), kind 0 is followed by a
// state byte (bit n = GP2+n). kind 1 = keepalive (no change), kind 2 =
// overflow (samples lost, timing resynced afterwards).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/stdio_usb.h"
#include "pico/stdio/driver.h"
#include "pico/bootrom.h"
#include "hardware/pio.h"
#include "hardware/dma.h"
#include "hardware/irq.h"
#include "hardware/clocks.h"
#include "hardware/vreg.h"
#include "sample.pio.h"

#define PIN_BASE   2
#define PIN_COUNT  8                 // GP2..GP7 are decoded
#define SAMPLE_BITS 8                // PIO samples GP2..GP9, 4 samples/word
#define PIN_MASK   ((1u << PIN_COUNT) - 1)
#define WORD_MASK  (PIN_MASK * 0x01010101u)

enum { EV_CHANGE = 0, EV_KEEPALIVE = 1, EV_OVERFLOW = 2 };
#define SYS_KHZ    200000

#define RING_BITS  15                       // 32 KiB ring
#define RING_WORDS ((1u << RING_BITS) / 4)
static uint32_t ring[RING_WORDS] __attribute__((aligned(1u << RING_BITS)));

static PIO pio = pio0;
static uint sm;
static uint pio_off;
static int dma_a, dma_b;          // chained pair: each fills the ring once
static volatile uint32_t laps;    // completed ring fills
static uint32_t rate = 4000000;

static uint8_t out[4096];
static uint out_len;

static void flush_out(void) {
    if (out_len) {
        stdio_usb.out_chars((const char *)out, out_len);
        out_len = 0;
    }
}

static void emit(uint64_t delta, uint32_t kind, uint8_t state) {
    if (out_len > sizeof(out) - 16)
        flush_out();
    uint64_t v = delta << 2 | kind;
    while (v >= 0x80) {
        out[out_len++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    out[out_len++] = (uint8_t)v;
    if (kind == EV_CHANGE)
        out[out_len++] = state;
}

static void dma_irq(void) {
    uint32_t m = dma_hw->ints0 & ((1u << dma_a) | (1u << dma_b));
    dma_hw->ints0 = m;
    laps += (uint32_t)__builtin_popcount(m);
}

static void setup_dma(int ch, int next) {
    dma_channel_config dc = dma_channel_get_default_config(ch);
    channel_config_set_transfer_data_size(&dc, DMA_SIZE_32);
    channel_config_set_read_increment(&dc, false);
    channel_config_set_write_increment(&dc, true);
    channel_config_set_ring(&dc, true, RING_BITS);
    channel_config_set_dreq(&dc, pio_get_dreq(pio, sm, false));
    channel_config_set_chain_to(&dc, next);
    dma_channel_configure(ch, &dc, ring, &pio->rxf[sm], RING_WORDS, false);
}

// Total words written by DMA so far (may briefly lag by one lap at a
// hand-over; the caller tolerates that).
static uint64_t dma_produced(void) {
    for (;;) {
        uint32_t l1 = laps;
        int ch = dma_channel_is_busy(dma_a) ? dma_a : dma_b;
        uint32_t wa = dma_hw->ch[ch].write_addr;
        if (laps == l1) {
            uint32_t pos = ((wa - (uint32_t)(uintptr_t)ring) / 4) % RING_WORDS;
            return (uint64_t)l1 * RING_WORDS + pos;
        }
    }
}

static void capture_start(void) {
    pio_sm_set_enabled(pio, sm, false);
    pio_sm_clear_fifos(pio, sm);
    pio_sm_restart(pio, sm);

    pio_sm_config c = sample8_program_get_default_config(pio_off);
    sm_config_set_in_pins(&c, PIN_BASE);
    sm_config_set_in_shift(&c, true, true, 32);
    sm_config_set_fifo_join(&c, PIO_FIFO_JOIN_RX);
    sm_config_set_clkdiv(&c, (float)clock_get_hz(clk_sys) / (float)rate);
    pio_sm_init(pio, sm, pio_off, &c);

    setup_dma(dma_a, dma_b);
    setup_dma(dma_b, dma_a);
    laps = 0;
    dma_hw->ints0 = (1u << dma_a) | (1u << dma_b);
    dma_channel_set_irq0_enabled(dma_a, true);
    dma_channel_set_irq0_enabled(dma_b, true);
    irq_set_enabled(DMA_IRQ_0, true);
    dma_channel_start(dma_a);

    pio_sm_set_enabled(pio, sm, true);
}

static void capture_stop(void) {
    pio_sm_set_enabled(pio, sm, false);
    irq_set_enabled(DMA_IRQ_0, false);
    // Break the chain first so aborting one channel cannot trigger the other.
    hw_clear_bits(&dma_hw->ch[dma_a].al1_ctrl, DMA_CH0_CTRL_TRIG_EN_BITS);
    hw_clear_bits(&dma_hw->ch[dma_b].al1_ctrl, DMA_CH0_CTRL_TRIG_EN_BITS);
    dma_channel_abort(dma_a);
    dma_channel_abort(dma_b);
}

// Returns when host sends 'X'.
static void stream(void) {
    static const uint8_t hdr[4] = {0xA5, 0x5A, 'P', 'T'};
    memcpy(out, hdr, 4);
    memcpy(out + 4, &rate, 4);
    out[8] = PIN_COUNT;
    out[9] = PIN_BASE;
    out_len = 10;
    flush_out();

    capture_start();

    uint64_t consumed = 0;        // words consumed
    uint64_t t = 0;               // sample index of next sample
    uint64_t last_evt = 0;
    uint32_t cur = 0xFF, rep = 0xFFFFFFFFu;  // rep can never match a masked word
    const uint64_t keepalive = rate / 20;
    absolute_time_t next_flush = make_timeout_time_ms(10);

    for (;;) {
        int ch = getchar_timeout_us(0);
        if (ch == 'X')
            break;

        uint64_t produced = dma_produced();
        if (produced <= consumed + 1)
            produced = consumed;
        else
            produced--;           // stay one word behind the DMA write

        if (produced - consumed > RING_WORDS - 64) {
            // Fell behind: drop data, resync.
            uint64_t skip = produced - consumed;
            consumed = produced;
            t += skip * (32 / SAMPLE_BITS);
            emit(t - last_evt, EV_OVERFLOW, 0);
            last_evt = t;
            cur = 0xFF;
            rep = 0xFFFFFFFFu;
        }

        while (consumed < produced) {
            uint32_t w = ring[consumed % RING_WORDS] & WORD_MASK;
            consumed++;
            if (w == rep) {
                t += 32 / SAMPLE_BITS;
                continue;
            }
            for (int i = 0; i < 32 / SAMPLE_BITS; i++, w >>= SAMPLE_BITS) {
                uint32_t s = w & PIN_MASK;
                if (s != cur) {
                    emit(t - last_evt, EV_CHANGE, (uint8_t)s);
                    last_evt = t;
                    cur = s;
                }
                t++;
            }
            rep = cur * 0x01010101u;
        }

        if (cur != 0xFF && t - last_evt >= keepalive) {
            emit(t - last_evt, EV_KEEPALIVE, 0);
            last_evt = t;
        }
        if (out_len > 1024 || (out_len && time_reached(next_flush))) {
            flush_out();
            next_flush = make_timeout_time_ms(10);
        }
    }
    capture_stop();
    flush_out();
}

int main(void) {
    vreg_set_voltage(VREG_VOLTAGE_1_15);
    sleep_ms(2);
    set_sys_clock_khz(SYS_KHZ, true);
    stdio_init_all();

    // Pure inputs, no pulls: never disturb the bus under test.
    for (int p = PIN_BASE; p < PIN_BASE + PIN_COUNT; p++) {
        gpio_init(p);
        gpio_set_dir(p, GPIO_IN);
        gpio_disable_pulls(p);
    }
    gpio_init(PICO_DEFAULT_LED_PIN);
    gpio_set_dir(PICO_DEFAULT_LED_PIN, GPIO_OUT);

    sm = pio_claim_unused_sm(pio, true);
    pio_off = pio_add_program(pio, &sample8_program);
    dma_a = dma_claim_unused_channel(true);
    dma_b = dma_claim_unused_channel(true);
    irq_set_exclusive_handler(DMA_IRQ_0, dma_irq);

    char line[32];
    int len = 0;
    for (;;) {
        int ch = getchar_timeout_us(100000);
        if (ch == PICO_ERROR_TIMEOUT)
            continue;
        if (len == 0 && ch == '?') {
            printf("PICOSNIFF v2 rate=%lu sys=%lu pins=GP2-GP7\n",
                   (unsigned long)rate, (unsigned long)clock_get_hz(clk_sys));
        } else if (len == 0 && ch == 'B') {
            reset_usb_boot(0, 0);
        } else if (len == 0 && ch == 'S') {
            gpio_put(PICO_DEFAULT_LED_PIN, 1);
            stream();
            gpio_put(PICO_DEFAULT_LED_PIN, 0);
        } else if (ch == '\n' || ch == '\r') {
            line[len] = 0;
            if (line[0] == 'R') {
                unsigned long r = strtoul(line + 1, NULL, 10);
                if (r >= 1000 && r <= 50000000)
                    rate = r;
                printf("OK rate=%lu\n", (unsigned long)rate);
            }
            len = 0;
        } else if (len < (int)sizeof(line) - 1 && ch != 'X') {
            line[len++] = (char)ch;
        }
    }
}
