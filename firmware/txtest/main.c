// txtest: self-loopback test of the PIO UART TX path. Drives 0x55 'U' on GP2
// (the NCP RX line) at 115200 and reads GP2 back on a second PIO SM. If the USB
// log shows 0x55 bytes, PIO UART TX (and RX) both work. Harmless to the NCP
// (it just receives 'U' bytes it will ignore). 1200-baud touch reboots to BOOTSEL.
#include <stdint.h>
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "tusb.h"
#include "pico/bootrom.h"
#include "pio_uart.pio.h"

#define BAUD 115200
#define PIN  2               // drive + read back the same pin

static PIO pio = pio0;
static uint sm_tx, sm_rx;

void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *c){ (void)itf; if(c->bit_rate==1200) reset_usb_boot(0,0);}

int main(void){
    set_sys_clock_khz(120000,true);
    float div=(float)clock_get_hz(clk_sys)/(8.0f*BAUD);

    uint off_tx=pio_add_program(pio,&uart_tx_program);
    uint off_rx=pio_add_program(pio,&uart_rx_program);
    sm_tx=pio_claim_unused_sm(pio,true);
    sm_rx=pio_claim_unused_sm(pio,true);

    // TX on PIN
    pio_sm_config c=uart_tx_program_get_default_config(off_tx);
    sm_config_set_out_shift(&c,true,false,32);
    sm_config_set_out_pins(&c,PIN,1);
    sm_config_set_sideset_pins(&c,PIN);
    sm_config_set_fifo_join(&c,PIO_FIFO_JOIN_TX);
    sm_config_set_clkdiv(&c,div);
    pio_sm_set_pins_with_mask(pio,sm_tx,1u<<PIN,1u<<PIN);
    pio_sm_set_pindirs_with_mask(pio,sm_tx,1u<<PIN,1u<<PIN);
    pio_gpio_init(pio,PIN);
    pio_sm_init(pio,sm_tx,off_tx,&c);
    pio_sm_set_enabled(pio,sm_tx,true);

    // RX on the same PIN (reads the driven level)
    pio_sm_config r=uart_rx_program_get_default_config(off_rx);
    sm_config_set_in_pins(&r,PIN);
    sm_config_set_jmp_pin(&r,PIN);
    sm_config_set_in_shift(&r,true,true,8);
    sm_config_set_fifo_join(&r,PIO_FIFO_JOIN_RX);
    sm_config_set_clkdiv(&r,div);
    pio_sm_init(pio,sm_rx,off_rx,&r);
    pio_sm_set_enabled(pio,sm_rx,true);

    gpio_init(PICO_DEFAULT_LED_PIN); gpio_set_dir(PICO_DEFAULT_LED_PIN,GPIO_OUT);
    tud_init(0);
    uint32_t last=0, n=0;
    while(true){
        tud_task();
        uint32_t now=to_ms_since_boot(get_absolute_time());
        if(now-last>=2){ last=now; pio_sm_put_blocking(pio,sm_tx,0x55); n++; }
        while(!pio_sm_is_rx_fifo_empty(pio,sm_rx)){
            uint8_t b=(uint8_t)(pio_sm_get(pio,sm_rx)>>24);
            if(tud_cdc_write_available()>=1){ tud_cdc_write_char((char)b); }
            gpio_xor_mask(1u<<PICO_DEFAULT_LED_PIN);
        }
        tud_cdc_write_flush();
    }
}
