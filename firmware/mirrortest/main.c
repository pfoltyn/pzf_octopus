// mirrortest: verify the PIO `mov pins, pins` level-mirror actually forwards.
// CPU drives GP20 (SIO) with a pattern; a PIO mirror copies GP20 -> GP21;
// CPU reads GP21 and reports whether it follows. No external wiring.
#include <stdint.h>
#include "pico/stdlib.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "tusb.h"
#include "pico/bootrom.h"
#include "pio_uart.pio.h"
#define IN 20
#define OUT 21
static PIO pio=pio0;
void tud_cdc_line_coding_cb(uint8_t itf,cdc_line_coding_t const*c){(void)itf;if(c->bit_rate==1200)reset_usb_boot(0,0);}
static void say(const char*s){ while(*s){ if(tud_cdc_write_available()>=1) tud_cdc_write_char(*s++); tud_task(); } tud_cdc_write_flush(); }
int main(void){
    set_sys_clock_khz(120000,true);
    gpio_init(IN); gpio_put(IN,0); gpio_set_dir(IN,GPIO_OUT);   // CPU drives IN
    uint off=pio_add_program(pio,&mirror_program);
    uint sm=pio_claim_unused_sm(pio,true);
    pio_gpio_init(pio,OUT);
    pio_sm_set_consecutive_pindirs(pio,sm,OUT,1,true);          // OUT driven by PIO
    pio_sm_config c=mirror_program_get_default_config(off);
    sm_config_set_in_pins(&c,IN);
    sm_config_set_out_pins(&c,OUT,1);
    pio_sm_init(pio,sm,off,&c);
    pio_sm_set_enabled(pio,sm,true);
    tud_init(0);
    char buf[64]; int lvl=0; uint32_t last=0;
    while(true){
        tud_task();
        uint32_t now=to_ms_since_boot(get_absolute_time());
        if(now-last>=300){
            last=now; lvl^=1; gpio_put(IN,lvl);
            for(volatile int i=0;i<1000;i++);   // settle
            int o=gpio_get(OUT);
            int n=0; const char*m=(o==lvl)?"OK":"MISMATCH";
            buf[n++]='I'; buf[n++]='N'; buf[n++]='='; buf[n++]='0'+lvl;
            buf[n++]=' '; buf[n++]='O'; buf[n++]='U'; buf[n++]='T'; buf[n++]='=';
            buf[n++]='0'+o; buf[n++]=' ';
            buf[n]=0; say(buf); say(m); say("\r\n");
        }
    }
}
