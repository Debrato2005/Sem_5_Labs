//Write a program to set the following intensity levels to the LED connected to PWM output.
//Use ROW-0 of keyboard for intensity variation.
//Key 0 = 10%, Key 1 = 25%, Key 2 = 50%, Key 3 = 75%
#include <LPC17xx.h>
#define PWM_PERIOD 30000                 // MR0 value: one PWM cycle = 30000 counts
// Global variables
unsigned long int duty_percent[4] = {10, 25, 50, 75};   // intensity for key 0,1,2,3
unsigned char key;

// Function declarations
void pwm_init(void);
void set_intensity(unsigned char k);
unsigned char scan_row0(void);
void delay(volatile unsigned int);

int main()
{
SystemInit();
SystemCoreClockUpdate();

// Keypad pins as GPIO
LPC_PINCON->PINSEL3 &= ~0x003FC000;      // P1.23-P1.26 (keypad columns)
LPC_PINCON->PINSEL4 &= ~0x0FF00000;      // P2.10-P2.13 (keypad rows)
LPC_GPIO1->FIODIR &= ~(0xF<<23);         // columns = input
LPC_GPIO2->FIODIR |=  (0xF<<10);         // rows = output

pwm_init();                              // P1.23 = PWM1.4, starts at 10%

while(1)
{
key = scan_row0();                       // 0-3 = key pressed, 0xFF = none
if(key != 0xFF)
{
delay(20000);                            // debounce
if(scan_row0() == key)                   // same key still pressed
{
set_intensity(key);                      // change LED intensity
while(scan_row0() != 0xFF);              // wait for key release
delay(20000);
}
}
}
}

// Initialise PWM1 channel 4 (single edge) on P1.23
void pwm_init(void)
{
LPC_SC->PCONP |= (1<<6);                 // power up PWM1
LPC_PINCON->PINSEL3 &= ~0x0000C000;      // clear P1.23 function
LPC_PINCON->PINSEL3 |=  0x00008000;      // P1.23 = PWM1.4
LPC_PWM1->PR  = 0;                       // no prescale, count at PCLK
LPC_PWM1->PCR = (1<<12);                 // enable PWM1.4 output, single edge
LPC_PWM1->MCR = 0x00000002;              // reset counter on MR0 match (no interrupt needed)
LPC_PWM1->MR0 = PWM_PERIOD;              // period
LPC_PWM1->MR4 = (PWM_PERIOD*10)/100;     // default duty = 10%
LPC_PWM1->LER = (1<<0)|(1<<4);           // latch MR0 and MR4
LPC_PWM1->TCR = 0x00000002;              // reset counter and prescaler
LPC_PWM1->TCR = 0x00000009;              // enable counter and PWM mode
}

// Set duty cycle for key 0-3
void set_intensity(unsigned char k)
{
LPC_PWM1->MR4 = (PWM_PERIOD*duty_percent[k])/100;   // pulse width = duty % of period
LPC_PWM1->LER = (1<<4);                  // new value takes effect at next MR0 match
}

// Scan ROW-0 only, return column 0-3 (= key 0-3), or 0xFF if no key
unsigned char scan_row0(void)
{
unsigned char x;
LPC_GPIO2->FIOCLR = (0xF<<10);           // all rows low
LPC_GPIO2->FIOSET = (1<<10);             // ROW-0 high
delay(1000);                             // let the line settle
x = (LPC_GPIO1->FIOPIN>>23) & 0x0F;      // read columns P1.23-P1.26
if(x==1) return 0;                       // key 0
if(x==2) return 1;                       // key 1
if(x==4) return 2;                       // key 2
if(x==8) return 3;                       // key 3
return 0xFF;                             // no key
}

// Software delay function
void delay(volatile unsigned int r1)
{
volatile unsigned int r;
for(r=0;r<r1;r++);
return;
}