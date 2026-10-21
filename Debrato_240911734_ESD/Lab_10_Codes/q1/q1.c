//Write a c program to display the digital value representing the difference in analog
//voltages at ADC channel 4 and channel 5 on LCD.
#include <LPC17xx.h>
// Global variables
unsigned long int temp1=0, temp2=0, i, j;
// flag1 = 0: Command mode (RS = 0)
// flag1 = 1: Data mode (RS = 1)
unsigned char flag1=0, flag2=0;
unsigned long int init_command[] = {0x30,0x30,0x30,0x20,0x28,0x0C,0x06,0x01,0x80};
unsigned int adc4, adc5, diff;
unsigned char neg;
char msg[]="Diff: ";
// Function declarations
void port_write(void);
void lcd_write(void);
void delay(volatile unsigned int);

int main()
{
SystemInit();
SystemCoreClockUpdate();
LPC_SC->PCONP = (1<<12);            // enable ADC
// P0.23-P0.28 as GPIO (LCD)
LPC_PINCON->PINSEL1=0;
// P1.30 = AD0.4, P1.31 = AD0.5
LPC_PINCON->PINSEL3=0xF0000000;
// P0.23-P0.26: LCD data lines D4-D7, P0.27: RS, P0.28: EN
LPC_GPIO0->FIODIR=(1<<27)|(1<<28)|(0xF<<23);
delay(300000); // power-up wait, ~15-20 ms
flag1 = 0; // command mode
for (i = 0; i < 9; i++)
{
temp1 = init_command[i];
lcd_write();
}
// Label on line 1
flag1=1; // data mode
i=0;
while(msg[i]!='\0')
{
temp1=msg[i];
lcd_write();
i++;
}
while(1)
{
// ---- Channel 4 ----
LPC_ADC->ADCR=(1<<4)|(1<<8)|(1<<21)|(1<<24);   // SEL = channel 4, CLKDIV = 1, PDN = 1, start now
while((LPC_ADC->ADGDR & (1<<31))==0);          // wait till DONE bit = 1
adc4=(LPC_ADC->ADGDR>>4)&0xFFF;                // 12 bit result
// ---- Channel 5 ----
LPC_ADC->ADCR=(1<<5)|(1<<8)|(1<<21)|(1<<24);   // SEL = channel 5
while((LPC_ADC->ADGDR & (1<<31))==0);
adc5=(LPC_ADC->ADGDR>>4)&0xFFF;
// ---- Difference ----
if(adc4>=adc5)
{
diff=adc4-adc5;
neg=0;
}
else
{
diff=adc5-adc4;                                // negative difference
neg=1;
}
// ---- Display on LCD ----
flag1=0; // command mode
temp1=0x86; // line 1, column 7 (after "Diff: ")
lcd_write();
flag1=1; // data mode
if(neg==1)
temp1='-';
else
temp1=' ';
lcd_write();                                   // sign
temp1=(diff/1000)+0x30;                        // thousands
lcd_write();
temp1=((diff/100)%10)+0x30;                    // hundreds
lcd_write();
temp1=((diff/10)%10)+0x30;                     // tens
lcd_write();
temp1=(diff%10)+0x30;                          // units
lcd_write();
delay(100000);                                 // small gap between readings
}
}

// Write a 4-bit value to LCD data pins
void port_write(void)
{
// Send temp2 bits to LCD D4-D7 (P0.23-P0.26)
LPC_GPIO0->FIOPIN=temp2<<23;
// Select command or data register
if(flag1==0)
{
// RS = 0: Command
LPC_GPIO0->FIOCLR=1<<27;
}
else
{
// RS = 1: Data
LPC_GPIO0->FIOSET=1<<27;
}
// EN = 1: Start LCD enable pulse
LPC_GPIO0->FIOSET=1<<28;
delay(50); // Keep enable HIGH briefly
// EN = 0: End enable pulse
LPC_GPIO0->FIOCLR=1<<28;
delay(30000); // Allow LCD to process data
}

// Send character/command to LCD
void lcd_write(void)
{
// flag2 = 1 only for the 0x30 / 0x20 init commands (command mode)
flag2 = (flag1 == 1) ? 0 : ((temp1 == 0x30) || (temp1 == 0x20)) ? 1 : 0;

temp2 = (temp1 >> 4) & 0x0F;     // upper nibble
port_write();

if (flag2 == 0)                  // lower nibble only for normal bytes
{
temp2 = temp1 & 0x0F;
port_write();
}
}

// Software delay function
void delay(volatile unsigned int r1)
{
volatile unsigned int r;
// Empty loop to generate delay
for(r=0;r<r1;r++);
return;
}