//Simulate DIE tossing on LCD
//Hint: Program reads the external interrupt using the key SW2. A random number
//between 0-6 should be displayed on the LCD upon keypress.
//a function to write 4bit data to the lcd p0.26 to p0.23
//assume 4bit data in temp2 anad flag1=0 if command code adn 1 if its a data
#include <LPC17xx.h>
// Global variables
unsigned long int temp1=0, temp2=0, i, j;
// flag1 = 0: Command mode (RS = 0)
// flag1 = 1: Data mode (RS = 1)
unsigned char flag1=0, flag2=0;
unsigned long int init_command[] = {0x30,0x30,0x30,0x20,0x28,0x0C,0x06,0x01,0x80};
unsigned int counter=0;   // free running counter (random source)
unsigned char dice=0;     // random number 0-6
// Strings to display on LCD
char msg1[]="DIE TOSS: SW2";
char msg2[]="Number: ";

// Function declarations
void port_write(void);
void lcd_write(void);
void delay(volatile unsigned int);
int main()
{
SystemInit();
SystemCoreClockUpdate();
// Configure P0.23 to P0.28 as GPIO
LPC_PINCON->PINSEL1=0;
// P0.23-P0.26: LCD data lines D4-D7
// P0.27: LCD RS (Register Select)
// P0.28: LCD EN (Enable)
LPC_GPIO0->FIODIR=(1<<27)|(1<<28)|(0xF<<23);
// SW2 on P2.10 as GPIO input
LPC_PINCON->PINSEL4=0x00000000;
LPC_GPIO2->FIODIR=0x00000000;
delay(300000); // power-up wait, ~15-20 ms
flag1 = 0; // command mode
for (i = 0; i < 9; i++)
{
temp1 = init_command[i];
lcd_write();
}

// Line 1
flag1=0; // command mode
temp1=0x80; // cursor to line 1
lcd_write();
flag1=1; // Select data mode (RS = 1)
i=0;
// Send each character until null terminator
while(msg1[i]!='\0')
{
temp1=msg1[i]; // Store ASCII value of character
lcd_write(); // Send character to LCD
i++; // Move to next character
}
// Line 2
flag1=0; // command mode
temp1=0xC0; // cursor to line 2
lcd_write();
flag1=1; // data mode
i=0;
while(msg2[i]!='\0')
{
temp1=msg2[i];
lcd_write();
i++;
}
while(1)
{
counter++; // keeps counting until SW2 is pressed
if((LPC_GPIO2->FIOPIN & (1<<12))==0) // SW2 pressed (active low)
{
dice=counter%7; // random number 0-6
flag1=0; // command mode
temp1=0xC8; // line 2, column 9 (after "Number: ")
lcd_write();
flag1=1; // data mode
temp1=dice+'0'; // convert number to ASCII
lcd_write(); // display the number
while((LPC_GPIO2->FIOPIN & (1<<12))==0); // wait until key is released
}
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