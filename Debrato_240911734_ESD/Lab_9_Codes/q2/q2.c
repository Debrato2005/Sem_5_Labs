//Write a program to input an expression of the type A operator B =, from the key board, where A and B are 
//the single digit BCD numbers and operator may be + or - .Display the result on the LCD.
#include <LPC17xx.h>
// Global variables
unsigned long int temp1=0, temp2=0, i, j;
// flag1 = 0: Command mode (RS = 0)
// flag1 = 1: Data mode (RS = 1)
unsigned char flag1=0, flag2=0;
unsigned long int init_command[] = {0x30,0x30,0x30,0x20,0x28,0x0C,0x06,0x01,0x80};
unsigned char key[4];           // key values: A, operator, B, '='
unsigned char k, a, b, neg;
unsigned int result;
// Function declarations
void port_write(void);
void lcd_write(void);
void delay(volatile unsigned int);
unsigned char scan_key(void);

int main()
{
SystemInit();
SystemCoreClockUpdate();
// All pins used are GPIO
LPC_PINCON->PINSEL1=0;           // P0.23-P0.28 (LCD)
LPC_PINCON->PINSEL3=0;           // P1.23-P1.26 (keypad columns)
LPC_PINCON->PINSEL4=0;           // P2.10-P2.13 (keypad rows)
// P0.23-P0.26: LCD data lines D4-D7, P0.27: RS, P0.28: EN
LPC_GPIO0->FIODIR=(1<<27)|(1<<28)|(0xF<<23);
LPC_GPIO1->FIODIR=0x00000000;    // columns = input
LPC_GPIO2->FIODIR=0xF<<10;       // rows = output
delay(300000); // power-up wait, ~15-20 ms
flag1 = 0; // command mode
for (i = 0; i < 9; i++)
{
temp1 = init_command[i];
lcd_write();
}
// Read A, operator, B and '=' from the keypad and echo them on the LCD
for(k=0;k<4;k++)
{
key[k]=scan_key();              // key value 0 to 15
flag1=1;                        // data mode
if(key[k]<10)
temp1=key[k]+0x30;              // 0-9 : add 30
else
temp1=key[k]+0x37;              // A-F : add 37
lcd_write();                    // show the key on the LCD
}
// Calculate result (A = + key, B = - key)
a=key[0];                       // already a BCD digit 0-9
b=key[2];
neg=0;
if(key[1]==10)                  // key A = '+'
{
result=a+b;                     // 0 to 18
}
else                            // key B = '-'
{
if(a>=b)
result=a-b;
else
{
result=b-a;                     // answer is negative
neg=1;
}
}
// Display result after '='
flag1=1;                        // data mode
if(neg==1)
{
temp1='-';
lcd_write();
}
if(result>=10)
{
temp1=(result/10)+0x30;         // tens digit (always 0-9)
lcd_write();
}
temp1=(result%10)+0x30;         // units digit (always 0-9)
lcd_write();
while(1);                       // Stop here
}

// Scan the keypad, return key number 0-15 (row*4+col)
unsigned char scan_key(void)
{
unsigned char row, col, x;
while(1)
{
for(row=0;row<4;row++)
{
LPC_GPIO2->FIOPIN = 1<<(10+row);       // make one row high
delay(100);
x=(LPC_GPIO1->FIOPIN>>23)&0x0F;        // read columns P1.23-P1.26
if(x!=0)                               // a key is pressed
{
if(x==1) col=0;
else if(x==2) col=1;
else if(x==4) col=2;
else col=3;
delay(20000);                          // debounce
while(((LPC_GPIO1->FIOPIN>>23)&0x0F)!=0);   // wait for key release
delay(20000);
return (4*row+col);
}
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