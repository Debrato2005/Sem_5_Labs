//Write an embedded C program to turn ON the LED when the switch connected
//to P2.12 is pressed and turn OFF the LED when the switch is released.
#include <LPC17XX.h>
#include <stdint.h>
int main()
{
	SystemInit();
	SystemCoreClockUpdate();
	
	LPC_PINCON->PINSEL0=0; //PORT 0 4TH BIT
	LPC_PINCON->PINSEL4=0;// PORT 2 12TH BIT
	
	LPC_GPIO0->FIODIR=1<<4;//PORT 0
	LPC_GPIO2->FIODIR=0;//PORT 2
	
	while(1)
	{
	int x=LPC_GPIO2->FIOPIN;
	if (!(x & (1 << 12)))//x 0 means pressed
	{
		LPC_GPIO0->FIOSET=1<<4;
	}
	else
	{
		LPC_GPIO0->FIOCLR=1<<4;
	}		
}
}