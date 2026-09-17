//Write a C program to read a key and display an 8-bit up/down counter on the LEDs.
//Hint: Use key SW2(if SW2=1, up counter else down counter), which is available
//at CNB1 pin 7. Connect CNB1 to any controller connector like CNB, CNC etc.
//Configure corresponding port pin as GPIO using corresponding PINSEL register
//and input pin using corresponding FIODIR register.
//P2.12
// if switch pressed value is 0 down
// up down counter should be from the current value not always from 0 or 255
#include <LPC17xx.h>
int main()
{
int i=0; int x,j;
LPC_PINCON->PINSEL0=0;
LPC_PINCON->PINSEL4=0;
LPC_GPIO0->FIODIR=0XFF<<4;
LPC_GPIO2->FIODIR=0;//INPUT
	
while(1)
{
	LPC_GPIO0->FIOPIN=i<<4; // print initial i value
	for(j=0;j<5000000;j++);
	
	x=LPC_GPIO2->FIOPIN & 1<<12; //IE EXTRACT THE SWITCH current input live
// remember is 12th port ie 13th bit
	if (x) //up counter
	{ 
		i++;
		if(i>255)
		{
			i=0; //edge case
		}
	}
	else
	{
		i--;
		if(i<0)
		{
			i=255;
		}
	}
	
}
}
	
	
	