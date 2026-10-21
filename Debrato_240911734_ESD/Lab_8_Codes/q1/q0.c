//1. Write a C program for 4 digit BCD up/down counter on seven segment using a
//switch
#include<LPC17xx.h>
unsigned char SEVENSEG[10] = {
    0x3F,0x06,0x5B,0x4F,0x66,
    0x6D,0x7D,0x07,0x7F,0x6F
};
int main()
{
	int i=0,j=0; int num=0,count=0;
	SystemInit();
	SystemCoreClockUpdate();
	LPC_PINCON->PINSEL0=0;
	LPC_PINCON->PINSEL3=0;
	LPC_PINCON->PINSEL4=0;
	LPC_GPIO0->FIODIR=0XFF<<4;//8 pins required to represent each digit
	LPC_GPIO1->FIODIR=0X0F<<23;// for decoder
	LPC_GPIO2->FIODIR=0;// switch
	
	while(1)
	{ int n=num;
		for(i=0;i<4;i++)
		{
			LPC_GPIO1->FIOPIN=i<<23;
			LPC_GPIO0->FIOPIN=SEVENSEG[n%10]<<4;
		for(j=0;j<1000;j++);
		n=n/10;
	}
	if(count>250)
	{
		if (LPC_GPIO2->FIOPIN & 1<<12)
		{
			num++;
			if(num>9999)
			{num=0;}
		}
		else
		{
			num--;
			if(num<0)
			{num=9999;}
		}
		count=0;
	}
	count++;
}
	}
		