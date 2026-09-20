	AREA RESET,DATA, READONLY
	EXPORT __Vectors

__Vectors
	DCD 0X10001000 ;stack pointer value when stack is emoty
	DCD Reset_Handler ; reset vector

	ALIGN

	AREA mycode, CODE , READONLY
	ENTRY
	EXPORT Reset_Handler ;till here common
Reset_Handler
	LDR R0,=SRC
	LDR R1,=DST
	
	LDRB R2,[R0]
	AND R4,#0XF
L2	CMP R2, #10
	BLO L1
	SUB R2,#10
	ADD R3,#1
	B L2
	
L1	LSL R3,#4
	ADD R3,R2
	STR R3,[R1]
	
stop b stop
SRC DCD 0X59
	AREA mydata , DATA, READWRITE
DST DCD 0
	END
	
