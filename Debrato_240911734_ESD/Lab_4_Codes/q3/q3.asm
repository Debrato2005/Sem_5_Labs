;3. Write an assembly language program to convert a 2-digit hex number in to its
;equivalent BCD number

	AREA RESET,DATA, READONLY
	EXPORT __Vectors

__Vectors
	DCD 0X10001000;STACK POINTER
	DCD Reset_Handler;RESET VECTOR
	
	ALIGN
	AREA MYCODE,CODE , READONLY
	ENTRY
	EXPORT Reset_Handler

Reset_Handler
	LDR R0,=SRC;LOADING SRC ADDR
	LDR R1,=DST; LOADING DST ADDR
	
	LDRB R3,[R0]      ; R3 = 0x59 = 89 decimal
	MOV R2,#0;
L2	CMP R3,#10; IE 0A HEX
	BLO L1
	SUB R3,#10;
	ADD R2,#1
	B L2
	
L1	LSL R2,#4 ; MAKING TENS DIGIT
	ADD R2,R3
	
	STRB R2,[R1]
	
STOP B STOP
SRC DCD 0x59; hexadecimal 
	AREA DATASEG, DATA, READWRITE
DST DCD 0
	END
		
		