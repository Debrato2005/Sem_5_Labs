;1.> Write an ARM assembly language program to transfer block of ten 32 bit numbers
;from one memory to another
;a. When the source and destination blocks are non-overlapping
;b. When the source and destination blocks are overlapping
;Hint: Use Register indirect addressing mode or indexed addressing mode

; a.>
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
	
	LDR R0,=SRC
	LDR R1,=DEST
	MOV R2,#10
	
L1  LDR R3,[R0],#4
	STR R3,[R1],#4
	SUBS R2,#1
	BNE L1
	
STOP B STOP

SRC DCD 0X00000000,0X12345678,0X23562356,0X65326532, 0X00000001,0X00000010,0X00000011,0X09876543,0X98765432, 0X89898989
	AREA DATASEG, DATA, READWRITE
DEST DCD 0,0,0,0,0,0,0,0,0,0
	
	END