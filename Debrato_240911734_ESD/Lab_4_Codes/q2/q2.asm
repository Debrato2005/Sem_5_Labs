;2. Write an assembly language program to convert a 2-digit BCD number in to its
;equivalent hexadecimal number.

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
	LDR R2,=DST; LOADING DST ADDR
	
	LDRB R3,[R0]; LOAD SRC 1 BYTE 89
	MOV R4,R3;MOVING R3 IN R4 AS SPARE
	LSR R3,#4; ROTATING TO GET AT UNITS PLACE
	AND R4,#0X0F; STORING 9
	
	MOV R5,#10
	MLA R3,R3,R5,R4;8*10+9=89 IN DECIMAL
	
	STRB R3,[R2];STORE DECIMAL 89 AS HEXA 59
STOP B STOP
SRC DCD 0x89; Stored bit pattern = 0x89 Interpret it as packed BCD: digits 8 and 9.
; Therefore its numeric value is 89 decimal, which is 0x59 in normal hexadecimal/binary form.
	AREA DATASEG, DATA, READWRITE
DST DCD 0
	END
		
		