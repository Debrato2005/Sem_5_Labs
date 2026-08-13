;4. Write an assembly language program to find LCM of two numbers
;Hint: i=1
;do{
;remainder= i*a mod b;
;If (remainder==0)
;Exit;
;Else
; i++;
; } while(remainder!=0);
;Return (i*a);

;find the remainder by repeated subtraction.
;lcm=a*b/gcd
;WORKS FOR 32BIT MULTIPLICATION OUTPUT

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
	LDR R0,=SRC1; GETS ADDRESS
	LDR R1,=SRC2
	LDR R2,=GCD
	LDR R3,=LCM
	
	LDR R4,[R0]
	LDR R5,[R1]
	MOV R6,R4
	MOV R7,R5
L1	CMP R4,R5
	BEQ L2 
	SUBHI R4,R5
	SUBLO R5,R4
	B L1
L2	STR R4,[R2]
	MUL R8,R6,R7
L3	CMP R8,R4
	BCC DONE
	SUB R8,R4
	ADD R9,#1
	B L3
DONE STR R9,[R3]
	
STOP B STOP
SRC1 DCD 0x12
SRC2 DCD 0x18
	AREA DATASEG, DATA, READWRITE
GCD DCD 0
LCM DCD 0

	END
		
		