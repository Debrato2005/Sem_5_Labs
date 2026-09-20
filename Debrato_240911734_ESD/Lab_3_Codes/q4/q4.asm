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
;lcm=a*b/gcd Do the division before multiplication acc to gpt
;WORKS FOR 32BIT MULTIPLICATION OUTPUT

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
	LDR R0,=SRC1;A ADDR
	LDR R1,=SRC2;B ADDR
	LDR R8,=DST
	
	LDR R2,[R0];A
	LDR R3,[R1];B

	MOV R4, R2; STORES A
	MOV R9, R3; STORES B
	
L1	CMP R2, R3;GCD
	BEQ L2
	SUBHI R2,R3
	SUBLO R3,R2
	B L1
	;GCD IN R2,R3
	
L2  CMP R4,R2;DIV
	BLO EXIT
	SUB R4,R2
	ADD R5,#1
	B L2
	
EXIT UMULL R6,R7,R5,R9
	STR R6,[R8],#4
	STR R7,[R8]
	
stop b stop
SRC1 DCD 0X03
SRC2 DCD 0X09
	AREA mydata , DATA, READWRITE
DST DCD 0,0
	END
	

	

			
		