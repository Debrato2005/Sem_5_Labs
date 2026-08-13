;2. Write a program to add two 128 bit numbers stored in code segment and store
;the result in data segment.
;Hint: Use indexed addressing mode.
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
	LDR R2,=SUM
	LDR R3,=CARRY
	MOV R4,#4; COUNTER
	
L1	LDR R5,[R0],#4; GETS VALUE AT THE ADDRESS THEN UPDATES USING POST INDEXING
	LDR R6,[R1],#4;
	; INITIALLY CARRY IS 0
	ADCS R7,R5,R6; ADDS THEN UPDATES CARRY, DEF AULT OF R5 IS 0 ADCS NOT ADDCS
	STR R7,[R2],#4; STORES THE FIRST RESULT IE FIRST 32 BIT PSRT OF 128 BIT
	
	SUB R4,#1; UPDATES COUNTER WITHOUT UPDATING CARRY BCS IT WILL OVERWRITE
	TEQ R4,#0 ; CHECKS IF R4 IS ZERO
	BNE L1
	
	ADC R8,#0; ADD FINAL CARRY
	STRB R8,[R3]
	
STOP B STOP
SRC1 DCD 0x12345678,0x23456789,0x3456789A,0x456789AB
SRC2 DCD 0x56789ABC,0x6789ABCD,0x789ABCDE,0x89ABCDEF
	AREA DATASEG, DATA, READWRITE
SUM DCD 0,0,0,0 ;Allocates 4 × 32-bit = 128 bits (16 bytes)
; READ 128-BIT RESULT:
; Each DCD = 32 bits = 4 bytes.
; ARM is LITTLE-ENDIAN, so bytes inside each 32-bit word appear reversed in memory.
; SUM[0] = least significant 32 bits
; SUM[1] = next 32 bits
; SUM[2] = next 32 bits
; SUM[3] = most significant 32 bits
; Therefore read the 128-bit result as: SUM[3] SUM[2] SUM[1] SUM[0]
CARRY DCB 0

	END