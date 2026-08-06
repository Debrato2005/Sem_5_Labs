;1.> Write an ARM assembly language program to transfer block of ten 32 bit numbers
;frobut where are we writing tjhm one memory to another
;a. When the source and destination blocks are non-overlapping
;b. When the source and destination blocks are overlapping
;Hint: Use Register indirect addressing mode or indexed addressing mode

; b.>
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
	LDR R5,=SRC; JUST TO SEE SRC ADDRRESS WHILE USING MEME WINDOW

	LDR R0,=SRC+(N-1)*4 ; R0 points to the LAST source element.
; (N-1)*4 = 9*4 = 36 bytes = 0x24 offset from SRC.	SOURCE POINTING TO ITS LAST ELEMENT
	LDR R1,=SRC +(N-1+S)*4; DESTINATION IS POINTING TO THE LAST ELEMENTS
	MOV R2,#10
	
L1  LDR R3,[R0],#-4; - BCZ WE ARE PERFORMING BACKWARD COPY
	STR R3,[R1],#-4
	SUBS R2,#1
	BNE L1
	
STOP B STOP
N EQU 10; ; Number of 32-bit elements in the source block
S EQU 3; SHIFT WE DECIDE ACC TO QN 
; Destination starts 3 words after the source (overlap offset)

	AREA DATASEG, DATA, READWRITE
;not reqd because we are overlapping the source memory BUT BCZ WRITING AS WELL SRC HERE
SRC DCD 0X00000000,0X12345678,0X23562356,0X65326532, 0X00000001,0X00000010,0X00000011,0X09876543,0X98765432, 0X89898989
; DATA DOESNT MATTER IT WILL BECOME 0 NO USE OF INITIALISE
	
	END