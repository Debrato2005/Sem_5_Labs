;Write an assembly language program to define 
;an array of 2 32 bit numbers in the code memory 
;and copy this array to the data memory
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
	LDR R1,[R0];R0=0XFF12

	LDR R2,=DST
	STR R1,[R2]

	ADD R0,#4
	ADD R2,#4
	LDR R3,[R0]
	STR R3,[R2]


stop 
	b stop
SRC DCD 0xFF12,0XB502 ;3RD PARAMETER Each value occupies 32 bits (4 bytes).
;SRC IS JUST label
;An array in ARM assembly is not a special language construct like in C. 
;It is simply multiple consecutive memory locations.

	AREA mydata , DATA, READWRITE
DST DCD 0,0 
;3RD PARAMETER IS THE DATA BUT, NO USE BCZ RAM ON START ALWAYS INITIALIZES TO 0 THEREFORE 0 IN MEMORY
;CAN INITIALISE RAM WHEN DEBUGGING IN MEMORY WINDOW
	END
	
