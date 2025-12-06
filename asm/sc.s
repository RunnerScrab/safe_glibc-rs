	[BITS 64]
	default rel
	global _start
	section .text
._main:
	push rbx
	push r12
	push r13
	push r14
	push r15
	push rbp
	mov rbp, rsp

	lea rdi, [.crab]
	call .strlen
	mov r12, rax
	xor r13, r13

	call .printcrabline

	lea rdi, [.string]
	call .strlen
	mov rsi, rax
	lea rdi, [.string]
	call .printrgbstring

	; Print the ANSI reset code so we leave the user's
	; terminal as we found it
	call .printansireset

	call .printcrabline

	mov rax, 0FEEDFACEDEADBEEFh
	mov rsp, rbp
	pop rbp
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	ret
	
	; Prints a line of UTF-8 crab emojis
.printcrabline:
	push r12
	push r13
._printcrabsloop:
	mov rsi, r12
	lea rdi, [.crab]
	call .printstr
	add r13, 1
	cmp r13, 28
	jl ._printcrabsloop
	call .printnl
	pop r13
	pop r12
	ret

	; _start being after main allows this to both run as a standalone
	; program and to be copied into and run from executable memory
_start:
	call ._main
	mov rax, 60
	mov rdi, 0
	syscall
	
.strlen: ; rdi str, rax ret
	push rbx

	xor rax, rax
	xor rbx, rbx
	lea rcx, [rdi]
._strlenloop:
	mov bl, [rcx]
	add rcx, 1
	add rax, 1
	cmp bl, 0
	jne ._strlenloop
	sub rax, 1

	pop rbx
	ret
.printrgbstring: ; rdi str, rsi len
	push r12
	push r13
	push r14
	push r15

	mov r8, rdi
	mov r9, rsi
	xor rcx, rcx
	xor r10, r10
	xor r12, r12
	xor r13, r13
	xor r15, r15
	
	mov r14, 36 ; Parts the color wheel is divided into
	mov r13, 36 ; starting color wheel angle step

	cmp rsi, r14
	jg ._loop; rsi >= 20
._setmaxtostrlen:
	mov r14, rsi
._loop: ; r9 string len, r13 color step count
	mov rsi, r13; step
	mov rdi, r14 ; max_steps
	call .hsv_to_rgb

	mov r10, rax ; red
	and r10, 255

	mov r11, rax ; green
	shr r11, 8
	and r11, 255

	mov rcx, rax ; blue
	shr rcx, 16
	and rcx, 255

	lea rax, [r8]
	add rax, r12
	xor rdi, rdi
	mov dil, byte [rax]
	mov r15b, dil
	mov rsi, r10
	mov rdx, r11

	cmp r15b, 0ah
	je ._nonprintingchar

._printablechar:
	push r8
	push r9
	push r10
	push r11
	call .printcolorchar
	pop r11
	pop r10
	pop r9
	pop r8
	jmp ._loopepilogue
._nonprintingchar:
	
	push r13
	push r14
	call .printchar
	pop r14
	pop r13
._loopepilogue:
	add r12, 1 ; Increment index into string

	cmp r12, r9 ; If we have reached the end of the buffer, exit loop
	jge ._loopend

	add r13, 1 ; Increment step

	cmp r15, 0ah ;Sync column color by resetting steps on \n
	je ._resetcolcount

	cmp r13, r14 ; If we have reached max_steps, reset steps
	jl ._loop
._resetcolcount:
	xor r13, r13
	jmp ._loop
._loopend:
	pop r15
	pop r14
	pop r13
	pop r12
	ret

.printansireset:
	lea rdi, [.ansireset]
	mov rsi, 4
	call .printstr
	ret
.printcolorchar: ; rdi - char, rsi r, rdx g, rcx b
	push r12
	push r13
	push r14
	push r15
	push rbp
	mov rbp, rsp

	mov r12, rdi
	mov r13, rsi
	mov r14, rdx
	mov r15, rcx

	;Prints the ANSI escape sequence for a 24-bit color code
	;the R, G, and B values are embedded as ASCII inside the code

	mov rsi, 07h
	lea rdi, [.ansicode1]
	call .printstr

	mov rdi, r13 ; red
	call .printnum

	mov rsi, 1
	lea rdi, [.ansicode34]
	call .printstr

	mov rdi, r14 ; green
	call .printnum

	mov rsi, 1
	lea rdi, [.ansicode34]
	call .printstr

	mov rdi, r15 ; blue
	call .printnum

	mov rsi, 1
	lea rdi, [.ansicode5]
	call .printstr

	mov rdi, r12
	call .printchar

	mov rsp, rbp
	pop rbp
	pop r15
	pop r14
	pop r13
	pop r12
	ret

.printnum: ; rdi num
	push rbp
	mov rbp, rsp
	sub rsp, 32

	lea rsi, [rbp - 1]
	call .itoa
	lea rsi, [rbp]
	sub rsi, rax
	mov rdi, rax
	call .printstr

	mov rsp, rbp
	pop rbp
	ret
.printchar: ; rdi char
	push rbp
	mov rbp, rsp
	sub rsp, 8

	mov [rbp - 8], dil
	lea rdi, [rbp - 8]
	mov rsi, 1
	call .printstr

	mov rsp, rbp
	pop rbp
	ret
.printstr: ; rdi str, rsi len
	push rbp
	mov rbp, rsp

	mov rdx, rsi
	mov rsi, rdi
	mov rax, 1
	mov rdi, 1
	syscall

	mov rsp, rbp
	pop rbp
	ret
.printnl:
	mov dil, 0ah
	call .printchar
	ret
	
	; Performs floating-point modulus
.flmod:
	movaps xmm2, xmm0
	divss xmm2, xmm1
	cvttss2si ecx, xmm2
	pxor xmm2, xmm2
	cvtsi2ss xmm2, ecx
	mulss xmm1, xmm2
	subss xmm0, xmm1
	ret
	; Map a channel of hsv to R, G, or B
.hsvf: ; xmm0 return, xmm0 n, xmm1 h
	addss xmm0, xmm1
	mov eax, 40c00000h
	movd xmm1, eax
	call .flmod

	mov edx, 40800000h
	movd xmm1, edx
	movaps xmm2, xmm0

	subss xmm1, xmm0
	mov edi, 3f800000h
	movd xmm0, edi

	comiss xmm1, xmm2
	jbe ._label1
	comiss xmm0, xmm2 ; xmm0 = n, xmm1 = h
	ja ._label2
._label3:
	minss xmm2, xmm0
	subss xmm0, xmm2
	mov esi, 437f0000h
	movd xmm3, esi
	mulss xmm0, xmm3
	ret
._label1:
	comiss xmm0, xmm1
	ja ._label4
._label5:
	movaps xmm2, xmm1
	jmp ._label3
._label4:
	pxor xmm2, xmm2
	comiss xmm1, xmm2
	ja ._label5
._label6:
	mov eax, 437f0000h
	movd xmm0, eax
	ret
._label2:
	pxor xmm1, xmm1
	comiss xmm2, xmm1
	ja ._label3
	jmp ._label6

	; Converts a hue-saturation-value angle into an rgb value
	; This is used to rotate through the color wheel
.hsv_to_rgb: ; eax return, edi max_steps, esi step
	push rbp
	mov rbp, rsp
	sub rsp, 18h

	mov [rbp - 1ch], edi ; max_steps_local, max_steps
	mov [rbp - 20h], esi ;step_local, step

	mov eax, 43b40000h ; 360.f
	mov edi, 42700000h ; 60.f
	mov esi, 40a00000h ; 5.f

	pxor xmm0, xmm0
	cvtsi2ss xmm0, [rbp - 20h]

	pxor xmm2, xmm2
	cvtsi2ss xmm2, [rbp - 1ch]

	movaps xmm1, xmm0
	divss xmm1, xmm2

	movd xmm0, eax

	mulss xmm0, xmm1
	movss [rbp - 14h], xmm0 ; angle

	movd xmm1, edi

	divss xmm0, xmm1
	movss [rbp - 10h], xmm0 ; h
	mov [rbp - 0ch], 0 ; v

	movss xmm0, [rbp - 10h]
	movaps xmm1, xmm0

	movd xmm0, esi
	call .hsvf

	mov ecx, 40400000h ; 3.f

	cvttss2si eax, xmm0
	movzx eax, al
	or [rbp - 0ch], eax ; first or

	movss xmm0, [rbp - 10h]

	movaps xmm1, xmm0

	movd xmm0, ecx
	call .hsvf
	cvttss2si edi, xmm0
	movzx edx, dil

	mov eax, 3f800000h ; 1.f

	shl edx, 8
	or [rbp - 0ch], edx ; second or

	movss xmm0, [rbp - 10h]
	movaps xmm1, xmm0
	movd xmm0, eax
	call .hsvf

	cvttss2si esi, xmm0
	movzx ecx, sil
	shl ecx, 16
	or [rbp - 0ch], ecx ; third or
	mov eax, [rbp - 0ch]

	mov rsp, rbp
	pop rbp
	ret

	; A naive itoa that is small and easy to write but slow
.itoa: ; ret rax, num edi, rsi outbuf
	mov r8, 10
	mov eax, edi ;eax is now the number
._itoaloop:
	; eax = eax / src
	; edx = eax % src
	xor edx, edx
	div r8
	mov ecx, eax
	add edx, 48
	mov [rsi], byte dl
	sub rsi, 1
	test eax, eax
	jnz ._itoaloop

	mov rax, rsi
	add rax, 1h
	ret
	; 5ch 78h 31h 62h 5Bh 33h 38h 3Bh 32h 3Bh _ 3Bh _ 3Bh _ 6dh
.ansicode1: db 1bh, 5bh, 33h, 38h, 3bh, 32h, 3bh
.ansicode34: db 3bh
.ansicode5: db 6dh
.ansireset: db 1bh, 5bh, 30h, 6dh
.crab: db 0F0h, 9Fh, 0A6h, 80h, 0h
.string: db "Rust is a many-splendored thing", 0ah,"It's the April rose that only grows in the early spring", 0Ah,\
	"Rust is nature's way of giving",0ah,"A reason to be living",0ah,"The borrow checker makes a man a king", 0ah, 0
.endstring:
	nop
