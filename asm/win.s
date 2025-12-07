[BITS 64]
default rel
section .text
push rbx
push r12
push r13
push rbp
mov rbp, rsp

xor rbx, rbx

mov [.WriteConsoleA], rcx
mov [.hStdOut], rdx

.loop:
    ;rcx, rdx, r8, r9

    lea rcx, [.border]
    call .strlen
    lea rcx, [.border]
    mov rdx, rax
    call .printrgbstring

    lea rcx, [.message]
    call .strlen
    lea rcx, [.message]
    mov rdx, rax
    call .printrgbstring

    lea rcx, [.border]
    call .strlen
    lea rcx, [.border]
    mov rdx, rax
    call .printrgbstring

    call .printnl

    
	add rbx, 1
    cmp rbx, 255
	
	call .printansireset
	
mov rsp, rbp
pop rbp
pop r13
pop r12
pop rbx
ret

.printrgbstring:
	push rbx
	push r12
	push r13
	push r14
	push r15
	
	mov r10, rcx ; r10 = string pointer
	mov r11, rdx ; r11 = string length
	xor r12, r12 ; r12 = loop counter
	mov r14, 36  ; r14 = max steps
	xor r13, r13  ; r13 = current step
._printrgbstrloop:
	mov rdx, r13
	mov rcx, r14
	call .hsv_to_rgb

	mov rdx, rax ;  red
	and rdx, 255
	
	mov r8, rax ; green
	shr r8, 8
	and r8, 255

	mov r9, rax
	shr r9, 16
	and r9, 255

	lea r15, [r10]
	add r15, r12  ; r15 = r10 + r12
	mov cl, byte [r15] ; cl = *r15	

	
	push r10
	push r11	
	call .printcolorchar
	pop r11
	pop r10

	add r12, 1 ; increment loop counter
	cmp r12, r11 ; compare loop counter to string length
	je ._printrgbstrloopend ; end loop if we have reached the end of the string
	add r13, 1 ; increment current step, too
	cmp r13, r14 ; compare the current step to the maximum step
	jl ._printrgbstrloop  ; if current step < maximum step goto ._loop
	xor r13, r13 ; r13 = 0 (reset step)
	jmp ._printrgbstrloop	
._printrgbstrloopend:
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	ret

.printcolorchar: ; rcx - char, rdx r, r8 g, r9 b
	push rbx
	push r12
	push r13
	push r14
	push r15
	push rbp
	mov rbp, rsp

	mov r12, rcx
	mov r13, rdx
	mov r14, r8
	mov r15, r9

	;Prints the ANSI escape sequence for a 24-bit color code
	;the R, G, and B values are embedded as ASCII inside the code

	mov rdx, 07h
	lea rcx, [.ansicode1]
	call .printstr

	mov rcx, r13 ; red
	call .printnum

	mov rdx, 1
	lea rcx, [.ansicode34]
	call .printstr

	mov rcx, r14 ; green
	call .printnum

	mov rdx, 1
	lea rcx, [.ansicode34]
	call .printstr

	mov rcx, r15 ; blue
	call .printnum

	mov rdx, 1
	lea rcx, [.ansicode5]
	call .printstr

	mov rcx, r12
	call .printchar

	mov rsp, rbp
	pop rbp
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	ret
.strlen: ; rcx str, rax ret
	push rbx

	xor rax, rax
	xor rbx, rbx

    ._strlenloop:
        mov bl, [rcx]
        add rcx, 1
        add rax, 1
        cmp bl, 0
        jne ._strlenloop
	sub rax, 1

	pop rbx
	ret

; A naive itoa that is small and easy to write but slow
.itoa: ; ret rax, num rcx, rdx outbuf
	push rbx
	
	mov r8, 10
	mov eax, ecx ;eax is now the number
	mov rbx, rdx ;rbx now buffer pointer
	
._itoaloop:
	; eax = eax / src
	; edx = eax % src
	xor edx, edx
	div r8
	mov ecx, eax
	add edx, 48
	mov [rbx], byte dl
	sub rbx, 1
	test eax, eax
	jnz ._itoaloop

	mov rax, rbx
	add rax, 1h
	
	pop rbx
	ret

.printnum: ; rcx num
	push r12
	push rbp
	mov rbp, rsp
	sub rsp, 32

	lea rdx, [rbp - 1]
	call .itoa

	lea rdx, [rbp]
	sub rdx, rax
	mov rcx, rax
	call .printstr

	mov rsp, rbp
	pop rbp
	pop r12
	ret
.printchar: ; rcx char
	push r12
	push rbp
	mov rbp, rsp
	sub rsp, 16

	mov [rbp - 8], cl
	lea rcx, [rbp - 8]
	mov rdx, 1
	call .printstr

	mov rsp, rbp
	pop rbp
	pop r12
	ret
.printnl:
	push rbp
	mov rbp, rsp
	lea rcx, [.crnl]
	mov rdx, 2
	call .printstr
	mov rsp, rbp
	pop rbp
	ret
.printstr: ; rcx - str, rdx - len
    push r12
    push r13
    push r14
    push rbp
    mov rbp, rsp

    lea r12, [.WriteConsoleA]

    mov r8, rdx
    mov rdx, rcx
    mov rcx, [.hStdOut] ; handle to stdout
    
    xor r9, r9
    push qword 0

    and rsp, -16 ; Align stack to 16 bytes
    sub rsp, 32  ; Reserve shadow space on stack
    call [r12]

    mov rsp, rbp
    pop rbp
    pop r14
    pop r13
    pop r12
ret
.printansireset:
	lea rcx, [.ansireset]
	mov rdx, 4
	call .printstr
	ret
; Floating point modulus
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
	sub rsp, 20h
	mov edi, ecx
	mov esi, edx

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

.hStdOut: db 0h, 0h, 0h, 0h, 0h, 0h, 0h, 0h
.WriteConsoleA: db 0h, 0h, 0h, 0h, 0h, 0h, 0h, 0h
.crnl: db 0dh, 0ah, 0h
.string: db "Awooooooooooooga", 0dh, 0ah, 0h
.stringend:
.ansicode1: db 1bh, 5bh, 33h, 38h, 3bh, 32h, 3bh
.ansicode34: db 3bh
.ansicode5: db 6dh
.ansireset: db 1bh, 5bh, 30h, 6dh
.crab: db 0F0h, 9Fh, 0A6h, 80h, 0h
.border: db "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", 0dh, 0ah, 0
.message: db "Rust is a many-splendored thing", 0ah,"It's the April rose that only grows in the early spring", 0Ah,\
	"Rust is nature's way of giving",0ah,"A reason to be living",0ah,"The borrow checker makes a man a king", 0ah, 0
.endmessage:
	nop

nop
