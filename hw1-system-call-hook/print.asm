BITS 64
GLOBAL _start

SECTION .text
_start:
    mov     rax, 1          ; syscall number
    mov     rdi, 1          ; stdout
    lea     rsi, [rel msg]  ; pointer to message
    mov     rdx, msg_len    ; message length
    syscall
    ret 

SECTION .data
msg: db "Hello from trampoline!", 0
msg_len equ $ - msg
