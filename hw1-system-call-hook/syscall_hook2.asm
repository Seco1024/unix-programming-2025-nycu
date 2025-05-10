BITS 64
DEFAULT REL

SECTION .text
GLOBAL syscall_hook
EXTERN handler

syscall_hook: 
    mov     rcx, r10
    push    rax
    call    handler wrt ..plt
    add    rsp, 8     
    ret
section .note.GNU-stack noalloc noexec nowrite
