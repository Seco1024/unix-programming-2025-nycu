BITS 64
DEFAULT REL
SECTION .text
GLOBAL  syscall_hook
EXTERN  c_hook_bridge 

syscall_hook:
        push    rdi
        push    rsi
        push    rdx
        push    r8
        push    r9
        push    r10          
        mov     rcx, r10      
        push    0    
        mov     r11, [rsp + 192]
        push    r11          
        push    rax 
        call    c_hook_bridge wrt ..plt
        add     rsp, 24        
        pop     r10
        pop     r9
        pop     r8
        pop     rdx
        pop     rsi
        pop     rdi
        ret                   
section .note.GNU-stack noalloc noexec nowrite