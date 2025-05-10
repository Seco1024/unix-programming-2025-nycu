%include "libmini.inc"

section .data
    seed:         dq 0
    longjmp_val:  dq 0

section .text
    global time
    global srand
    global grand
    global rand
    global sigemptyset
    global sigfillset
    global sigaddset
    global sigdelset
    global sigismember
    global sigprocmask
    global setjmp
    global longjmp

time:
    xor edi, edi                ; time(NULL)
    mov rax, 201      
    syscall
    ret

srand:
    mov rax, rdi
    dec rax
    mov [rel seed], rax
    ret

grand:
    mov rax, [rel seed]
    ret

rand:
    mov rax, [rel seed]
    mov rcx, 6364136223846793005
    mul rcx    
    add rax, 1
    mov [rel seed], rax
    shr rax, 33        
    mov eax, eax
    ret

sigemptyset:
    mov qword [rdi], 0
    xor eax, eax
    ret

sigfillset:
    mov qword [rdi], -1
    xor eax, eax
    ret

sigaddset:
    mov ecx, esi
    dec ecx
    cmp ecx, 63
    jae .sigadd_err
    mov rax, 1
    shl rax, cl
    or qword [rdi], rax
    xor eax, eax
    ret
.sigadd_err:
    mov eax, -1
    ret

sigdelset:
    mov ecx, esi
    dec ecx
    cmp ecx, 63
    jae .sigdel_err
    mov rax, 1
    shl rax, cl
    not rax
    and qword [rdi], rax
    xor eax, eax
    ret
.sigdel_err:
    mov eax, -1
    ret

sigismember:
    mov ecx, esi
    dec ecx
    cmp ecx, 63
    jae .sigism_err
    mov rax, [rdi]
    shr rax, cl
    and eax, 1
    ret
.sigism_err:
    mov eax, -1
    ret

sigprocmask:
    mov r10, 8                ; size of sigset_t
    mov rax, 14               ; syscall number
    syscall
    ret

setjmp:
    mov r8, rdi                ; env in r8
    mov rax, [rsp]             ; return RIP
    mov [r8 + 7*8], rax
    xor edi, edi               ; how = 0
    xor esi, esi               ; set = NULL
    lea rdx, [r8 + 8*8]        ; &env->mask
    mov r10, 8
    mov rax, 14                ; __NR_rt_sigprocmask
    syscall
    mov [r8 + 0*8], rbx
    mov [r8 + 1*8], rbp
    mov [r8 + 2*8], r12
    mov [r8 + 3*8], r13
    mov [r8 + 4*8], r14
    mov [r8 + 5*8], r15
    lea rax, [rsp + 8]
    mov [r8 + 6*8], rax
    xor eax, eax               ; return 0
    ret

longjmp:
    mov r8, rdi                ; env in r8
    mov [rel longjmp_val], rsi ; stash val
    ; restore mask
    mov edi, 2                 ; how = SIG_SETMASK
    lea rsi, [r8 + 8*8]
    xor edx, edx               ; oldset = NULL
    mov r10, 8
    mov rax, 14
    syscall
    mov rbx, [r8 + 0*8]
    mov rbp, [r8 + 1*8]
    mov r12, [r8 + 2*8]
    mov r13, [r8 + 3*8]
    mov r14, [r8 + 4*8]
    mov r15, [r8 + 5*8]
    mov rsp, [r8 + 6*8]
    mov rax, [rel longjmp_val]
    test rax, rax
    jne .Llj_ready
    mov rax, 1
.Llj_ready:
    mov rdx, [r8 + 7*8]
    jmp rdx
