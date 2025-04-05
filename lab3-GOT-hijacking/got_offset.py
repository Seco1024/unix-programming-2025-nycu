from pwn import *

elf = ELF('./gotoku')
main_off = elf.symbols['main']
print(f'#define MAIN_OFFSET 0x{main_off:x}')
print(f'static uintptr_t got_offsets[] = {{')

for i in range(1, 1201):
    name = f"gop_{i}"
    if name in elf.got:
        offset = elf.got[name]
        print(f"  0x{offset:x}, // {name}")
print('};')