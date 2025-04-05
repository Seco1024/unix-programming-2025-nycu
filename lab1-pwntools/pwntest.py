# this is from the website, just to test if pwntools is working properly

from pwn import *
r = process('read Z; echo $Z', shell=True)
r.sendline(b'AAA')
r.interactive()