from pwn import *

conn = remote('ipinfo.io', 80)
conn.sendline(b'GET /ip HTTP/1.1')
conn.sendline(b'Host: ipinfo.io')
conn.sendline(b'User-Agent: curl/7.88.1')
conn.sendline(b'Accept: */*')
conn.sendline(b'')

conn.recvuntil("includeSubDomains\r\n\r\n")
a = conn.recv().decode()
print("IP: ", a)