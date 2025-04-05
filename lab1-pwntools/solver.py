#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

import sys
from pwn import *
from solpow import solve_pow
import zlib
import base64
from itertools import permutations


def base64_encode_text(plain):
    encoded_plain = plain.encode()
    compressed = zlib.compress(encoded_plain)
    length = len(compressed)
    length_to_bytes = length.to_bytes(4, 'little')
    message = base64.b64encode(length_to_bytes + compressed).decode()
    return message


def base64_decode_text(encrypted):
    msg = encrypted.strip()
    msg = base64.b64decode(msg) # 用 base64 先解碼
    mlen = int.from_bytes(msg[0:4], 'big')  # 用 Big-Endian 解讀前四 bytes
    m = zlib.decompress(msg[4:]).decode()  # 解壓縮
    return m


def parse_result(msg):
    a = int.from_bytes(msg[:4].encode(), 'big')
    b = int.from_bytes(msg[5:9].encode(), 'big')
    print(f"{a}A {b}B")
    return a, b
    

def solveProblem(plain, a, b):
    global candidates_list, all_possible
    matched_plain = []
    for candidate in all_possible:
        a_counter, b_counter = 0, 0
        for i in range(4):
            if candidate[i] == plain[i]:
                a_counter += 1
            if candidate[i] in set(plain.strip('')):
                b_counter += 1
        
        if a_counter == a and b_counter - a_counter == b:
            matched_plain.append(candidate)
            
    candidates_list = list(filter(lambda x:x in matched_plain, candidates_list))
    return candidates_list[0]
    
    
candidates_list, all_possible = [''.join(p) for p in permutations('0123456789', 4)], [''.join(p) for p in permutations('0123456789', 4)]


def main():
    if len(sys.argv) > 1:
        ## for remote access
        r = remote('up.zoolab.org', 10155)
        solve_pow(r)
    else:
        ## for local testing
        r = process('./guess.dist.py', shell=False)
        
    print('*** Implement your solver here ...')

    plain = "0123"

    a = r.recvline()
    print(base64_decode_text(a))

    for i in range(10):
        msg = r.recvline()
        print(base64_decode_text(msg))    
        r.sendline(base64_encode_text(plain).encode())
        msg = r.recvline()
        a, b = parse_result(base64_decode_text(msg))
        msg = r.recvline()
        print(base64_decode_text(msg))
        
        if a == 4 and b == 0:
            break
        else:
            plain = solveProblem(plain, a, b)
    
    r.interactive()

if __name__ == '__main__':
    main()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :