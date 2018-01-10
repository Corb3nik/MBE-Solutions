#!/usr/bin/env python

def xor(a, b):
    new = ""
    for i in xrange(len(a)):
        new += chr(ord(a[i]) ^ ord(b[i]))

    return new

enc = "Q}|u`sfg~sf{}|a3"
plaintext = 'Congratulations!'
key = xor(enc, plaintext)

print "Found key : {}".format(ord(key[0]))

