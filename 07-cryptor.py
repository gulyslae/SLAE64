#!/usr/bin/python
# author: Sandro "guly" Zaccarini - SLAE64-1497
# this code has been written for SLAE64 assignment 7
# license: CC-BY-NC-SA
#
# sample shellcode from my writeHelo
# 0x48,0x31,0xc0,0x48,0x31,0xff,0x48,0xff,0xc7,0x50,0x48,0xbb,0x6c,0x6c,0x6f,0x20,0x67,0x75,0x6c,0x79,0x53,0x66,0x68,0x68,0x65,0x48,0x89,0xe6,0xb0,0x01,0x48,0x89,0xc2,0xb2,0x0a,0x0f,0x05,0x48,0x31,0xc0,0x48,0x89,0xc7,0xb0,0x3c,0x0f,0x05
# 
# cut&paste output:
# $ python 07_cryptor.py e 0x48,0x31,0xc0,0x48,0x31,0xff,0x48,0xff,0xc7,0x50,0x48,0xbb,0x6c,0x6c,0x6f,0x20,0x67,0x75,0x6c,0x79,0x53,0x66,0x68,0x68,0x65,0x48,0x89,0xe6,0xb0,0x01,0x48,0x89,0xc2,0xb2,0x0a,0x0f,0x05,0x48,0x31,0xc0,0x48,0x89,0xc7,0xb0,0x3c,0x0f,0x05
#
# $ python 07_cryptor.py d 0x48,0x31,0xc0,0x48,0x31,0xff,0x48,0xff,0xc7,0x50,0x48,0xbb,0x6c,0x6c,0x6f,0x20,0x67,0x75,0x6c,0x79,0x53,0x66,0x68,0x68,0x65,0x48,0x89,0xe6,0xb0,0x01,0x48,0x89,0xc2,0xb2,0x0a,0x0f,0x05,0x48,0x31,0xc0,0x48,0x89,0xc7,0xb0,0x3c,0x0f,0x05

import os,sys
import base64
import ctypes, mmap
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def execute(origsc):
    # as a proof, i'll try to exec my shellcode
    # never do it in real life :)

    # because the input is like 4831c0.... convert it to \x48\x31\xc0...
    hexsc = origsc.decode("hex")

    # convert shellcode to bytes
    sc = bytes(hexsc)

    # map enough memory to hold my shellcode
    execmem = mmap.mmap(-1,len(sc), prot = mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC, flags = mmap.MAP_ANONYMOUS | mmap.MAP_PRIVATE)

    # copy shellcode to mapped memory
    execmem.write(sc)

    buffer = ctypes.c_int.from_buffer(execmem)
    function = ctypes.CFUNCTYPE( ctypes.c_int64 )(ctypes.addressof(buffer))
    function._avoid_gc_for_mmap = execmem

    return function

def getkey():
    inpass = "SLAE64-Assignment7" # long enough for a demo
    bytepass = inpass.encode()    # convert to byte, could be done just in 1 line but it's less readable
    salt = b'SLAE64-1497'         # this should be random, but this is just a demo
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytepass))
    return key

def help():
    print( "use: python2 %s e|d payload" % sys.argv[0])
    print( "where:")
    print( "  e => encrypt")
    print( "  d => decrypt")
    print( "  payload => shellcode\n")
    print( '  shellcode could be 0x414243 or 0x41,0x42,0x43 or \x41\x42\x43 and must NOT contain spaces')
    sys.exit()

if len(sys.argv) < 3:
    help()

dirtyPayload = sys.argv[2]
# remove '\x', then 0x, then , to have an hex-only shellcode
payload = dirtyPayload.replace('\\x','').replace('0x','').replace(',','')

key = getkey()
f = Fernet(key)
if sys.argv[1] == 'e':
    enc = f.encrypt(payload.encode('utf-8')) #need to convert the string to bytes
    print 'encrypted: {0}'.format(enc)
    dec = f.decrypt(enc)
    print 'decrypted: {0}'.format(dec)
elif sys.argv[1] == 'd':
    dec = f.decrypt(payload.encode('utf-8'))
    print 'decrypted: {0}'.format(dec)
    execute(dec)()
else:
    print "invalid action, is e or d?"
    help()


# This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
