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

# 4.0 FLAG 

# 5.0 FINAL SCRIPT 

# 6.0 REFERENCE
ORW ????
https://kagehutatsu.com/?p=1143 ROP 这个是神
LEAK HEAP BASE
LEAK LIBC BASE


https://www.cnblogs.com/L1nyun/p/18516575 ROP 解释不多

https://blog.csdn.net/Mr_Fmnwon/article/details/143355594 SigreturnFrame 这个人的学习方法跟我很像
可以参考这个 https://blog.csdn.net/Mr_Fmnwon/article/details/143310980?spm=1001.2014.3001.5501