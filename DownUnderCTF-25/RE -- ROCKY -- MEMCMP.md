# 1.0 Challenge
1. HOW TO BREAK MEMCMP?
# 2.0 Analysis
其实这个题目不难 他是一个md5 hash cracking 题目
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[32]; // [rsp+0h] [rbp-60h] BYREF
  char s2[16]; // [rsp+20h] [rbp-40h] BYREF
  char s[32]; // [rsp+30h] [rbp-30h] BYREF
  _QWORD s1[2]; // [rsp+50h] [rbp-10h] BYREF

  s1[0] = 0xD2F969F60C4D9270LL;
  s1[1] = 0x1F35021256BDCA3CLL;
  printf("Enter input: ");
  fgets(s, 17, _bss_start);
  s[strcspn(s, "\n")] = 0;
  md5String(s, s2);
  if ( !memcmp(s1, s2, 0x10u) )
  {
    puts("Hash matched!");
    reverse_string(s, v4);
    decrypt_bytestring(s, v4);
  }
  else
  {
    puts("Hash mismatch :(");
  }
  return 0;
}
```
可以看到 重点就在这边
  s1[0] = 0xD2F969F60C4D9270LL;
  s1[1] = 0x1F35021256BDCA3CLL;
所以 只要换成 little endian
其实 就是 倒转罢了  
然后丢进 md5 station 就可以了
可是我一开始用gdb how ?
# 3.0 Solution
3.1 HOW TO BREAK MEMCMP?

最容易的方法是 gdb 
```
info function memcmp
break memcmp@plt

c
```
这个时候看stack rdi 是 s1 (compare hash) rsi 是 s2 (input)
```
x/2gx $rdi
x/16bx $rdi <- 用这个

pwndbg> x/16bx $rdi
0x7fffffffdba0: 0x70    0x92    0x4d    0x0c    0xf6    0x69    0xf9    0xd2
0x7fffffffdba8: 0x3c    0xca    0xbd    0x56    0x12    0x02    0x35    0x1f

70924d0cf669f9d23ccabd561202351f
== emergencycall911
```

# 4.0 FLAG 
DUCTF{In_the_land_of_cubicles_lined_in_gray_Where_the_clock_ticks_loud_by_the_light_of_day}
# 5.0 FINAL SCRIPT 

# 6.0 REFERENCE
