# 1.0 Challenge
1. why stop at middle anything stop it?
2. how to NOP it
# 2.0 Analysis
这个static solve 也是不难 但是 我想用 dynamic 的方法 solve
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD v4[2]; // [rsp+20h] [rbp-40h] BYREF
  char v5; // [rsp+30h] [rbp-30h]
  _QWORD v6[2]; // [rsp+40h] [rbp-20h] BYREF
  char v7; // [rsp+50h] [rbp-10h]

  _main();
  v6[0] = 0xE8BEF2E0E0D2D6E6uLL;
  v6[1] = 0xBED0E6EAC4BECAD0uLL;
  v7 = 64;
  sandwich(v6);
  v4[0] = 0xDEDEE4C2CEDCC2D6uLL;
  v4[1] = 0xDEDEDEDEDEDEDEDEuLL;
  v5 = 64;
  sandwich(v4);
  decrypt_bytestring(v6, v4);
  return 0;
}

__int64 __fastcall sandwich(__int64 a1)
{
  stone(a1);
  decryptor(a1);
  return stone(a1);
}

// write access to const memory has been detected, the output may be wrong!
const char *__fastcall stone(char *a1)
{
  FILE *v1; // rax
  FILE *v2; // rax
  const char *result; // rax

  v1 = __acrt_iob_func(2u);
  _mingw_fprintf(v1, "%s\n", "Oh no! Skippy is about to trip!");
  v2 = __acrt_iob_func(2u);
  fflush(v2);
  result = "Oh no! Skippy is about to trip!";
  aOhNoSkippyIsAb[0] = *a1;
  return result;
}

int __fastcall decryptor(__int64 a1)
{
  FILE *v1; // rax
  FILE *v2; // rax
  int result; // eax
  unsigned __int64 i; // [rsp+28h] [rbp-8h]

  v1 = __acrt_iob_func(2u);
  fwrite("Uh oh... Skippy sees a null zone in the way...\n", 1u, 0x2Fu, v1);
  v2 = __acrt_iob_func(2u);
  fflush(v2);
  result = _mingw_printf("%d\n", MEMORY[0]);
  for ( i = 0; i <= 0xF; ++i )
  {
    result = a1 + i;
    *(_BYTE *)(a1 + i) >>= 1;
  }
  return result;
}
```

# 3.0 Solution
## 3.1 why stop at middle anything stop it?
如果进 stone function 会看到 红色 
这个就是 花指令？所以
```
// write access to const memory has been detected, the output may be wrong!
```
GPT 找出有问题的地方
![[Pasted image 20250808034057.png]]

# 4.0 FLAG 
not solve but learn how to NOP
# 5.0 FINAL SCRIPT 

# 6.0 REFERENCE
