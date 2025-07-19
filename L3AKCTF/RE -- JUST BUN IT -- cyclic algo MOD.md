# 1.0 Challenge
1. why the code so messy?
2. find the pattern of result after run the elf
3. MOD

# 2.0 Analysis
a bit messy so run the program see the output
```cpp
004047b1        void* fsbase
004047b1        int64_t rax = *(fsbase + 0x28)
004047c4        int32_t rbx
004047c4        
004047c4        if (arg1 == 3)
00404851            void var_48
00404851            sub_40507e(&var_48, arg2[1])
00404867            int64_t rax_8 = sub_404c23(&var_48, nullptr, 0xa)
00404877            sub_474860(&var_48)
004048ad            sub_40507e(&var_48, arg2[2])
004048be            int64_t zmm0_1 = sub_404c71(&var_48, nullptr)
004048d3            sub_474860(&var_48)
004048d3            
00404900            if (0.0 f> zmm0_1 || not(zmm0_1 f< 0x3ff0000000000000))
00404916                sub_46e490(&data_5dc380, "Error: x must be in [0,1)\n")
0040491b                rbx = 1
00404900            else
004049bc                sub_46cf80(sub_46e3c0(&data_5dc4a0, *sub_474d90(&data_5db560, sx.q((modu.dp.q(0:(sx.q(int.d(100.0 * sub_40473d(rax_8, zmm0_1)))), sub_474a80(&data_5db560))).d))), sub_46dd70, sub_46dd70)
004049c1                rbx = 0
004047c4        else
00404804            sub_46e490(sub_46e490(sub_46e490(&data_5dc380, "Usage: "), *arg2), " <n> <x>\n")
0040481d            sub_46e490(&data_5dc380, "n: non-negative integer, x: real…")
00404822            rbx = 1
00404822        
004049cc        *(fsbase + 0x28)
004049cc        
004049d5        if (rax == *(fsbase + 0x28))
00404acb            return zx.q(rbx)
00404acb        
00404ac1        sub_52f020()
00404ac1        noreturn
```

the input format `./runme <n> <x>`
u can see the 1 0 and 5 0 is same and keep repeating so
we no need to care how big is the n
```
┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 
Usage: ./runme <n> <x>
n: non-negative integer, x: real number in [0,1)

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 0 0
0

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 0 1
Error: x must be in [0,1)

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 0 2
Error: x must be in [0,1)

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 1 0 
T

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 2 0 
a

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 3 0 
p

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 4 0 
0

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 5 0 
T

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 6 0  
a

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 7 0 
p

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 8 0 
0

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 4843 0.362 
l

┌──(kali㉿kali)-[~/Desktop/CTF/lake/r2 Just Bun It]
└─$ ./runme 956458 0.78 
3

```
# 3.0 Solution

## 3.1 MOD 4
see the input.txt last n is very big
so just mod them to 4 and test is same or not
like 
./runme 4843 0.362 
./runme 3 0.362 
they are same result 'l'
```python
import ast

# Step 1: Read and parse the input
with open('input.txt', 'r') as f:
    data = ast.literal_eval(f.read())

# Step 2: Apply `mod 4` to the first element of each pair
modified = [[num % 4, val] for num, val in data]

# Step 3: Write the result back in original list format
with open('output.txt', 'w') as f:
    f.write(str(modified))

```

then auto run only
# 4.0 FLAG 

l3ak{bun_thought_binary_lifting_was_neeRed_turns_out_f_was_cyclic_after_all}
# 5.0 FINAL SCRIPT 

```python
#!/usr/bin/env python3
import subprocess
import ast

filename = "output.txt"

# Step 1: Load list of [int, float] pairs from file
with open(filename, 'r') as f:
    pairs = ast.literal_eval(f.read())

# Step 2: Call ./runme on each pair, collect output
result = ""
for num, val in pairs:
    # Format float to pass correctly
    proc = subprocess.run(
        ["./runme", str(num), str(val)],
        capture_output=True,
        text=True
    )
    if proc.returncode != 0:
        print(f"Error running ./runme {num} {val}")
        continue
    char = proc.stdout.strip()
    result += char

# Step 3: Print final concatenated string
print(result)

```