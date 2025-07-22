# 1.0 Challenge
1. HOW TO DUMP? with gdb script
2. what is the VM instruction?
3. z3 solve with instruction?

# 2.0 Analysis

This is a check flag function with sigaction DEBUG 
HOW TO KNOW?
`ltrace -i -S ./chal`
![[Pasted image 20250722220829.png]]
THIS IS IN IDA ANALYSIS
### 🔐 Custom Bitwise Arithmetic Functions

| Old Name   | Suggested Name           | Behavior Description                    |
| ---------- | ------------------------ | --------------------------------------- |
| `sub_1381` | `bitwise_xor_weird`      | Complex XOR/bit logic                   |
| `sub_1401` | `bitwise_mask_transform` | Inverts and mutates bits                |
| `sub_153B` | `custom_multiply`        | Manual multiply based on bits           |
| `sub_15B8` | `bit_and_multiply`       | Combines bit masking and multiplication |
| `sub_164A` | `bitwise_add_no_carry`   | Adds without carry                      |
| `sub_16C8` | `bitwise_sum_mod2`       | Bitwise addition mod 2                  |
| `sub_1728` | `bitwise_not_32bit`      | Inverts all bits of a 32-bit int        |
## 📌 Variable Renames

| Old Name     | New Name              | Description                             |
| ------------ | --------------------- | --------------------------------------- |
| `qword_3FA0` | `entry_point_func`    | Function pointer to obfuscated logic    |
| `off_3FD8`   | `libc_start_main_ptr` | Points to `__libc_start_main`           |
| `off_3FE8`   | `gmon_start_ptr`      | `_gmon_start__` (optional init call)    |
| `off_3FF8`   | `finalize_ptr`        | Usually `__cxa_finalize`                |
| `off_4008`   | `dtors_list_ptr`      | Possibly `.dtors` or similar            |
| `unk_4028`   | `decode_key_table`    | Probably decoding key pointer           |
| `byte_4038`  | `finalize_flag`       | Marks whether finalization was called   |
| `dword_403C` | `decode_index`        | Used to index into decode table         |
| `byte_2020`  | `decode_table[]`      | Table for XOR decoding                  |
| `qword_1350` | `decode_result[]`     | Stores decode result (first byte = '7') |
# 3.0 Solution

## 3.1 HOW TO DUMP?
1. EASY WAY IS CTRL C in the input then dump memory ....
then do static analysis 
```
__int64 qword_1350[6] =
{
  5260204354197571383LL,
  -8554587491439868533LL,
  52072870645000391LL,
  7275659254713810944LL,
  172420770632LL,
  -3891110089827285644LL
}; // weak
_BYTE byte_2020[2560] =
{
  90,
  -10,
  81,
  -22,
  -9,
  17,
  .......
  }
```

2. A JAPAN GUY DYNAMIC dump with gdb script
https://github.com/Tan90909090/ctf-writeups/blob/main/L3akCTF_2025/Alpha/my-script.py
```
#!/usr/bin/env python3
# Usage: gdb -q -x ./my-script.py chal
# Note: pwngdb is required (due to piebase command)

import gdb

# Python API利用コードのデバッグ時に役立ちます
gdb.execute("set python print-stack full")

INPUT_FILENAME = "input.txt"
with open(INPUT_FILENAME, "w") as f:
    f.write("test")

# piebaseコマンドは実行後にのみ動作します
gdb.execute(f"starti < {INPUT_FILENAME}")


def get_va(rva: int) -> int:
    output = gdb.execute(f"piebase {hex(rva)}", to_string=True)
    return int(output.split(" = ")[1], 0)


addr_main = get_va(0x1310)
addr_sighandler = get_va(0x11E9)
addr_sighandler_ret = get_va(0x1282)
print(f"{addr_main = :#018x}")


def print_main_instructions_until_bad():
    for line in gdb.execute(f"x/64i {hex(addr_main)}", to_string=True).splitlines():
        if "nop" in line:
            continue
        if "(bad)" in line:
            break
        print(line)


class MyTraceBreakpoint(gdb.Breakpoint):
    def __init__(self, spec: str):
        super(MyTraceBreakpoint, self).__init__(
            spec,
            type=gdb.BP_HARDWARE_BREAKPOINT,
            internal=False,
            temporary=False,
        )

    def stop(self):
        # memory = gdb.inferiors()[0].read_memory(addr_main, 0x40).tobytes()
        # print(memory)
        print_main_instructions_until_bad()  # signal handlerで書き換えられた後のmain内容
        return False  # Continue execution (equivalent to `silent` in GDB)


# 何故かmain先頭へハードウェアブレークポイントを設置しても1回目だけヒットしたので、signal handlerからreturnするところで再ダンプする
MyTraceBreakpoint(f"*{hex(addr_sighandler_ret)}")

# 最初のmain内容
print_main_instructions_until_bad()

gdb.execute("handle SIGILL pass noprint")  # SIGILL発生時にgdbを止めない
# gdb.execute(rf"""dprintf *{hex(addr_sighandler)}, "SIGILL!\n" """)
gdb.execute("continue")
gdb.execute("quit")
```

FINAL RESULT CAN SEE THIS 
can almost see the instruction 
![[Pasted image 20250722221258.png]]
```
   0x555555555310:	movsx  ebx,al
   0x555555555313:	movzx  eax,BYTE PTR [rbp-0x60]
   0x555555555317:	movsx  r12d,al
   0x55555555531b:	movzx  eax,BYTE PTR [rbp-0x54]
   0x55555555531f:	movsx  edx,al
   0x555555555322:	movzx  eax,BYTE PTR [rbp-0x53]
   0x555555555326:	movsx  eax,al
   0x555555555329:	mov    esi,edx
   0x55555555532b:	mov    edi,eax
   0x55555555532d:	call   0x55555555564a
   0x555555555332:	mov    esi,r12d
   0x555555555335:	mov    edi,eax
   0x555555555337:	call   0x5555555556c8
   0x55555555533c:	mov    esi,ebx
   0x55555555533e:	mov    edi,eax
   0x555555555340:	call   0x55555555553b
   0x555555555345:	cmp    eax,0x1326
```

## 3.2 what is the VM instruction?
JAPAN GUY IS VERY SMART AND I NEVER KNOW TIS WAY 

first u can see 
the flow is like 
```
r12d = 0x60
edx = 0x54
eax = 0x53
eax = 0x55555555564a(eax,edx)
eax = 0x5555555556c8(eax,r12d)
eax = 0x55555555553b(eax,ebx)
compare(eax == 0x1326)
```
so what is the 0x55555555564a 0x5555555556c8 0x55555555553b
can check in binary ninja 
![[Pasted image 20250722221714.png]]
so these are the instruction, can read thru the IDA but japan guy have a smartest way
i modified a bit
```python
#!/usr/bin/env python

import ctypes
import lief
import operator

bin: lief.ELF.Binary = lief.parse("./chal")

function_rva_list = [0x1381, 0x1401, 0x153B, 0x15B8, 0x164A, 0x16C8, 0x1728]

for rva in function_rva_list:
    bin.add_exported_function(rva, f"rva_{hex(rva)}")
bin[lief.ELF.DynamicEntry.TAG.FLAGS_1].remove(lief.ELF.DynamicEntryFlags.FLAG.PIE)
bin.write("chal.so")

lib = ctypes.CDLL("./chal.so")

# Test pattern: sufficient to identify most operations
test_pattern = list(range(10)) + [0x10, 0x100, 0x1000, 0xFFFFFFFF]

# Define candidate operations
ops_2arg = {
    "Add": operator.add,
    "Sub": operator.sub,
    "Mul": operator.mul,
    "BitAnd": operator.and_,
    "BitOr": operator.or_,
    "Xor": operator.xor,
}
ops_1arg = {
    "BitNot": lambda x: ~x
}

# Try to match a function to a known operation
def match_operation(func, is_unary=False):
    if is_unary:
        results = {op_name: True for op_name in ops_1arg}
        for a in test_pattern:
            actual = func(a)
            for name, op in ops_1arg.items():
                try:
                    expected = op(a) & 0xFFFFFFFF  # mask to 32-bit
                    if actual != expected:
                        results[name] = False
                except:
                    results[name] = False
        for name, ok in results.items():
            if ok:
                return name
    else:
        results = {op_name: True for op_name in ops_2arg}
        for a in test_pattern:
            for b in test_pattern:
                actual = func(a, b)
                for name, op in ops_2arg.items():
                    try:
                        expected = op(a, b) & 0xFFFFFFFF
                        if actual != expected:
                            results[name] = False
                    except:
                        results[name] = False
        for name, ok in results.items():
            if ok:
                return name
    return "Unknown"

print("RVA\t\tFunction")
for i, rva in enumerate(function_rva_list):
    func_name = f"rva_{hex(rva)}"
    func = getattr(lib, func_name)
    func.argtypes = [ctypes.c_uint32] * (1 if i == len(function_rva_list) - 1 else 2)
    func.restype = ctypes.c_uint32

    operation = match_operation(func, is_unary=(i == len(function_rva_list) - 1))
    print(f"{hex(rva)}\t{operation}")

```
RESULT
```
└─$ python extract_code.py
RVA             Function
0x1381  Add
0x1401  Sub
0x153b  Mul
0x15b8  BitAnd
0x164a  BitOr
0x16c8  Xor
0x1728  BitNot
```

ORI_SCRIPT
https://github.com/Tan90909090/ctf-writeups/blob/main/L3akCTF_2025/Alpha/test-chal-functions.py
```
#!/usr/bin/env python

import ctypes

import lief  # https://lief.re/doc/latest/installation.html

bin: lief.ELF.Binary = lief.parse("./chal")

# 最後の関数だけ引数1個、他は引数2個
function_rva_list = [0x1381, 0x1401, 0x153B, 0x15B8, 0x164A, 0x16C8, 0x1728]

for rva in function_rva_list:
    bin.add_exported_function(rva, f"rva_{hex(rva)}")
bin[lief.ELF.DynamicEntry.TAG.FLAGS_1].remove(lief.ELF.DynamicEntryFlags.FLAG.PIE)
bin.write("chal.so")

lib = ctypes.CDLL("./chal.so")

test_pattern = list(range(10)) + [0x10, 0x100, 0x1000, 0xFFFFFFFF]
for rva in function_rva_list:
    func_name = f"rva_{hex(rva)}"
    func = lib[func_name]
    for a in test_pattern:
        for b in test_pattern:
            result = func(a, b)
            print(f"{func_name}({a}, {b}) = {result}")
```
RESULT
```
rva_0x16c8(4294967295, 7) = -8
rva_0x16c8(4294967295, 8) = -9
rva_0x16c8(4294967295, 9) = -10
rva_0x16c8(4294967295, 16) = -17
rva_0x16c8(4294967295, 256) = -257
rva_0x16c8(4294967295, 4096) = -4097
rva_0x16c8(4294967295, 4294967295) = 0
rva_0x1728(0, 0) = -1
rva_0x1728(0, 1) = -1
rva_0x1728(0, 2) = -1
rva_0x1728(0, 3) = -1
```

THEN YOU CAN KNOW THE RELATIONSHIP

## 3.3 z3 solve with instruction?
use this map
```
0x1381  Add
0x1401  Sub
0x153b  Mul
0x15b8  BitAnd
0x164a  BitOr
0x16c8  Xor
0x1728  BitNot
```
with list all instruction 
```
r12d = 0x60
edx = 0x54
eax = 0x53
eax = BitOr_64a(eax,edx)
eax = Xor_6c8(eax,r12d)
eax = Mul_53b(eax,ebx)
s.add(eax == 0x1326)
```

TWO WAYS 
1. recompile the extracted main then recompile with own mapping function in ASM 
2. z3 solve with manual input variable / auto way 

FIRST I SAVE IN TXT
```
   0x555555555310:	movsx  ebx,al
   0x555555555313:	movzx  eax,BYTE PTR [rbp-0x60]
   0x555555555317:	movsx  r12d,al
   0x55555555531b:	movzx  eax,BYTE PTR [rbp-0x54]
   0x55555555531f:	movsx  edx,al
   0x555555555322:	movzx  eax,BYTE PTR [rbp-0x53]
   0x555555555326:	movsx  eax,al
   0x555555555329:	mov    esi,edx
   0x55555555532b:	mov    edi,eax
   0x55555555532d:	call   0x55555555564a
   0x555555555332:	mov    esi,r12d
   0x555555555335:	mov    edi,eax
   0x555555555337:	call   0x5555555556c8
   0x55555555533c:	mov    esi,ebx
   0x55555555533e:	mov    edi,eax
   0x555555555340:	call   0x55555555553b
   0x555555555345:	cmp    eax,0x1326
```
EXTRACT LIKE THIS
```PYTHON
import re

# Mapping of known function addresses to operations
func_map = {
    "0x555555555381": "Add",
    "0x555555555401": "Sub",
    "0x55555555553b": "Mul",  
    "0x5555555555b8": "BitAnd",
    "0x55555555564a": "BitOr",
    "0x5555555556c8": "Xor", 
    "0x555555555728": "BitNot", 
}

# Registers
reg_state = {}
al_origin = None  # Track where 'al' came from
lines_out = []

def get_input_offset(src):
    m = re.match(r"BYTE PTR \[rbp-(0x[0-9a-f]+)\]", src)
    if m:
        return int(m.group(1), 16)
    return None

with open("trace.txt", "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        match = re.match(r"^\s*(0x[0-9a-f]+):\s+(\w+)\s+(.*)", line)
        if not match:
            continue

        addr, instr, operands = match.groups()
        instr = instr.lower()
        operands = operands.strip()

        if instr.startswith("movzx") or instr.startswith("mov"):
            parts = [x.strip() for x in operands.split(',')]
            if len(parts) != 2:
                continue
            dst, src = parts

            # movzx eax, BYTE PTR [rbp-0x60]
            if "BYTE PTR" in src:
                offset = get_input_offset(src)
                if dst == "eax" or dst == "al":
                    al_origin = offset
                    reg_state["eax"] = offset
                else:
                    reg_state[dst] = offset
                # lines_out.append(f"{dst} = 0x{offset:x}")

            elif src == "al":
                if al_origin is not None:
                    reg_state[dst] = f"get_input({al_origin})"
                    # lines_out.append(f"{dst} = 0x{al_origin:x}")
            elif src in reg_state:
                reg_state[dst] = reg_state[src]
                # Only show if meaningful (e.g., not eax = al)
                if dst != src:
                    pass
                    # lines_out.append(f"{dst} = {reg_state[src]}")
            else:
                reg_state[dst] = src

        elif instr == "call":
            func_addr = operands
            func_name = func_map.get(func_addr, None)
            if func_name:
                a = reg_state.get("edi", "edi")
                b = reg_state.get("esi")
                if b is not None:
                    expr = f"{func_name}({a},{b})"
                else:
                    expr = f"{func_name}({a})"
                reg_state["eax"] = expr
                # lines_out.append(f"eax = {expr}")
            else:
                pass
                # lines_out.append(f"# call to unknown function {func_addr}")

        elif instr == "cmp":
            parts = [x.strip() for x in operands.split(',')]
            if len(parts) == 2:
                lhs, rhs = parts
                lhs_val = reg_state.get(lhs, lhs)
                lines_out.append(f"s.add({lhs_val} == {rhs})")

# Output final symbolic trace
for line in lines_out:
    print(line)
    if("s.add"  in line):
        print()
        # break

```
RESULT
```
┌──(kali㉿kali)-[~/Desktop/CTF/lake/r3 apha]
└─$ python dec_v2.py
s.add(Mul(Xor(BitOr(get_input(83),get_input(84)),get_input(96)),ebx) == 0x1326)

s.add(Xor(Sub(BitOr(get_input(82),get_input(86)),get_input(74)),get_input(76)) == 0xffffffc0)

s.add(Sub(Sub(Xor(get_input(89),get_input(86)),get_input(84)),get_input(94)) == 0xffffffb9)

s.add(Mul(BitAnd(Xor(get_input(76),get_input(89)),get_input(80)),get_input(85)) == 0x22e2)

s.add(Mul(Xor(Mul(get_input(95),get_input(88)),get_input(81)),get_input(89)) == 0x44126)

s.add(BitOr(Xor(Xor(get_input(74),get_input(95)),get_input(88)),get_input(76)) == 0x73)
```

WHY I NEED THE get_input?
```
ins = {}
for i in range(0x49, 0x61):
    ins[i] = BitVec(f'in_{i:x}', 8)

def get_input(offset):
    if offset in ins:
        return SignExt(24, ins[offset])
```
make ins to 8 + 24 = 32 bits
because have negative hex so must extend 
-0x40 = 0xffffffc0
![[Pasted image 20250723032401.png]]
key_byte_1 -> cincai put but must same 
like k1 = BitVec('k1',8)

key_byte_1 = BitVec('key_byte_1', 8)
ebx = SignExt(24, key_byte_1)
这个是给第一个 ebx 因为他是unknown 

# 4.0 FLAG 

L3AK{R3m0V&_Qu@n~iF!3rs}
# 5.0 FINAL SCRIPT 

```
from z3 import *

s = Solver()

# 0x1381 - Add
def Add(a, b):
    return a + b

# 0x1401 - Sub
def Sub(a, b):
    return a - b

# 0x153b - Mul
def Mul(a, b):
    return a * b

# 0x15b8 - BitAnd
def BitAnd(a, b):
    return a & b

# 0x164a - BitOr
def BitOr(a, b):
    return a | b

# 0x16c8 - Xor
def Xor(a, b):
    return a ^ b

# 0x1728 - BitNot (unary)
def BitNot(a):
    return ~a

ins = {}
for i in range(0x49, 0x61):
    ins[i] = BitVec(f'in_{i:x}', 8)

def get_input(offset):
    if offset in ins:
        return SignExt(24, ins[offset])

key_byte_1 = BitVec('key_byte_1', 8)
ebx = SignExt(24, key_byte_1)

# 将表达式中对应的数替换为变量 v[i]
s.add(Mul(Xor(BitOr(get_input(83),get_input(84)),get_input(96)),ebx) == 0x1326)

s.add(Xor(Sub(BitOr(get_input(82),get_input(86)),get_input(74)),get_input(76)) == 0xffffffc0)

s.add(Sub(Sub(Xor(get_input(89),get_input(86)),get_input(84)),get_input(94)) == 0xffffffb9)

s.add(Mul(BitAnd(Xor(get_input(76),get_input(89)),get_input(80)),get_input(85)) == 0x22e2)

s.add(Mul(Xor(Mul(get_input(95),get_input(88)),get_input(81)),get_input(89)) == 0x44126)

s.add(BitOr(Xor(Xor(get_input(74),get_input(95)),get_input(88)),get_input(76)) == 0x73)

s.add(Xor(Add(BitOr(get_input(78),get_input(76)),get_input(85)),get_input(95)) == 0xe5)

s.add(BitAnd(Mul(Mul(get_input(83),get_input(96)),get_input(92)),get_input(75)) == 0x50)

s.add(Xor(Xor(Add(get_input(92),get_input(84)),get_input(90)),get_input(74)) == 0x8c)

s.add(Mul(Add(Xor(get_input(93),get_input(94)),get_input(78)),get_input(91)) == 0x19a0)

s.add(Add(BitAnd(Mul(get_input(78),get_input(96)),get_input(90)),get_input(82)) == 0x40)

s.add(BitAnd(BitOr(BitAnd(get_input(94),get_input(94)),get_input(92)),get_input(91)) == 0x52)

s.add(Sub(Mul(Xor(get_input(96),get_input(87)),get_input(84)),get_input(81)) == 0x7cc)

s.add(Xor(Add(Mul(get_input(79),get_input(84)),get_input(75)),get_input(85)) == 0x21f4)

s.add(Xor(Add(BitAnd(get_input(74),get_input(84)),get_input(74)),get_input(79)) == 0xad)

s.add(Mul(BitAnd(Xor(get_input(73),get_input(80)),get_input(73)),get_input(79)) == 0x69)

s.add(Sub(BitAnd(Sub(get_input(94),get_input(96)),get_input(95)),get_input(75)) == 0xffffffbf)

s.add(Mul(Xor(Mul(get_input(82),get_input(74)),get_input(96)),get_input(94)) == 0x73f8c)

s.add(Sub(Mul(Sub(get_input(92),get_input(81)),get_input(78)),get_input(76)) == 0x35b)

s.add(Mul(Mul(Sub(get_input(95),get_input(88)),get_input(91)),get_input(95)) == 0x3102)

s.add(Sub(Add(Sub(get_input(82),get_input(80)),get_input(93)),get_input(90)) == 0xffffffda)

s.add(BitAnd(BitAnd(Xor(get_input(73),get_input(75)),get_input(75)),get_input(85)) == 0x2)

s.add(Sub(Add(BitAnd(get_input(73),get_input(83)),get_input(77)),get_input(90)) == 0x63)

s.add(Xor(Xor(Add(get_input(85),get_input(73)),get_input(80)),get_input(92)) == 0xd9)

s.add(Add(Xor(Mul(get_input(83),get_input(83)),get_input(93)),get_input(88)) == 0x3562)

s.add(BitOr(Xor(BitAnd(get_input(75),get_input(81)),get_input(95)),get_input(88)) == 0x71)

s.add(Xor(Sub(BitAnd(get_input(82),get_input(81)),get_input(94)),get_input(85)) == 0xffffffa0)

if s.check() == sat:
    m = s.model()
    flag_bytes = [m[ins[i]].as_long() for i in sorted(ins)[::-1]]
    print("Flag:", bytes(flag_bytes))
else:
    print("No solution found.")


```

# 6.0 REFERENCE 
https://gist.github.com/tien0246/3750e630af623effa3f92c7395ebf4b9#file-systrace-bt

japan dynamic
https://tan.hatenadiary.jp/entry/2025/07/16/022507

gdb debug
https://github.com/braazaareer/writeup/blob/main/reverse_engineering/L3akCTF_2025/Alpha/Write_up.md