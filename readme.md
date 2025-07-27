| Category | CTF Name | Challenge Name | Type | Description | Date | Solved |
|----------|----------|----------------|------|-------------|------|--------|
| Crypto | DeadSec-25 | infant RSA | phi low 500 | 1. phi & ((1 << 500)-1) do what?<br>2. how to use this hint to get p / q? | 2025-07-27 | ✅ Yes |
| PWN | WDB-24 | pwn2 | STACK MITIGATION 32 | 1. why after system show sh: 1: \x0c-#: not found?<br>2. not enough buffer, how ?<br>3. how to generate stack mitigation payload | 2025-07-27 | ✅ Yes |
| AND | L3AKCTF-25 | Androbro |  | # 2.0 Analysis | 2025-07-23 | ✅ Yes |
| AND | L3AKCTF-25 | FileStorage |  | # 2.0 Analysis | 2025-07-23 | ✅ Yes |
| PWN | L3AKCTF-25 | Safe Gets | BO | 1. strlen -> /x00 to stop the checking<br>2. python wrapper only 0xff -> can use emoji in python on 1 length, but for c is 4 bytes | 2025-07-23 | ✅ Yes |
| RE | L3AKCTF-25 | ALPHA | GDB dump lief extract VM instruction | 1. HOW TO DUMP? with gdb script<br>2. what is the VM instruction?<br>3. z3 solve with instruction? | 2025-07-23 | ✅ Yes |
| RE | L3AKCTF-25 | PAC | DUMP MEMORY FILENAME START END | 1. Why decompile code so less?<br>2. How to dump it?<br>3. How to list stack variable value | 2025-07-23 | ✅ Yes |
| RE | L3AKCTF-25 | USELESS VM | JS DEBUG | 1. HOW TO DEBUG JS<br>2. WHERE TO debug? | 2025-07-23 | ✅ Yes |
| PWN | DownUnderCTF-25 | fakeobj.py | python debug | No description. | 2025-07-21 | ❌ No |
| PWN | L3AKCTF-25 | Chunky Threads | CANARY LEAK | 1. where is the leaking point?<br>2. how to find the canary?<br>3. canary rec, why need + b'\0'<br>4. leak stack find libc base<br>5. how to build ROP | 2025-07-21 | ✅ Yes |
| PWN | L3AKCTF-25 | THE GOOSE | ret2shellcode | 1. how to predict the rand ?<br>2. Python’s way of **getting the first byte as an integer**.<br>3. what position to format string<br>4. ret2libc or ret2shellcode<br>5. how to find buffer address<br>6. why need asm nop in shellcode | 2025-07-21 | ✅ Yes |
| RE | L3AKCTF-25 | JUST BUN IT | cyclic algo MOD | 1. why the code so messy?<br>2. find the pattern of result after run the elf<br>3. MOD | 2025-07-20 | ✅ Yes |
| PWN | L3AKCTF-25 | Go Write Where | WWW SYSCALL ROP | 1. typical Write Where What challenge<br>2. what address to write ?<br>3. write what value?<br>4. can only write once, how to increase LOOP<br>5. no libc no system, can only syscall<br>6. HOW to build syscall ROP? | 2025-07-17 | ✅ Yes |
