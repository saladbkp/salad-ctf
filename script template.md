simple
```python
from pwn import *


elf = context.binary = ELF("./chall")
p = process()
p = remote("34.45.81.67",16002)
     
gdb.attach(p)

p.sendline()
p.interactive()
```

for libc
```

```

for heap
```

```
