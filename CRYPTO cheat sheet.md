RSA common decrypt
```
from gmpy2 import isqrt, mpz
from Crypto.Util.number import long_to_bytes

n = 
c = 
e = 

# 计算p和q
p = 
q = 

# 验证分解结果
if p * q == n:
	print("[+] Found p and q!")
	print(f"p = {p}")
	print(f"q = {q}")
	
	d = pow(e, -1, int(phi_candidate))
	m = pow(c, d, n)
	flag = long_to_bytes(int(m))
	print("\nFlag:", flag.decode())
	break
```