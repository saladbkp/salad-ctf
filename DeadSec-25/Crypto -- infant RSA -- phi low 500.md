# 1.0 Challenge
1. phi & ((1 << 500)-1) do what?
2. how to use this hint to get p / q?
# 2.0 Analysis

source code
```
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long
from secret import flag

p, q = getPrime(512), getPrime(512)
n = p * q
e = 65537
phi = (p-1) * (q-1)
hint = phi & ((1 << 500)-1)

m = bytes_to_long(flag)
c = pow(m, e, n)

print(f'{n=}')
print(f'{c=}')
print(f'{hint=}')
#n=144984891276196734965453594256209014778963203195049670355310962211566848427398797530783430323749867255090629853380209396636638745366963860490911853783867871911069083374020499249275237733775351499948258100804272648855792462742236340233585752087494417128391287812954224836118997290379527266500377253541233541409
#c=120266872496180344790010286239079096230140095285248849852750641721628852518691698502144313546787272303406150072162647947041382841125823152331376276591975923978272581846998438986804573581487790011219372437422499974314459242841101560412534631063203123729213333507900106440128936135803619578547409588712629485231
#hint=867001369103284883200353678854849752814597815663813166812753132472401652940053476516493313874282097709359168310718974981469532463276979975446490353988
```

# 3.0 Solution

1. What is phi & ((1 << 500)-1) doing?
理解关系
```
phi = (p-1) * (q-1)
    = p*q - p - q + 1 
    = n - (p + q) + 1 
p + q = n + 1 - phi
phi = n - (p + q) + 1

hint 给出了 phi 的低500位
phi 平时大概是1024
因为p q 是 512
所以我们还需要 1024 - 500 = 524

hint = phi & ((1 << 500)-1)
phi = (x << 500) + hint
x 是一个524位的数
```
2. How to use it to get p / q?
找k 
```
假设我懂要找 x 可是从哪里 开始？

x = k
因为 phi = φ(n) ≈ n - 2√n + 1，可估算k ≈ (n + 1 - hint - 2√n) >> 500
真实k在近似值附近的小范围内（±10000）
around x_guess = (n + 1 - hint) >> 500

对每个候选k，计算φ(n)候选值
用φ(n)计算p+q = n + 1 - φ(n)
检查p+q是否满足二次方程：t² - (p+q)t + n = 0有整数解

如果找到了 就直接 解
```
3. How to filter?
```
p + q > 0 /////

# 检查判别式是否为完全平方数 ////
D = p_plus_q**2 - 4 * n > 0

不是很需要？？？？？？？
root = isqrt(D)
if root * root != D:
	continue
```

FLOW
x_guess = (n + 1 - hint) >> 500  # 计算k的近似值
low_k = x_guess - 10000 # 设置搜索范围（扩大范围确保覆盖）
high_k = x_guess + 10000
for loop low_k high_k+1
phi_candidate = (k << 500) + hint # 计算候选phi(n)
p_plus_q = n + 1 - phi_candidate # 计算p+q
D = p_plus_q**2 - 4 * n # 检查判别式是否为完全平方数
p = (p_plus_q - root) // 2 # 计算p和q
q = (p_plus_q + root) // 2
normal decrypt
# 4.0 FLAG 

deadsec{1_w0nd3r_1f_7h15_p40bl3m_c0u1d_b3_s0lv3d_1f_m0r3_b1t7_w343_unKn0wn}

# 5.0 FINAL SCRIPT 
```
from gmpy2 import isqrt, mpz
from Crypto.Util.number import long_to_bytes

# 给定值
n = mpz(144984891276196734965453594256209014778963203195049670355310962211566848427398797530783430323749867255090629853380209396636638745366963860490911853783867871911069083374020499249275237733775351499948258100804272648855792462742236340233585752087494417128391287812954224836118997290379527266500377253541233541409)
c = mpz(120266872496180344790010286239079096230140095285248849852750641721628852518691698502144313546787272303406150072162647947041382841125823152331376276591975923978272581846998438986804573581487790011219372437422499974314459242841101560412534631063203123729213333507900106440128936135803619578547409588712629485231)
hint = mpz(867001369103284883200353678854849752814597815663813166812753132472401652940053476516493313874282097709359168310718974981469532463276979975446490353988)
e = 65537

# 计算k的近似值
x_guess = (n + 1 - hint) >> 500

# 设置搜索范围（扩大范围确保覆盖）
low_k = x_guess - 10000
high_k = x_guess + 10000

# 搜索正确的k值
for k in range(int(low_k), int(high_k) + 1):
    # 计算候选phi(n)
    phi_candidate = (k << 500) + hint
    print(k,phi_candidate)
    # 计算p+q
    p_plus_q = n + 1 - phi_candidate
    if p_plus_q <= 0:
        continue
    
    # 检查判别式是否为完全平方数
    D = p_plus_q**2 - 4 * n
    if D < 0:
        continue
    
    root = isqrt(D)
    if root * root != D:
        continue
    
    # 计算p和q
    p = (p_plus_q - root) // 2
    q = (p_plus_q + root) // 2
    
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
else:
    print("[-] Failed to find solution in the given range")
    print("Try increasing the search range")
```


# 6.0 REFERENCE
