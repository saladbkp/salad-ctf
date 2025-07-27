## 1.0 Challenge
1. Why decompile code so less?
2. How to dump it?
3. How to list stack variable value
## 2.0 Analysis

总结来讲是
check length 32 
check flag 
but 
```cpp
void __fastcall start_0(__int64 a1, __int64 a2, int a3)
{
  unsigned __int64 v3; // kr00_8

  v3 = __getcallerseflags();                          // Save flags
  sub_40419E(&loc_401110, 756, byte_4041DB);          // Likely anti-debug/log
  __writeeflags(v3);                                  // Restore flags
  __debugbreak();                                     // <=== 🚨 Debug trap
  *(_DWORD *)(a1 - 1473916168) |= a3;                 // Memory write at weird offset
  JUMPOUT(0x40111D);                                  // Unusual jump
}
```
感觉entry point 很奇怪
看了 writeup 才知道 要dump 
  
FROM IDA
- **文件名**: pac
- **基地址**: 0x400000
- **文件大小**: 0x3ac0 (15040 bytes)

## 3.0 Solution

## 3.1 How to dump?
after start then go this function 
![[Pasted image 20250719232049.png]]
either break 04041d6 or ctrl c at input 
my idea is VMMAP then i know code is at 0x400000 - 0x405000
![[Pasted image 20250719232133.png]]
then only dump this area
`dump memory buffer2.bin 0x400000 0x405000`

## 3.2 Analyze Code
IN dogbolt
通过逆向分析，我们发现程序的主要流程如下：

1. 程序启动时执行自解密流程
2. 解密完成后，程序要求用户输入32字符的密码短语
3. 将输入分为4个64位块（两个数据块，每个数据块包含两个64位值）
4. 使用自定义的Feistel网络加密算法对输入进行加密
5. 将加密结果与预期值进行比较
6. 如果匹配，则显示成功消息

0x4011F6: encrypt_block = 加密单个数据块的核心函数 
0x401234: encrypt_data = 使用Feistel网络结构加密数据 
0x4012C8: main_logic = 主要业务逻辑，处理输入和验证 


  encrypt_block 函数 (0x4011F6)

```c
__int64 __fastcall encrypt_block(__int64 a1, __int64 a2)
{
  // 使用异或、左旋转和乘法运算的加密函数
  return __ROL8__(a2 ^ a1, 13) ^ (31 * (a2 ^ a1));
}
```

encrypt_data (0x401234)

```c

__int64 *__fastcall encrypt_data(__int64 *a1)

{

  // 使用Feistel网络结构的加密函数

  // 进行4轮加密，使用qword_402020数组作为轮密钥

  for ( i = 0; i <= 3; ++i )

  {

    v5 = *v4;  // 保存右半部分

    v2 = *a1;  // 保存左半部分

    *v4 = encrypt_block(*v4, qword_402020[i]) ^ v2;  // 新的右半部分

    *a1 = v5;  // 新的左半部分

  }

  return result;

}

```

  
## 3.3 extract value
可以看到有 store key address

![[Pasted image 20250719232733.png]]
then i just 
```
pwndbg> x/30gx 0x402020 
0x402020:       0x00001337deadbeef      0x0000c0de12345678
0x402030:       0x0000abcdef012345      0x00009876543210ab
0x402040:       0xfd83487a8f04bc91      0x1ea9b29316416331
0x402050:       0x2fbea4546b08944f      0x922e9e7e9854dcaf
0x402060:       0x6170207265746e45      0x6573617268707373
0x402070:       0x6168632032332820      0x000a00203a297372
0x402080:       0x2064696c61766e49      0x656c207475706e69
0x402090:       0x754d202e6874676e      0x7865206562207473
0x4020a0:       0x642520796c746361      0x7463617261686320
0x4020b0:       0x9ce2000a2e737265      0x000000989ce20094
0x4020c0:       0x000000443b031b01      0xffffef6000000007
0x4020d0:       0xffffefe000000088      0xfffff050000000b0
0x4020e0:       0xfffff08000000060      0xfffff13600000074
0x4020f0:       0xfffff174000000c8      0xfffff208000000e8
0x402100:       0x000000000000010c      0x0000000000000014
```

加密密钥数组 (0x402020)

```

0x402020: 0x00001337deadbeef 0x0000c0de12345678

0x402030: 0x0000abcdef012345 0x00009876543210ab

```

预期的加密结果 (0x402040-0x402050)

```

0x402040: 0xfd83487a8f04bc91 0x1ea9b29316416331

0x402050: 0x2fbea4546b08944f 0x922e9e7e9854dcaf

```

  
## 3.4 Decryption

IDK JUST GPT
Feistel网络的加密过程如下：
1. 将输入分为左右两部分（L0, R0）
2. 对于每一轮i：
   - Li+1 = Ri
   - Ri+1 = Li ⊕ F(Ri, Ki)，其中F是轮函数，Ki是轮密钥

解密过程则是：
1. 将密文分为左右两部分（Ln, Rn）
2. 对于每一轮i（从n-1到0）：
   - Ri = Li+1
   - Li = Ri+1 ⊕ F(Li+1, Kn-1-i)，注意密钥顺序是反向的

## 4.0 FLAG
L3AK{feistel_netWork_Is_fun!!!!}

## 5.0 FINAL SCRIPT

```python
import struct
import binascii

# Constants from memory dump
# Encryption keys from 0x402020
ENCRYPTION_KEYS = [
    0x00001337deadbeef,
    0x0000c0de12345678,
    0x0000abcdef012345,
    0x00009876543210ab
]

# Expected encrypted result from 0x402040-0x402050
ENCRYPTED_RESULT = [
    0xfd83487a8f04bc91, 0x1ea9b29316416331,  # First block (v1)
    0x2fbea4546b08944f, 0x922e9e7e9854dcaf   # Second block (v2)
]

# Encryption block function (from sub_4011F6)
def encrypt_block(a1, a2):
    """Encrypt a single block using the custom algorithm
    
    Args:
        a1: The data block
        a2: The key
        
    Returns:
        The encrypted block
    """
    # Implement __ROL8__(a2 ^ a1, 13) ^ (31 * (a2 ^ a1))
    xored = a2 ^ a1
    rol = ((xored << 13) | (xored >> (64 - 13))) & 0xFFFFFFFFFFFFFFFF
    multiplied = (31 * xored) & 0xFFFFFFFFFFFFFFFF
    return rol ^ multiplied

# Encryption function (from sub_401234)
def encrypt_data(data, keys):
    """Encrypt data using Feistel network with the given keys
    
    Args:
        data: List of two 64-bit integers [left_block, right_block]
        keys: List of encryption keys
        
    Returns:
        Encrypted data as [left_block, right_block]
    """
    left, right = data[0], data[1]
    
    for i in range(4):  # 4 rounds of encryption
        # Swap left and right
        left, right = right, encrypt_block(right, keys[i]) ^ left
    
    return [left, right]

# Decryption function (reverse of encrypt_data)
def decrypt_data(encrypted_data, keys):
    """Decrypt data using Feistel network with the given keys in reverse order
    
    Args:
        encrypted_data: List of two 64-bit integers [left_block, right_block]
        keys: List of encryption keys
        
    Returns:
        Decrypted data as [left_block, right_block]
    """
    left, right = encrypted_data[0], encrypted_data[1]
    
    # Use keys in reverse order for decryption
    for i in range(3, -1, -1):  # 4 rounds of decryption
        # Swap left and right, and apply the inverse operation
        left, right = right ^ encrypt_block(left, keys[i]), left
    
    return [left, right]

# Convert integer to bytes (little-endian)
def int_to_bytes(n):
    """Convert a 64-bit integer to 8 bytes (little-endian)"""
    return struct.pack("<Q", n)

# Main function to decrypt the flag
def decrypt_flag():
    """Decrypt the flag using the encrypted result and keys"""
    # Split encrypted result into two blocks
    block1 = ENCRYPTED_RESULT[0:2]
    block2 = ENCRYPTED_RESULT[2:4]
    
    # Decrypt each block
    decrypted_block1 = decrypt_data(block1, ENCRYPTION_KEYS)
    decrypted_block2 = decrypt_data(block2, ENCRYPTION_KEYS)
    
    # Convert decrypted integers to bytes
    flag_bytes = b''
    for block in [decrypted_block1, decrypted_block2]:
        for value in block:
            flag_bytes += int_to_bytes(value)
    
    # Try to decode as ASCII/UTF-8
    try:
        flag = flag_bytes.decode('utf-8').strip('\x00')
        print(f"Decrypted flag: {flag}")
    except UnicodeDecodeError:
        print(f"Could not decode as UTF-8. Raw bytes: {binascii.hexlify(flag_bytes)}")
        # Try to find printable characters
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in flag_bytes)
        print(f"Printable characters: {printable}")

# Test the encryption/decryption functions
def test_encryption():
    """Test the encryption function with a known input/output"""
    # Test data
    test_data = [0x1234567890ABCDEF, 0xFEDCBA0987654321]
    
    # Encrypt
    encrypted = encrypt_data(test_data, ENCRYPTION_KEYS)
    print(f"Original: {test_data}")
    print(f"Encrypted: {encrypted}")
    
    # Decrypt
    decrypted = decrypt_data(encrypted, ENCRYPTION_KEYS)
    print(f"Decrypted: {decrypted}")
    
    # Verify
    if decrypted == test_data:
        print("Encryption/decryption test passed!")
    else:
        print("Encryption/decryption test failed!")

# Main execution
if __name__ == "__main__":
    print("Pacman CTF Flag Decryption")
    print("-" * 30)
    
    # Test encryption/decryption
    print("Testing encryption/decryption:")
    test_encryption()
    print("-" * 30)
    
    # Decrypt the flag
    print("Attempting to decrypt the flag:")
    decrypt_flag()
    print("-" * 30)
```

ANGR WTF ???
```
import angr
proj = angr.Project('pac')
state = proj.factory.entry_state(
    add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
    }
)
simgr = proj.factory.simgr(state)
simgr.run()
flag = simgr.deadended[2].posix.dumps(0).decode()
print(f"{flag = }")
```