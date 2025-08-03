
要看 看这个[[TUTORIAL]]
问题 [[QUESTION]]
#### 🔰 第一阶段：基础知识与简单技巧（建议熟悉 glibc 2.27-2.29）

1. **unsafe_unlink.c** ✅
    - 最基础的堆 unlink 漏洞，适用于旧版本。
    - 学会 chunk 链表结构与 unlink 流程。
        
2. **poison_null_byte.c** ✅ 2.32 ❌
    - 经典堆溢出技巧，利用 null byte 改变 chunk size。
    - 适合理解 chunk 合并机制。
        
3. **fastbin_dup.c** ✅
    - fastbin 重复释放实现 double free。
    - 学会 fastbin 的 fd 指针操作。
        
4. **fastbin_dup_consolidate.c** ✅
    - 加深理解 fastbin 与 top chunk 合并。
        
5. **fastbin_dup_into_stack.c** ✅
    - 进阶 fastbin 利用，malloc 到栈地址。
        

---

#### 🚧 第二阶段：fastbin 和 tcache 利用（glibc 2.29–2.35）

1. **tcache_poisoning.c**
    
    - tcache 机制及其利用方式。
        
    - 常见于 glibc 2.27+。
        
2. **tcache_house_of_spirit.c**
    
    - 将 “伪 chunk” 放进 tcache freelist。
        
3. **tcache_metadata_poisoning.c**
    
    - 修改 metadata，触发任意地址写。
        
4. **fastbin_reverse_into_tcache.c**
    
    - 将 fastbin chunk 转移到 tcache 中，理解混合利用。
        
5. **house_of_spirit.c**
    
    - 基础版 spirit 技巧（与 tcache 版本对照学习）。
        

---

#### 🧠 第三阶段：堆重叠与高阶利用技巧（偏向 glibc 2.31+）

1. **overlapping_chunks.c**
    
    - 控制多个 chunk 重叠，用于任意地址写。
        
2. **mmap_overlapping_chunks.c**
    
    - mmap chunk 的 overlap 技巧。
        
3. **large_bin_attack.c**
    
    - largebin fd/bk 操控，覆盖全局变量或函数指针。
        
4. **house_of_lore.c**
    
    - 使用 unsorted bin，复杂的 chunk 操控。
        
5. **house_of_einherjar.c**
    
    - 高级 unlink 利用，构造复杂场景。
        

---

#### 🧪 第四阶段：新版本保护机制绕过与创新技巧（glibc 2.32–2.35）

1. **decrypt_safe_linking.c**
    
    - 绕过 safe-linking（防止 FD 泄漏的 XOR）。
        
2. **safe_link_double_protect.c**
    
    - 利用 double free 绕过 safe-linking。
        
3. **house_of_mind_fastbin.c**
    
    - 结合 fastbin 与 unsafe unlink 的新技巧。
        
4. **tcache_stashing_unlink_attack.c**
    
    - stashing 技巧，用于构造更复杂攻击链。
        
5. **house_of_botcake.c**
    
    - 先进技巧，将 chunk malloc 到栈地址。
        
6. **house_of_tangerine.c / house_of_water.c**
    
    - 创新技巧（非经典，适合提升眼界）