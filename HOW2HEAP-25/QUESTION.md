我问 我答:
# 4.0 fastbin_dup_into_stack 2.39 with tcache
## 4.1 tache 是什么? 结构是怎样的?
简单来讲 
tcache 是一个“线程私有”的内存回收池，用于快速管理小块内存的分配与释放，避免频繁访问全局堆结构（如 fastbin、unsorted bin 等），减少锁竞争，提高性能
在没有 `tcache` 之前：
- 每次 `malloc` 或 `free` 都会访问全局堆结构。
- 多线程下会产生 **锁竞争（mutex）**，导致性能下降。

| 特性                   | 说明                                              |
| -------------------- | ----------------------------------------------- |
| 线程私有                 | 每个线程维护一个独立的 `tcache`，不与其他线程共享                   |
| 大小分类                 | 针对小块内存（≤ 1032 bytes），按大小分类（如 0x20、0x30...）      |
| 最多 7 个 chunk         | 每个大小 class 最多缓存 7 个 chunk（默认）                   |
| 无需锁操作                | tcache 操作只涉及当前线程，无需加锁，因此速度快                     |
| 优先使用 tcache          | 当 `malloc()` 请求的大小在 tcache 范围内，优先从 `tcache` 中取出 |
| `free()` 优先放回 tcache | 若当前大小类在 `tcache` 中未满，则直接回收到 `tcache`            |
```
Thread A 堆结构：
┌────────────────────────────┐
│ tcache                     │
│ ┌──────────────┐          │
│ │ size 0x20 → A │──→ B → C │  ← 本地链表（最多 7 个）
│ └──────────────┘          │
│ ...                       │
└────────────────────────────┘

Thread B 堆结构：
┌────────────────────────────┐
│ tcache (独立)              │
│ ┌──────────────┐          │
│ │ size 0x20 → X │──→ Y     │
│ └──────────────┘          │
└────────────────────────────┘
```

## 4.2 为什么要填7 次？
简单理解 
- 如果 tcache bin 还没满（<7），它会把 chunk 放进 tcache(不是 fastbin)
- 只有当 tcache bin 满了之后，再 `free()` 的 chunk 才会放到 fastbin

## 4.3 为什么要 A = A address >> 12 ^ stack address？
glibc 2.32+ 引入了 **safe-linking** 机制，防止堆链表的 **指针伪造（tcache poisoning）**
```
ori 
chunk->fd = next_chunk;

>2.32
chunk->fd = (next_chunk_addr >> 12) ^ current_chunk_addr;
```
所以当你做 tcache poisoning（伪造 fd），你必须伪造成：

`fd = (victim_chunk_addr >> 12) ^ target_address;`
这样当 malloc() 解码 fd 时，glibc 会做：
```
decoded = (fd) ^ (victim_chunk_addr >> 12)
        = ((victim_chunk_addr >> 12) ^ target_address) ^ (victim_chunk_addr >> 12)
        = target_address
```
这就成功把 malloc() 返回的地址伪造成你想要的地址（如栈地址）。

## 4.4. 为什么 set d value 就可以 改 next chunk 
因为你是在伪造 fastbin/tcache 中当前 chunk 的 `fd` 字段。
TB：
```
void* d = malloc(8);  // 分配出原先 free 掉的 chunk
*d = (addr >> 12) ^ stack_address;

这个 *d 实际上就是 堆块头部 8 字节的 fd 指针(next)
在 tcache 中，每个 chunk 的前 8 字节就是指向下一个 free chunk 的指针（被加密）：

struct malloc_chunk {
    ...
    void* fd; // tcache 使用的“下一个”指针
}

current_chunk->fd = safe_link_encoded(stack_address)
```
这样当你下一次 `malloc(8)`，它会解密这个 `fd` 并返回 **你想要的栈地址（+0x10 对齐）**。

## 4.5 什么是 tcache poisoning 
后面再 补上来
https://zhuanlan.zhihu.com/p/664043417
## 4.6 为什么返回 stack_address + 0x10?
因为 malloc 返回的是 **user data 部分**，而 `stack_address` 是你伪造的 **chunk header**（包含 fake size field），
所以它会返回 `stack_address + sizeof(size_t)*2 = +0x10`，这就是堆数据的实际起始。
