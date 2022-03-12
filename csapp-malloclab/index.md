# CSAPP Malloclab

# CSAPP-Malloclab

<!--more-->
大致框架使用课本上的示例，补充一些宏定义。
```c
/* Basic constants and macros */
#define WSIZE 4             /* Word and header/footer size (bytes) */
#define DSIZE 8             /* Double word size (bytes) */
#define CHUNKSIZE (1<<12)   /* Extend heap by this amount (bytes) */
#define MINBLOCKSIZE 16

#define MAX(x, y) ((x) > (y) ? (x) : (y))

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc) ((size) | (alloc)) 

/* Read and write a word at address p */
#define GET(p)      (*(unsigned int *)(p)) /* read a word at address p */
#define PUT(p, val) (*(unsigned int *)(p) = (val)) /* write a word at address p */

#define GET_SIZE(p)     (GET(p) & ~0x7) /* read the size field from address p */
#define GET_ALLOC(p)    (GET(p) & 0x1) /* read the alloc field from address p */

#define HDRP(bp) ((char*)(bp) - WSIZE) /* given block ptr bp, compute address of its header */
#define FTRP(bp) ((char*)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) /* given block ptr bp, compute address of its footer */

#define NEXT_BLKP(bp) ((char*)(bp) + GET_SIZE(HDRP(bp))) /* given block ptr bp, compute address of next blocks */
#define PREV_BLKP(bp) ((char*)(bp) - GET_SIZE((char*)(bp)-DSIZE)) /* given block ptr bp, compute address of prev blocks */
```
此时，chunk的结构为：
```c
struct chunk{
	int header;			/*header==footer*/
	char data[size];
	char padding[align];
	int footer;
}
```
书中实现了`mm_init`, `mm_malloc`, `mm_free`, `extend_heap`, `coalesce`, 根据书中的代码我们实现：
 **mm_realloc**
```c
void *mm_realloc(void *ptr, size_t size)
{
    void *new_ptr;

    if(ptr==NULL){
        new_ptr=mm_malloc(size);
        if (new_ptr == NULL)
            return NULL;
        return new_ptr;
    }
    if(size==0){
        mm_free(ptr);
        return NULL;
    }
    if(size==GET_SIZE(HDRP(ptr))){
        return ptr;
    }
    else{  
        new_ptr=mm_malloc(size);
        if (new_ptr == NULL)
            return NULL;
        memcpy(new_ptr, ptr, size-WSIZE);
        mm_free(ptr);
        return new_ptr;
    }
}
```
**place**
```c
static void place(void *bp, size_t asize){
    size_t size=GET_SIZE(HDRP(bp));
    PUT(HDRP(bp),PACK(size, 1));
    PUT(FTRP(bp),PACK(size, 1));
    
    split_block(bp,asize);

}
```
**split_block**
```c
static void split_block(void *bp, size_t asize){
    size_t size =GET_SIZE(HDRP(bp));
    if((size-asize)>=MINBLOCKSIZE){
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK((size-asize),0));
        PUT(FTRP(bp),PACK((size-asize),0));
        coalesce(bp);    
    }

}
```
**next_fit**
```c
static void *next_fit(size_t asize){
    char* bp;
    for ( bp = prev_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp))
    {
        if (!GET_ALLOC(HDRP(bp)) && GET_SIZE(HDRP(bp)) >= asize)
        {
            prev_listp = bp;
            return bp;
        }
    }

    for ( bp = heap_listp; bp != prev_listp; bp = NEXT_BLKP(bp))
    {
        if (!GET_ALLOC(HDRP(bp)) && GET_SIZE(HDRP(bp)) >= asize)
        {
            prev_listp = bp;
            return bp;
        }
    }
    return NULL;
}
```

这里使用的是隐式链表+next fit，得分：
```text
Results for mm malloc:
trace  valid  util     ops      secs  Kops
 0       yes   91%    5694  0.001710  3329
 1       yes   92%    5848  0.000948  6166
 2       yes   95%    6648  0.002903  2290
 3       yes   97%    5380  0.003700  1454
 4       yes   66%   14400  0.000099146193
 5       yes   91%    4800  0.004307  1114
 6       yes   89%    4800  0.003500  1371
 7       yes   55%   12000  0.014687   817
 8       yes   51%   24000  0.007490  3204
 9       yes   27%   14401  0.048774   295
10       yes   45%   14401  0.001818  7919
Total          73%  112372  0.089937  1249

Perf index = 44 (util) + 40 (thru) = 84/100
```
## 改进：显式链表+first fit
最开始使用的是`first_fit`只有50+，改为`next_fit`之后达到了80+，在搜索的时候几乎是在遍历整个堆段，所以想到使用显示链表的方法来管理空闲chunk。
修改free_chunk结构：
```c
struct chunk{
	int header;			/*header==footer*/
	chunk *fd;			/*prev free chunk*/
	chunk *bk;			/*next free chunk*/
	int footer;
}
```
添加定义：
```c
#define FD(bp)  ((char *)(bp))
#define BK(bp)  ((char *)(bp)+WSIZE)

#define SET_PTR(p,ptr)  (*(unsigned int *)(p) = (unsigned int)(ptr))

#define GET_NEXT(bp)    (*(char **)(BK(bp)))
#define GET_PREV(bp)    (*(char **)(bp)) 

static char* free_listp;	//manage all free chunk
static void insert_freelist(void* bp);	
static void remove_freelist(void* bp);
```
这里的fd，bk与glibc中的malloc是相似的。
**insert_freelist**
```c
static void insert_freelist(void* bp)
{
    if (bp == NULL)
        return;

    if (free_listp == NULL)
    {
        free_listp = bp;
        SET_PTR(FD(bp),NULL);       //at the end of the list fd will be null;
        SET_PTR(BK(bp),NULL);       //at the begin of the list bk will be null;

    }
    else {
        void *old=free_listp;
        free_listp = bp;
        SET_PTR(FD(bp),old);
        SET_PTR(BK(bp),NULL);
        SET_PTR(BK(old),bp);
    }
    return;
}
```

**remove_freelist**
```c
static void remove_freelist(void* bp)
{
    if(GET_NEXT(bp)!=NULL)
    {
        if(GET_PREV(bp)!=NULL)  /* free_listp-->xxx->bp-->xxx */
        {      
            SET_PTR(FD(GET_NEXT(bp)),GET_PREV(bp));
            SET_PTR(BK(GET_PREV(bp)),GET_NEXT(bp));
        }
        else                    /* free_listp-->xxx->bp */
        {
            SET_PTR(FD(GET_NEXT(bp)),NULL);
        }
    }
    else
    {
        if(GET_PREV(bp)!=NULL)  /* free_listp-->bp-->xxx */
        {
            SET_PTR(BK(GET_PREV(bp)),NULL);
            free_listp=GET_PREV(bp);
        }
        else                    /* free_listp-->bp */
        {
            free_listp=NULL;
        }
    }
}
```
**first_fit**
```c
static void *find_fit(size_t asize)
{  
    void *bp=free_listp;
    for(;bp!=NULL;bp=GET_PREV(bp)) {
        if(asize<=GET_SIZE(HDRP(bp)))
            return bp;
    }

    return NULL;
}
```
但是分数没有变化。
```text
Results for mm malloc:
trace  valid  util     ops      secs  Kops
 0       yes   89%    5694  0.000159 35789
 1       yes   92%    5848  0.000106 55326
 2       yes   94%    6648  0.000232 28717
 3       yes   96%    5380  0.000177 30361
 4       yes  100%   14400  0.000095151739
 5       yes   88%    4800  0.000379 12668
 6       yes   85%    4800  0.000507  9471
 7       yes   55%   12000  0.004043  2968
 8       yes   51%   24000  0.002807  8549
 9       yes   26%   14401  0.058122   248
10       yes   34%   14401  0.002460  5854
Total          74%  112372  0.069087  1627

Perf index = 44 (util) + 40 (thru) = 84/100
```
## 改进：分离链表+first fit
依据2的次幂分为16个组：{1}，{2}，{3，4}，{5~8}，…，{1025~2048}，{2049~4096}...
修改宏定义：
```c
#define MAX_FREE_LIST 16

static void* free_listp[MAX_FREE_LIST];
static void insert_freelist(void* bp,size_t size);
```
**first_fit**
```c
static void *first_fit(size_t asize)
{
    int index=free_index(asize);
    void *bp=NULL;
    while(index<MAX_FREE_LIST)
    {
        bp=free_listp[index];
        while((bp!=NULL)&&(asize>GET_SIZE(HDRP(bp))))
        {
            bp = GET_PREV(bp);
        }
        if(bp!=NULL)
            return bp;
        index++;
    }
    
    return NULL;
}
```
**free_index**
```c
static int free_index(size_t size) {
    int index=0;
    while ((index<MAX_FREE_LIST-1))
    {
        if(size>1) {
            size>>=1;
            index++;
        }
        else
            break;
    }
    return index;
}
```
此版得分：
```text
trace  valid  util     ops      secs  Kops
 0       yes   98%    5694  0.000244 23307
 1       yes   97%    5848  0.000362 16168
 2       yes   96%    6648  0.000287 23156
 3       yes   98%    5380  0.000518 10386
 4       yes  100%   14400  0.000306 47105
 5       yes   93%    4800  0.000338 14189
 6       yes   90%    4800  0.000517  9283
 7       yes   55%   12000  0.000311 38598
 8       yes   51%   24000  0.000735 32666
 9       yes   28%   14401  0.058034   248
10       yes   28%   14401  0.002643  5448
Total          76%  112372  0.064295  1748

Perf index = 46 (util) + 40 (thru) = 86/100
```
## 改进：realloc
在之前的版本中，`realloc`都依赖了`malloc`和`free`函数，实现很暴力。在改进中，若当前块的后一个块是free且相加后的大小满足需求就可以进行合并。

```c
void *mm_realloc(void *ptr, size_t size)
{
    void *new_ptr;
    size_t asize;
    if(ptr==NULL){
        new_ptr=mm_malloc(size);
        if (new_ptr == NULL)
            return NULL;
        return new_ptr;
    }
    if(size==0){
        mm_free(ptr);
        return NULL;
    }
    if(size <= DSIZE)
        asize = 2*DSIZE;
    else
        asize = ALIGN(size + DSIZE);
    size_t oldsize=GET_SIZE(HDRP(ptr));
    if(asize<=oldsize){
        place(ptr,asize);
        return ptr;
    }
    else{
        size_t next_alloc=GET_ALLOC(HDRP(NEXT_BLKP(ptr)));
        size_t new_size;
        new_size=GET_SIZE(HDRP(NEXT_BLKP(ptr)))+oldsize;
        if(!next_alloc&&(asize<=new_size)) //next is free
        {
            remove_freelist(NEXT_BLKP(ptr));
            PUT(HDRP(ptr), PACK(new_size, 1));
            PUT(FTRP(ptr), PACK(new_size, 1));
            return ptr;
        }
        else {
            new_ptr=mm_malloc(size);
            if (new_ptr == NULL)
                return NULL;
            memcpy(new_ptr, ptr, size-WSIZE);
            mm_free(ptr);
            return new_ptr;
        }
    }
}
```
这里我认为合并后可以再次细化进行分割，但是分割后分数反而低了（黑人？？？.jpg）

```text
Results for mm malloc:
trace  valid  util     ops      secs  Kops
 0       yes   98%    5694  0.000216 26361
 1       yes   97%    5848  0.000214 27340
 2       yes   96%    6648  0.000308 21556
 3       yes   98%    5380  0.000197 27365
 4       yes  100%   14400  0.000250 57554
 5       yes   93%    4800  0.000344 13970
 6       yes   90%    4800  0.000310 15469
 7       yes   55%   12000  0.000334 35907
 8       yes   51%   24000  0.000761 31521
 9       yes   99%   14401  0.000260 55367
10       yes   57%   14401  0.000234 61464
Total          85%  112372  0.003429 32771

Perf index = 51 (util) + 40 (thru) = 91/100
```
目前分数最高的一版。
