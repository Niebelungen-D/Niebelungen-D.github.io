# Heap Unlink


# unlink

<!-- more -->

```c
/* Take a chunk off a bin list */
// unlink p
#define unlink(AV, P, BK, FD) {                                            
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
      malloc_printerr ("corrupted size vs. prev_size");               
    FD = P->fd;                                                                      
    BK = P->bk;                                                                      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {                                                                      
        FD->bk = BK;                                                              
        BK->fd = FD;                                                              
        if (!in_smallbin_range (chunksize_nomask (P))                              
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {                      
            if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    
              malloc_printerr (check_action,                                      
                               "corrupted double-linked list (not small)",    
                               P, AV);                                              
            if (FD->fd_nextsize == NULL) {                                      
                if (P->fd_nextsize == P)                                      
                  FD->fd_nextsize = FD->bk_nextsize = FD;                      
                else {                                                              
                    FD->fd_nextsize = P->fd_nextsize;                              
                    FD->bk_nextsize = P->bk_nextsize;                              
                    P->fd_nextsize->bk_nextsize = FD;                              
                    P->bk_nextsize->fd_nextsize = FD;                              
                  }                                                              
              } else {                                                              
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;                      
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;                      
              }                                                                      
          }                                                                      
      }                                                                              
}
```

unlink适用于small bin，且在最新的libc2.27及以上中，加入了新的机制，该攻击不再那么适用。但是对于该技巧的学习，有助于更好的理解堆操作。

## 旧的unlink

在旧的unlink中，并没有size和双向链表的检查。那么unlink操作就相当于执行了以下操作：

```c
FD = P -> fd;
BK = P -> bk;
FD -> bk = BK;
BK -> fd = FD;
```

假设我们在`P -> fd`中写入目标地址：`dest_addr - 0x18`，在`P -> bk`中写入修改的地址（例如某函数的got表地址）`expect_addr`。以上函数相当于：

```c
FD = dest_addr - 0x18;
BK = expect_addr;
*(dest_addr - 0x18 + 0x18) = expect_addr
*(expect_addr + 0x10) = dest_addr - 0x18
```

我们将`expect_addr`写入了`dest_addr`的位置。通过这一点我们可以向任意的位置写任意的值。

## 新的unlink

添加了以下检查机制：

```c
···
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
      malloc_printerr ("corrupted size vs. prev_size");               
    FD = P->fd;                                                                      
    BK = P->bk;                                                                      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {                                                                      
        FD->bk = BK;                                                              
        BK->fd = FD;  
···
```

它要求`FD->bk = BK->fd = P`，即`*(P -> fd+0x18)==*(P -> bk+0x10)==P`，所以`*(P -> fd)=P-0x18`，`*(P -> bk)=P-0x10`。

最终实现：

```c
*P=P-0x18
```

此时，再编辑P所指chunk为某got表，就可以对got进行编辑。

应用的场景，存在一个管理堆指针的数组，这个数组我们无法直接操作，但是其P的附近，所以我们可以通过unlink改变其中的值，再将P指向我们想写入的地址（got表），实现任意地址写。

另外，因为我们要修改chunk header,所以需要想办法溢出或UAF。


