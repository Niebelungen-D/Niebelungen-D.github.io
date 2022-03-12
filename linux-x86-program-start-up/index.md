# Linux X86 Program Start Up




# 程序开始

一个程序真正的入口是_start函数。

start函数有三个参数：

- `agrc`——表示有多少个命令行参数，第一个就是执行程序名，所以argc最少为1。
- `argv`是具体的参数。字符串数组
  - argv[0]为空串("") 。
    argv[1] 为在DOS命令行中执行程序名后的第一个字符串;
    argv[2] 为执行程序名后的第二个字符串;
    ……
    argv[argc]为NULL。
- `envp`是系统的环境变量，字符串数组，envp[]的每一个元素都包含在ENVVAR=value形式的字符串。

我们使用一个简单的程序simple.c看一下这个过程：

```c
int main()
{
    return 0;
}
```

编译后使用

```shell
objdump -f simple
```

```shell
giantbranch@ubuntu:~/Desktop$ objdump -f simple
simple:     file format elf64-x86-64
architecture: i386:x86-64, flags 0x00000112:
EXEC_P, HAS_SYMS, D_PAGED
start address 0x00000000004003e0
```

这里显示的开始地址就是_start函数的地址，我们进行反编译看一看：

```shell
objdump -d simple
```

```assembly
Disassembly of section .text:

00000000004003e0 <_start>:
  4003e0:	31 ed                	xor    %ebp,%ebp
  4003e2:	49 89 d1             	mov    %rdx,%r9
  4003e5:	5e                   	pop    %rsi
  4003e6:	48 89 e2             	mov    %rsp,%rdx
  4003e9:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  4003ed:	50                   	push   %rax
  4003ee:	54                   	push   %rsp
  4003ef:	49 c7 c0 60 05 40 00 	mov    $0x400560,%r8
  4003f6:	48 c7 c1 f0 04 40 00 	mov    $0x4004f0,%rcx
  4003fd:	48 c7 c7 d6 04 40 00 	mov    $0x4004d6,%rdi
  400404:	e8 b7 ff ff ff       	callq  4003c0 <__libc_start_main@plt>
  400409:	f4                   	hlt    
  40040a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
```

可以看到_start函数向寄存器中传递了参数：

- 0x400560：__libc_csu_fini的地址
- 0x4004f0：__libc_csu_init的地址
- 0x4004d6：main的地址

然后调用了一个libc函数__libc_start_main：

```c
extern int BP_SYM (__libc_start_main) (int (*main) (int, char **, char **),
		int argc,
		char *__unbounded *__unbounded ubp_av,
		void (*init) (void),
		void (*fini) (void),
		void (*rtld_fini) (void),
		void *__unbounded stack_end)
__attribute__ ((noreturn));
```

__libc_start_main函数做了什么呢？

1. 处理关于setuid、setgid程序的安全问题
2. 启动线程
3. 把`fini`函数和`rtld_fini`函数作为参数传递给`at_exit`调用，使它们在`at_exit`里被调用，从而完成用户程序和加载器的调用结束之后的清理工作
4. 调用其`init`参数
5. 调用`main`函数，并把`argc`和`argv`参数、环境变量传递给它
6. 调用`exit`函数，并将main函数的返回值传递给它

`init`参数就是__libc_csu_init函数：

```assembly
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0                 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

__libc_csu_init函数会调用`get_pc_truck`。它是给位置无关码使用的。设置它们可以让位置无关码正常工作。为了让它们工作，基址寄存器（%ebp）需要知道`GLOBAL_OFFSET_TABLE`（GOT）。该函数的主要目的其实是获取变量对应的GOT，以通过它获取变量真正的值。

之后会进入一个循环中，为main设置环境，和寄存器参数。下面的函数都在循环中执行

然后，我们来看`gmon_start`函数。如果它是空的，我们跳过它，不调用它。否则，调用它来设置profiling。该函数调用一个例程开始profiling，并且调用`at_exit`去调用另一个程序运行,并且在运行结束的时候生成gmon.out。

接下来`frame_dummy`函数会被调用。其目的是调用`__register_frame_info`函数，但是，调用`frame_dummy`是为了给上述函数设置参数。

之后是`__do_global_ctors_aux`

。。。。

最后跳出循环，回到\__libc_start_main，__libc_start_main去调用我们的mian。

# 结束

进程正常结束有两种情况：

1. `main`正常返回，由`__libc_start_main`来调用`exit`函数。
2. 程序中直接使用`exit`退出。

`__libc_csu_fini`函数

```assembly
.text:0000000000402960 __libc_csu_fini proc near               ; DATA XREF: start+Fo
.text:0000000000402960 ; __unwind {
.text:0000000000402960                 push    rbp
.text:0000000000402961                 lea     rax, unk_4B4100
.text:0000000000402968                 lea     rbp, _fini_array_0
.text:000000000040296F                 push    rbx
.text:0000000000402970                 sub     rax, rbp
.text:0000000000402973                 sub     rsp, 8
.text:0000000000402977                 sar     rax, 3
.text:000000000040297B                 jz      short loc_402996
.text:000000000040297D                 lea     rbx, [rax-1]
.text:0000000000402981                 nop     dword ptr [rax+00000000h]
.text:0000000000402988
.text:0000000000402988 loc_402988:                             ; CODE XREF: __libc_csu_fini+34j
.text:0000000000402988                 call    qword ptr [rbp+rbx*8+0]
.text:000000000040298C                 sub     rbx, 1
.text:0000000000402990                 cmp     rbx, 0FFFFFFFFFFFFFFFFh
.text:0000000000402994                 jnz     short loc_402988
.text:0000000000402996
.text:0000000000402996 loc_402996:                             ; CODE XREF: __libc_csu_fini+1Bj
.text:0000000000402996                 add     rsp, 8
.text:000000000040299A                 pop     rbx
.text:000000000040299B                 pop     rbp
.text:000000000040299C                 jmp     sub_48E32C
.text:000000000040299C ; } // starts at 402960
.text:000000000040299C __libc_csu_fini endp
```

在.text:0000000000402988这个地方有一个call指令,结合前面的代码可以知道rbp保存的是fini_array的值,所以这里会调用fini_array中的函数.所以只要修改了fini_array的数值,我们就可以劫持eip.看一下fini_array的代码:

```
.fini_array:``00000000004B40F0` `_fini_array   segment para public ``'DATA'` `use64
.fini_array:``00000000004B40F0`         `assume cs:_fini_array
.fini_array:``00000000004B40F0`         `;org ``4B40F0h
.fini_array:``00000000004B40F0` `_fini_array_0  dq offset sub_401B00  ; DATA XREF: .text:``000000000040291Co
.fini_array:``00000000004B40F0`                     `; __libc_csu_fini``+``8o
.fini_array:``00000000004B40F8`         `dq offset sub_401580
.fini_array:``00000000004B40F8` `_fini_array   ends
```

这里保存了两个函数指针,分别是fini_array[0]和fini_array[1],观察libc_csu_fini中的汇编代码我们可以得知这俩函数指针是反向执行的,先执行fini_array[1],再执行fini_array[0].如果我们将fini_array[0]覆盖为libc_csu_fini的地址,再将fini_array[1]覆盖为任意一个地址A,那么程序就会循环执行A地址的代码,直到fini_array[0]覆盖为其他值. 

其次,在.text:0000000000402968可以修改rbp为fini_array的首地址,配合leave;ret可以把栈迁移到fini_array.

参考：[__libc_start_main](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)


