# UCore Lab 0


# 概述

> 在学习一个东西之前，我都喜欢思考，这个东西解决了什么问题？
>
> 所有的技术都不是无故产生的，面向问题的学习能更好的理解它的设计思路。

操作系统是系统软件，在硬件层与应用软件之间。

**为什么需要操作系统？**

为用户提供更加方便的使用计算机的方式。对资源进行有效的管理。

<!--more-->

## 内核特征

- 并发

  计算机系统中有多个正在运行的程序，需要OS的管理和调度。维护每个进程的状态（寄存器值，当前执行的指令等），并在不同进行之间进行切换（切换由内核态完成后，回到用户态）

- 共享

  宏观上，体现各进程“同时”访问微观上，互斥共享。同一时刻仅有一个进程在访问内存。

  > 系统总线只有一条，不允许多进程同时访问。

- 虚拟

  利用多道程序设计技术，让每个进程都觉得计算机是为该进程独占的

- 异步

  - 程序的执行不是一贯到底的，而是走走停停，向前推进的速度不可预知
  - 只要运行环境相同，OS需要保证程序运行的结果是相同的

# Lab 0：实验环境的搭建

可以使用课程提供的完整的VMbox环境，基于Ubuntu 14.04。这个镜像是2015年创建的，所以使用版本较老。

这里我使用Ubuntu 20.04进行，当然如果你可以使用其他的版本（14.04+）。虚拟机的安装略过

## 换源

备份原来的源

```bash
sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
```

打开/etc/apt/sources.list文件

```bash
sudo gedit /etc/apt/sources.list
```

在前面添加如下条目，并保存

```tex
# aliyun
deb http://mirrors.aliyun.com/ubuntu/ focal main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ focal-security main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-security main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ focal-updates main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ focal-proposed main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-proposed main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ focal-backports main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-backports main restricted universe multiverse
```

然后

```bash
sudo apt update
sudo apt upgrade
```

## 工具安装

```bash
sudo apt-get install build-essential git qemu-system vim gdb cgdb make diffutils exuberant-ctags tmux openssh-server cscope meld qgit gitg gcc-multilib gcc-multilib g++-multilib
```

与官方的并不是完全一样，在ubuntu20.04中eclipse-cdt改变了安装方式，vim由vim-gnome改为vim。

这里我又安装了gdb的拓展peda（在ctf中经常用到），pwndbg在后面发现没法使用。

```bash
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
echo "DONE! debug your program with gdb and enjoy"
```

vs code用来写代码

```bash
sudo apt install snapd -y
sudo snap install --classic code
```

## Intel 80386基础知识

### 运行模式

- 实模式

  - 为了兼容早期16位8086

  - 80386加电启动后处于实模式运行状态，在这种状态下软件可访问的物理内存不能超过1MB，且无法发挥Intel 80386以上级别的32位CPU的4GB内存管理能力

- 保护模式

  - 支持内存分页机制，提供了对虚拟内存的良好支持。保护模式下80386支持多任务，还支持优先级机制，不同程序运行在不同的优先级上。优先级一共分0-3 4个级别，操作系统运行在最高的的优先级0上，应用程序则运行在比较低的级别上；配合良好的检查机制后，既可以子啊任务间实现数据的安全共享也可以很好地隔离各个任务。

- SMM模式

- 虚拟8086模式

### 内存架构

地址是访问内存空间的索引

> 一个地址对应一个字节，借用CSAPP的话，你可以将内存看成数组，地址对应了下标。

一般而言，内存地址有两个：一个是CPU通过总线访问物理内存用到的物理地址，一个是我们编写的应用程序所用到的为虚拟地址（也称逻辑地址）。看下面的程序：

```c
int a = 5;
int *addr = &a;
```

指针`addr`保存了变量`a`的地址，这个地址就是虚拟地址。
80386是32位的处理器，即可以寻址的物理内存地址空间为$2^{32}=4$字节。为更好理解面向80386处理器的ucore操作系统，需要用到三个地址空间的概念：物理地址、线性地址和虚拟地址。物理内存地址空间是处理器提交到总线上用于访问计算机系统中的内存和外设的最终地址。一个计算机系统中只有一个物理地址空间。线性地址空间是80386处理器通过段（Segment）机制控制下的形成的地址空间。在操作系统的管理下，每个运行的应用程序有相对独立的一个或多个内存空间段，每个段有各自的起始地址和长度属性，大小不固定，这样可让多个运行的应用程序之间相互隔离，实现对地址空间的保护。

在操作系统完成对80386处理器段机制的初始化和配置（主要是需要操作系统通过特定的指令和操作建立全局描述符表，完成虚拟地址与线性地址的映射关系）后，80386处理器的段管理功能单元负责把虚拟地址转换成线性地址，在没有下面介绍的页机制启动的情况下，这个线性地址就是物理地址。

相对而言，段机制对大量应用程序分散地使用大内存的支持能力较弱。所以Intel公司又加入了页机制，每个页的大小是固定的（一般为4KB），也可完成对内存单元的安全保护，隔离，且可有效支持大量应用程序分散地使用大内存的情况。

在操作系统完成对80386处理器页机制的初始化和配置（主要是需要操作系统通过特定的指令和操作建立页表，完成虚拟地址与线性地址的映射关系）后，应用程序看到的虚拟地址先被处理器中的段管理功能单元转换为线性地址，然后再通过80386处理器中的页管理功能单元把线性地址转换成物理地址。

> 页机制和段机制有一定程度的功能重复，但Intel公司为了向下兼容等目标，使得这两者一直共存。

上述三种地址的关系如下：

-   分段机制启动、分页机制未启动：逻辑地址--->**段机制处理**--->线性地址=物理地址
    
-   分段机制和分页机制都启动：逻辑地址--->**段机制处理**--->线性地址--->**页机制处理**--->物理地址

### 寄存器
如果对汇编比较熟悉可以直接跳过
80386的寄存器可以分为8组：通用寄存器，段寄存器，指令指针寄存器，标志寄存器，系统地址寄存器，控制寄存器，调试寄存器，测试寄存器，它们的宽度都是32位。一般程序员看到的寄存器包括通用寄存器，段寄存器，指令指针寄存器，标志寄存器。

~~放出我最喜欢的图~~（图中展示了64位寄存器到8位寄存器的结构，更高级的CPU还有媒体寄存器）
![寄存器](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210828010146.png)
```text

    EAX：累加器
    EBX：基址寄存器
    ECX：计数器
    EDX：数据寄存器
    ESI：源地址指针寄存器
    EDI：目的地址指针寄存器
    EBP：基址指针寄存器
    ESP：堆栈指针寄存器
```
Segment Register(段寄存器，也称 Segment Selector，段选择符，段选择子)：除了8086的4个段外(CS,DS,ES,SS)，80386还增加了两个段FS，GS,这些段寄存器都是16位的，用于不同属性内存段的寻址，它们的含义如下：

```text
    CS：代码段(Code Segment)
    DS：数据段(Data Segment)
    ES：附加数据段(Extra Segment)
    SS：堆栈段(Stack Segment)
    FS：附加段
    GS 附加段
```
Instruction Pointer(指令指针寄存器，PC)：EIP的低16位就是8086的IP，它存储的是下一条要执行指令的内存地址，在分段地址转换中，表示指令的段内偏移地址。
Flag Register(标志寄存器)：EFLAGS,和8086的16位标志寄存器相比，增加了4个控制位

```text
    CF(Carry Flag)：进位标志位；
    PF(Parity Flag)：奇偶标志位；
    AF(Assistant Flag)：辅助进位标志位；
    ZF(Zero Flag)：零标志位；
    SF(Singal Flag)：符号标志位；
    IF(Interrupt Flag)：中断允许标志位,由CLI，STI两条指令来控制；设置IF位使CPU可识别外部（可屏蔽）中断请求，复位IF位则禁止中断，IF位对不可屏蔽外部中断和故障中断的识别没有任何作用；
    DF(Direction Flag)：向量标志位，由CLD，STD两条指令来控制；
    OF(Overflow Flag)：溢出标志位；
    IOPL(I/O Privilege Level)：I/O特权级字段，它的宽度为2位,它指定了I/O指令的特权级。如果当前的特权级别在数值上小于或等于IOPL，那么I/O指令可执行。否则，将发生一个保护性故障中断；
    NT(Nested Task)：控制中断返回指令IRET，它宽度为1位。若NT=0，则用堆栈中保存的值恢复EFLAGS，CS和EIP从而实现中断返回；若NT=1，则通过任务切换实现中断返回。在ucore中，设置NT为0。
```
### 编程技巧
在结构体中定义函数指针和数据形成虚表。
code: lab2/kern/mm/pmm.h
```c
// pmm_manager is a physical memory management class. A special pmm manager - XXX_pmm_manager
// only needs to implement the methods in pmm_manager class, then XXX_pmm_manager can be used
// by ucore to manage the total physical memory space.
struct pmm_manager {
    // XXX_pmm_manager's name
    const char *name;  
    // initialize internal description&management data structure
    // (free block list, number of free block) of XXX_pmm_manager 
    void (*init)(void); 
    // setup description&management data structcure according to
    // the initial free physical memory space 
    void (*init_memmap)(struct Page *base, size_t n); 
    // allocate >=n pages, depend on the allocation algorithm 
    struct Page *(*alloc_pages)(size_t n);  
    // free >=n pages with "base" addr of Page descriptor structures(memlayout.h)
    void (*free_pages)(struct Page *base, size_t n);   
    // return the number of free pages 
    size_t (*nr_free_pages)(void);                     
    // check the correctness of XXX_pmm_manager
    void (*check)(void);                               
};
```
对于双向链表的指针域使用统一的结构定义。
```c
struct list_entry {
    struct list_entry *prev, *next;
};

struct Var {
    type var_1;          
    ……
    list_entry_t link;         
};
```
使用指针+偏移的方式访问结构体与变量。
```c
// convert list entry to page
#define le2page(le, member)                 \
to_struct((le), struct Page, member)


/* Return the offset of 'member' relative to the beginning of a struct type */
#define offsetof(type, member)                                      \
((size_t)(&((type *)0)->member))

/* *
 * to_struct - get the struct from a ptr
 * @ptr:    a struct pointer of member
 * @type:   the type of the struct this is embedded in
 * @member: the name of the member within the struct
 * */
#define to_struct(ptr, type, member)                               \
((type *)((char *)(ptr) - offsetof(type, member)))
```

