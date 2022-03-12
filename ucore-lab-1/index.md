# UCore Lab 1


# 启动

<!--more-->

![](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210606141617.png)

在CPU加电后，寄存器CS:IP被强制初始化为`0xf000:0xfff0`，此时CPU处于实模式，有20位地址线可用，可以访问1MB的地址空间，`PC = 16*CS + IP`。这时的地址也是真实的物理地址。

各个段寄存器和IP都是16位的。

## BIOS

在这个位置是一个`jmp far f000：e05b`指令，它会让CPU跳转到BIOS程序的位置。接下来，BIOS就开始运行

BIOS实际上是被固化在计算机ROM（只读存储器）芯片上的一个特殊的软件，为上层软件提供最底层的、最直接的硬件控制与支持。更形象地说，BIOS就是PC计算机硬件与上层软件程序之间的一个"桥梁"，负责访问和控制硬件。它做了这些工作

- 硬件自检POST
  - 检测系统中内存和显卡等关键部件的存在和工作状态
  - 查找并执行显卡等接口卡BIOS，进行设备初始化
- 执行系统BIOS，进行系统检测
  - 检测和配置系统中安装的即插即用设备
  - 检测并初始化外设、在`0x000-0x3ff`建立数据结构，中断向量表IVT并填写中断例程。
- 更新CMOS中的扩展系统配置数据ESCD
- 按照指定启动顺序从软盘、硬盘和光驱启动  
- 加载第一个扇区，MBR，将其512字节加载到内存中
- 跳转到0x7c00的第一条指令开始执行

## MBR（主引导记录）

MBR（主引导记录），它固定在0盘0道1扇区。BIOS结束后，没有直接将CPU的控制权给操作系统，而是给了MBR。MBR知道操作系统被加载到了哪个分区，也会有多个操作系统需要你去选择加载哪一个。
MBR共512字节（一个扇区大小）包含

 - 启动代码：446字节
    - 检查分许表的正确性
    - 加载并跳转到磁盘上的引导程序bootloder
    - 当安装了多个操作系统时，需要选择加载哪个系统，MBR会跳转到对应的分区执行bootloader
 - 硬盘分区表：64字节
    - 描述分区状态和位置
    - 每个分区描述信息占据16字节
 - 结束标志(魔数)：0xaa55
    - 主引导记录的有效标志

## 加载程序（bootloader）

- 切换到保护模式，启用分段机制
- 从文件系统中读取启动配置信息（与操作系统有关）
  - 各分区都有超级块，一般位于本分区的第2个扇区。超级块里面记录了此分区的信息，其中就有文件系统的魔数，一种文件系统对应一个魔数，通过比较即可得知文件系统类型。
  - 对于uCore来说就是ELF格式
- 启动并显示菜单，可选系统内核列表和参数
- 依据选择的配置加载内核

之后，CPU就交给操作系统内核了。下面我们进一步看看bootloader的过程

## 保护模式的开启

在进入保护模式前，要建立各段的映射关系，从而开启段机制。有关其内存管理的细节在lab2中。

### 建立段映射

各段寄存器指向了不同段的基址，而在每个段的开始有段描述符。

##### 段描述符

- 在分段存储管理机制的保护模式下，每个段由如下三个参数进行定义：段基地址(Base Address)、段界限(Limit)和段属性(Attributes)
  - 段基地址：规定线性地址空间中段的起始地址。任何一个段都可以从32位线性地址空间中的任何一个字节开始，不用像实模式下规定边界必须被16整除。
  - 段界限：规定段的大小。可以以字节为单位或以4K字节为单位。
  - 段属性：确定段的各种性质。
    - 段属性中的粒度位（Granularity），用符号G标记。G=0表示段界限以字节位位单位，20位的界限可表示的范围是1字节至1M字节，增量为1字节；G=1表示段界限以4K字节为单位，于是20位的界限可表示的范围是4K字节至4G字节，增量为4K字节。
    - 类型（TYPE）：用于区别不同类型的描述符。可表示所描述的段是代码段还是数据段，所描述的段是否可读/写/执行，段的扩展方向等。其4bit从左到右分别是
      - 执行位：置1时表示可执行，置0时表示不可执行；
      - 一致位：置1时表示一致码段，置0时表示非一致码段；
      - 读写位：置1时表示可读可写，置0时表示只读；
      - 访问位：置1时表示已访问，置0时表示未访问。
    - 描述符特权级（Descriptor Privilege Level）（DPL）：用来实现保护机制。
    - 段存在位（Segment-Present bit）：如果这一位为0，则此描述符为非法的，不能被用来实现地址转换。如果一个非法描述符被加载进一个段寄存器，处理器会立即产生异常。操作系统可以任意的使用被标识为可用（AVAILABLE）的位。
    - 已访问位（Accessed bit）：当处理器访问该段（当一个指向该段描述符的选择子被加载进一个段寄存器）时，将自动设置访问位。操作系统可清除该位。

#### 段选择子

在一个段寄存器中，会保存一块区域叫段选择子。

- 线性地址部分的选择子是用来选择哪个描述符表和在该表中索引哪个描述符的。选择子可以做为指针变量的一部分，从而对应用程序员是可见的，但是一般是由连接加载器来设置的。
- 段选择子结构
  - 索引（Index）：高13位，在描述符表中从8192个描述符中选择一个描述符。处理器自动将这个索引值乘以8（描述符的长度），再加上描述符表的基址来索引描述符表，从而选出一个合适的描述符。
  - 表指示位（Table Indicator，TI）：1位，选择应该访问哪一个描述符表。0代表应该访问全局描述符表（GDT），1代表应该访问局部描述符表（LDT）。
  - 请求特权级（Requested Privilege Level，RPL）：低两位，保护机制。

由段选择子得到的段描述符，再得到段的基址，最后加上偏移就得到了一个线性地址。在未开启分页机制时，线性地址即为物理地址。

#### 全局描述符表（GDT）

我们需要一个大数组来管理那么多的段，这个数组我们称为全局描述符表（GDT），它保存了各段的段描述符，简称段表。

全局描述符表的起始地址保存在全局描述符表寄存器GDTR中。GDTR长48位，其中高32位为基地址，低16位为段界限。

### 保护模式使能

建立映射后，使能保护模式。通过一个特定的寄存器，**系统性寄存器CRT**，将其bit 0置1，则代表CPU进入保护模式。段机制，是在保护模式下自动使能的。

## 加载ELF格式的uCore kernel

这里不是文件系统，因为我们还没有为kernel进行编写。

#### ELF文件格式概述

ELF(Executable and linking format)文件格式是Linux系统下的一种常用目标文件(object file)格式，有三种主要类型:

- 用于执行的可执行文件(executable file)，用于提供程序的进程映像，加载的内存执行。 这也是本实验的OS文件类型。
- 用于连接的可重定位文件(relocatable file)，可与其它目标文件一起创建可执行文件和共享目标文件。
- 共享目标文件(shared object file)，连接器可将它与其它可重定位文件和共享目标文件连接成其它的目标文件，动态连接器又可将它与可执行文件和其它共享目标文件结合起来创建一个进程映像。

这里只分析与本实验相关的ELF可执行文件类型。ELF header在文件开始处描述了整个文件的组织。ELF的文件头包含整个执行文件的控制结构，其定义在elf.h中：

```c
struct elfhdr {
  uint magic;  			// must equal ELF_MAGIC
  uchar elf[12];
  ushort type;
  ushort machine;
  uint version;
  uint entry;  			// 程序入口的虚拟地址
  uint phoff;  			// program header 表的位置偏移
  uint shoff;
  uint flags;
  ushort ehsize;
  ushort phentsize;
  ushort phnum; 		//program header表中的入口数目
  ushort shentsize;
  ushort shnum;
  ushort shstrndx;
};
```

`program header`描述与程序执行直接相关的目标文件结构信息，用来在文件中定位各个段的映像，同时包含其他一些用来为程序创建进程映像所必需的信息。

可执行文件的程序头部是一个`program header`结构的数组， 每个结构描述了一个段或者系统准备程序执行所必需的其它信息。目标文件的 “段” 包含一个或者多个 “节区”（section） ，也就是“段内容（Segment Contents）” 。程序头部仅对于可执行文件和共享目标文件有意义。可执行目标文件在ELF头部的`e_phentsize`和`e_phnum`成员中给出其自身程序头部的大小。程序头部的数据结构如下表所示：

```c
struct proghdr {
  uint type;   			// 段类型
  uint offset;  		// 段相对文件头的偏移值
  uint va;     			// 段的第一个字节将被放到内存中的虚拟地址
  uint pa;
  uint filesz;
  uint memsz;  			// 段在内存映像中占用的字节数
  uint flags;
  uint align;
};
```

根据`elfhdr`和`proghdr`的结构描述，bootloader就可以完成对ELF格式的ucore操作系统的加载过程（参见boot/bootmain.c中的bootmain函数）。

# 中断、异常和系统调用

**为什么需要中断、异常和系统调用？**
- 在计算机运行中，内核是被信任的第三方
- 只有内核可以执行特权指令
- 方便应用程序

中断和异常希望解决，外设连接计算机时的加载问题和应对程序的意外行为。如，当计算机希望你按回车键时，按下键盘的时间是不确定的，计算机不能永远等待。
系统调用希望解决用户使用内核服务时，不会对内核造成威胁的问题。

![image-20210606140809300](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210606140816.png)

## 中断

### BIOS中断、DOS中断、Linux中断的区别

- BIOS和DOS都存在于实模式下，由它们建立的中断调用都是建立在中断向量表（Interrupt Vector Table，IVT）中的，都是通过软中断指令 int 中断号来调用。
- BIOS 中断调用的主要功能是提供了硬件访问的方法，该方法使对硬件的操作变得简单易行。
- DOS 是运行在实模式下的，故其建立的中断调用也建立在中断向量表中，只不过其中断向量号和BIOS的不能冲突。
- Linux 内核是在进入保护模式后才建立中断例程的，不过在保护模式下，中断向量表已经不存在了，取而代之的是中断描述符表（Interrupt Descriptor Table，IDT）。Linux 的系统调用和DOS中断调用类似，不过Linux是通过`int 0x80`指令进入一个中断程序后再根据eax寄存器的值来调用不同的子功能函数的。

### 中断描述符表

- 中断描述符表（Interrupt Descriptor Table, IDT）把每个中断或异常编号和一个指向中断服务例程的描述符联系起来。同GDT一样，IDT是一个8字节的描述符数组，但IDT的第一项可以包含一个描述符。
- IDT可以位于内存的任意位置，CPU通过IDT寄存器（IDTR）的内容来寻址IDT的起始地址。

###  IDT gate descriptors

- 中断/异常应该使用`Interrupt Gate`或`Trap Gate`。其中的唯一区别就是：当调用`Interrupt Gate`时，Interrupt会被CPU自动禁止；而调用`Trap Gate`时，CPU则不会去禁止或打开中断，而是保留原样。

  > 这其中的原理是当CPU跳转至`Interrupt Gate`时，其eflag上的IF位会被清除。而`Trap Gate`则不改变。

- IDT中包含了3种类型的Descriptor

  - Task-gate descriptor
  - Interrupt-gate descriptor （中断方式用到）
  - Trap-gate descriptor（系统调用用到）

### 中断的处理流程

- 产生中断后，会通过其中断号，查找其ISR在IDT的哪一项。
- 找到响应的`Interrupt Gate`或`Trap Gate`，取出段选择子
- 根据段选择子查找GDT，得到基地址
- 基地址+偏移得到中断服务例程的地址。

### 不同特权级的中断切换对堆栈的影响

堆栈的不同特权级记录在段描述符中。如果低两位为0，则运行为内核态，若为3，则运行在用户态。

在用户态产生的中断会进入内核态进行处理，而在内核态产生的中断还是在内核态。这是两种不同的处理方式，因为其中产生了特权级的变化。

#### 内核态中断

- 栈没有变换

- 如果产生的是异常，压入Error code
- 压入cs和eip，即压入pc值
- 压入标志寄存器的值
- 通过`iret`返回，会弹出`EFLAGS`和SS/EIP（根据是否改变特权级）

#### 用户态中断

- 切换到内核堆栈

- 在内核中断的基础上额外压入用户栈的ss和esp，保存用户态的栈信息
- 通过`ret`或`retf`返回，仅弹出EIP，`retf`弹出CS和EIP

## 异常

一般源于程序的错误执行，或非法访问。

异常处理的例程也多数只会中止程序的执行。

## 系统调用

系统调用也是特殊的中断，通过`Trap Gate`进入，所以通过系统调用进入内核态也称为陷入内核。

**一个例子**：在调用`printf`时，会触发系统调用`write`。

- 操作系统的服务的编程接口
- 通常由高级语言编写（C/C++）
- 通常通过更高层次的API封装而不是直接调用

### 实现

- 每个系统调用对应一个系统调用号
  - 系统调用接口根据系统调用号来维护表的索引
- 系统调用接口调用内核态中的系统调用功能实现，并返回系统调用的状态和结果
- 用户不需要知道，系统调用的实现，只需设置参数获取返回结果。

### 系统调用与函数调用

- 系统调用：使用`int`和`iret`，有堆栈切换和特权级的切换（内核堆栈和用户堆栈不同）
- 函数调用：使用`call`和`ret`，没有堆栈和特权级的切换

### 系统调用开销：

- 超过函数调用
- 引导机制，用户到内核
- 建立内核堆栈
- 验证参数
- 内核态映射到用户态的地址空间，更新页面映射权限
- 内核独立地址空间，TLB变化

# 特权级

特权级共分为四档，分别为0-3，其中`Kernel`为第0特权级（ring 0），用户程序为第3特权级（ring 3），系统程序分别为第1和第2特权级。

特权级的区别

- 一些指令（例如特权指令`lgdt`）只能运行在ring 0下。
- CPU在如下时刻会检查特权级
  - 访问数据段
  - 访问页
  - 进入中断服务例程（ISRs）
  - …
- 如果检查失败，则会产生**保护异常（General Protection Fault）**

## TSS简介

TSS，即 Task State Segment，意为任务状态段，TSS 是一种数据结构，它用于存储任务的环境。TSS 是每个任务都有的结构，它用于一个任务的标识，相当于任务的身份证，程序拥有此结构才能运行，这是处理器硬件上用于任务管理的系统结构，处理器能够识别其中每一个字段。

![](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210616224957.png)

其中包含了三个栈指针，分别为ring0、ring1、ring2的特权栈。当低特权级向高特权级转换的时候，才会用到这些栈指针进行栈的切换。切换完成后，低特权级的栈指针会被保存在切换后的栈中，通过`retf`或`iret`返回。并不是每个任务都有三个栈指针，因为这些栈指针只有低特权级向高特权级转移时才会用到，所以对于本身就处在ring2的程序是没有ring2的栈指针的，其他同理。切换栈的操作从开始中断的那一瞬间就已完成。

TSS 是硬件支持的系统数据结构，它和GDT 等一样，由软件填写其内容，由硬件使用。GDT 也要加载到寄存器 GDTR 中才能被处理器找到，TSS也是一样，它是由 TR（Task Register）寄存器加载的，每次处理器执行不同任务时，将TR寄存器加载不同任务的TSS就成了。

Code:mmu.h

```c
/* task state segment format (as described by the Pentium architecture book) */
struct taskstate {
    uint32_t ts_link;        // old ts selector
    uintptr_t ts_esp0;        // stack pointers and segment selectors
    uint16_t ts_ss0;        // after an increase in privilege level
    uint16_t ts_padding1;
    uintptr_t ts_esp1;
    uint16_t ts_ss1;
    uint16_t ts_padding2;
    uintptr_t ts_esp2;
    uint16_t ts_ss2;
    uint16_t ts_padding3;
    uintptr_t ts_cr3;        // page directory base
    uintptr_t ts_eip;        // saved state from last task switch
    uint32_t ts_eflags;
    uint32_t ts_eax;        // more saved state (registers)
    uint32_t ts_ecx;
    uint32_t ts_edx;
    uint32_t ts_ebx;
    uintptr_t ts_esp;
    uintptr_t ts_ebp;
    uint32_t ts_esi;
    uint32_t ts_edi;
    uint16_t ts_es;            // even more saved state (segment selectors)
    uint16_t ts_padding4;
    uint16_t ts_cs;
    uint16_t ts_padding5;
    uint16_t ts_ss;
    uint16_t ts_padding6;
    uint16_t ts_ds;
    uint16_t ts_padding7;
    uint16_t ts_fs;
    uint16_t ts_padding8;
    uint16_t ts_gs;
    uint16_t ts_padding9;
    uint16_t ts_ldt;
    uint16_t ts_padding10;
    uint16_t ts_t;            // trap on task switch
    uint16_t ts_iomb;        // i/o map base address
};
```

## DPL、RPL、CPL、IOPL

首先要明确一点，在计算机中具备“能动性”的只有计算机指令，只有指令才具备访问、请求其他资源的能力，指令便是资源的请求者。指令“请求”、“访问”其他资源的能力等级便称之为请求特 权级，指令存放在代码段中，所以，就用代码段寄存器 CS 中选择子的 RPL 位表示代码请求别人资源能力的等级。

- DPL，即 Descriptor Privilege Level，描述符特权级，它存在于段描述符中。标识了访问该段的门槛。
- CPL，Current Privilege Level，它表示处理器正在执行的代码的特权级别。它与当前段的DPL是相同的。
- RPL，请求特权级，来自发出请求的CS.RPL。
- IOPL，该位存在于`eflags`字段中。指当前运行任务的I/O特权级(I/O privilege level)，正在运行任务的当前特权级(CPL)必须小于或等于I/O特权级才能允许访问I/O地址空间。这个域只能在CPL为0时才能通过POPF以及IRET指令修改。

对于受访者为数据段（段描述符中 type 字段中未有X可执行属性）来说： 

只有访问者的权限大于等于该 DPL 表示的最低权限才能够继续访问，否则连这个门槛都迈不过去。比如，DPL 为 1 的段描述符，只有特权级为 0、1 的访问者才有资格访问它所代表的资源，特权为 2、3 的访问者会被 CPU 拒之门外。 

对于受访者为代码段（段描述符中 type 字段中含有X可执行属性）来说：

只有访问者的权限等于该 DPL 表示的最低权限才能够继续访问，即只能平级访问。任何权限大于或小于它的访问者都将被 CPU 拒之门外。这是为什么呢？自问自答之前先明确一个概念，对于受访者为代码段一这说法，实际上是指处理器从当前运行的代码段上转移到受访者这个目标代码段上去执行，并不是 说把该目标代码段当数据一样访问，在真实物理机器上，代码段通常情况下是不被当成数据来处理的，但确实可以这么做（话说虚拟机中会把代码当成数据来处理）。

对于数据段和代码段的要求不同，在执行代码时，高特权级的程序几乎不会主动降低自己的特权级，中断的返回除外。

##  trapFrame

- `trapframe`结构是进入中断门所必须的结构，其结构如下

  ```c
  COPYstruct trapframe {
      // tf_regs保存了基本寄存器的值，包括eax,ebx,esi,edi寄存器等等
      struct pushregs tf_regs;
      uint16_t tf_gs;
      uint16_t tf_padding0;
      uint16_t tf_fs;
      uint16_t tf_padding1;
      uint16_t tf_es;
      uint16_t tf_padding2;
      uint16_t tf_ds;
      uint16_t tf_padding3;
      uint32_t tf_trapno;
      // 以下这些信息会被CPU硬件自动压入切换后的栈。包括下面切换特权级所使用的esp、ss等数据
      uint32_t tf_err;
      uintptr_t tf_eip;
      uint16_t tf_cs;
      uint16_t tf_padding4;
      uint32_t tf_eflags;
      // 以下这些信息会在切换特权级时被使用
      uintptr_t tf_esp;
      uint16_t tf_ss;
      uint16_t tf_padding5;
  } __attribute__((packed));
  ```

## 中断处理例程的入口代码

- 中断处理例程的入口代码用于保存上下文并构建一个`trapframe`，其源代码如下：

  ```c
  COPY  #include <memlayout.h>
  
  # vectors.S sends all traps here.
  .text
  .globl __alltraps
  __alltraps:
      # push registers to build a trap frame
      # therefore make the stack look like a struct trapframe
      pushl %ds
      pushl %es
      pushl %fs
      pushl %gs
      pushal
  
      # load GD_KDATA into %ds and %es to set up data segments for kernel
      movl $GD_KDATA, %eax
      movw %ax, %ds
      movw %ax, %es
  
      # push %esp to pass a pointer to the trapframe as an argument to trap()
      pushl %esp
      # call trap(tf), where tf=%esp
      call trap
      # pop the pushed stack pointer
      popl %esp
  
      # return falls through to trapret...
  .globl __trapret
  __trapret:
      # restore registers from stack
      popal
  
      # restore %ds, %es, %fs and %gs
      popl %gs
      popl %fs
      popl %es
      popl %ds
  
      # get rid of the trap number and error code
      addl $0x8, %esp
      iret
  ```

## 切换特权级的过程

### 特权级提升

当通过陷入门**从ring3切换至ring0（特权提升）** 时

- 在陷入的一瞬间，CPU会因为特权级的改变，索引TSS，切换`ss`和`esp`为内核栈，并**按顺序自动**压入`user_ss`、`user_esp`、`user_eflags`、`user_cs`、`old_eip`以及`err`。

  > 需要注意的是，CPU先切换到内核栈，此时的`esp`与`ss`不再指向用户栈。但此时CPU却可以再将用户栈地址存入内核栈。这种操作可能是依赖硬件来完成的。

  > 如果没有err，则CPU会自动压入0。

- 之后CPU会在中断处理例程入口处，先将剩余的段寄存器以及所有的通用寄存器压栈，构成一个`trapframe`。然后将该`trapframe`传入给真正的中断处理例程并执行。

- 该处理例程会判断传入的中断数(`trapno`)并执行特定的代码。在**提升特权级的代码**中，程序会处理传入的`trapframe`信息中的`CS、DS、eflags`寄存器，修改上面的**DPL、CPL与IOPL**以达到提升特权的目的。

- 将修改后的`trapframe`**压入用户栈**（这一步没有修改`user_esp`寄存器），并设置中断处理例程结束后将要弹出`esp`寄存器的值为**用户栈的新地址**（与刚刚不同，这一步修改了**将要恢复**的`user_esp`寄存器）。

  > 注意此时的用户栈地址指向的是修改后的`trapframe`。

  这样在退出中断处理程序，准备恢复上下文的时候，首先弹出的栈寄存器值是修改后的用户栈地址，其次弹出的通用寄存器、段寄存器等等都是存储于用户栈中的`trapframe`。

  > 为什么要做这么奇怪的操作呢？ 因为恢复`esp`寄存器的指令**只有一条`pop %esp`**
  >
  > (当前环境下的`iret`指令不会弹出栈地址)。
  >
  > 正常情况下，中断处理例程结束，恢复`esp`寄存器后，`esp`指向的还是内核栈。
  >
  > 但我们的目的是切换回用户栈，则此时只能修改原先要恢复的`esp`值，通过该指令切换到用户栈。

  > 思考一下，进入中断处理程序前，上下文**保存在内核栈**。但将要恢复回上下文的数据却**存储于用户栈**。

- 在内核中，将修改后的``trapframe`压入用户栈这一步，需要舍弃`trapframe`中末尾两个旧的`ss`和`esp`寄存器数据，因为`iret`指令的特殊性：

  - `iret`指令的功能如下

    > `iret`指令会按顺序依次弹出`eip`、`cs`以及`eflag`的值到特定寄存器中，然后从新的`cs:ip`处开始执行。如果特权级发生改变，则还会在弹出`eflag`后再依次弹出`esp`与`ss`寄存器值。

  - 由于`iret`前后特权级不发生改变（**[中断中]ring0 -> ring0 [中断后]**），故`iret`指令不会弹出`esp`和`ss`寄存器值。如果这两个寄存器也被复制进用户栈，则相比于进入中断前的用户栈地址，`esp`最终会抬高8个字节，可能造成很严重的错误。

### 特权级降低

通过陷入门**从ring0切换至ring3（特权降低）** 的过程与特权提升的操作基本一样，不过有几个不同点需要注意一下

- 与ring3调用中断不同，当ring0调用中断时，进入中断前和进入中断后的这个过程，栈不发生改变。

  > 因为在调用中断前的权限已经处于ring0了，而中断处理程序里的权限也是ring0，所以这一步陷入操作的特权级没有发生改变，故不需要访问TSS并重新设置`ss` 、`esp`寄存器。

- 修改后的`trapFrame`不需要像上面那样保存至将要使用的栈，因为当前环境下`iret`前后特权级会发生改变，执行该命令会弹出`ss`和`esp`，所以可以通过`iret`来设置返回时的栈地址。

# C函数调用的实现

- [C 语言函数调用栈 (一)](http://www.cnblogs.com/clover-toeic/p/3755401.html)
- [C 语言函数调用栈 (二)](http://www.cnblogs.com/clover-toeic/p/3756668.html)

# GCC内联汇编

在c语言中插入汇编代码，完成c语言无法做到的指令。

## Syntax

```c
asm(assembler template
    :output operands		(optional)
    :input operands 		(optional)
    :clobbers				(optional)
);
```

## Example 1

对于：

```assembly
movl $0xffff, %eax
```

转化为：

```c
asm("movl $0xffff, %%eax\n");
```

## Example 2

对于：

```assembly
movl %cr0, %ebx
movl %ebx, 12(%esp)
orl  $-2147483648, 12(%esp)
movl 12(%esp), %eax
movl %eax, %cr0
```

转化为：

```c
uint32_t cr0;
asm volatile ("movl %%cr0, %0\n": "=r"(cr0));
cr0 |= 0x80000000;
asm volatile ("movl %0, %%cr0\n":: "=r"(cr0));
```

- volatile：不需要优化，不需要调整顺序
- %0：第一个用到的寄存器
- r：任意寄存器

## Example 3

对于：

```assembly
movl $11, %eax
movl -28(%ebp), %ebx
movl -24(%ebp), %ecx
movl -20(%ebp), %edx
movl -16(%ebp), %esi
int $0x80
movl %edi, -12(%ebp)
```

转化为：

```c
long_res, arg1 = 2, arg2 = 22, arg3 = 222, arg4 = 233;
_asm_volatile("int $0x80"
             :"=a"(_res)
             :"0"(11), "b"(arg1), "c"(arg2), "d"(arg3), "S"(arg4));
```

- a = %eax
- b = %ebx
- c = %ecx
- d = %edx
- S = %esi
- D = %edi 

# Lab 1:

## 练习1

**理解通过make生成执行文件的过程**

这个练习需要对Makefile有一定的了解。

首先，我们使用`make V=`看一下`make`执行了什么命令

```bash
+ cc kern/init/init.c
gcc -Ikern/init/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/init/init.c -o obj/kern/init/init.o
+ cc kern/libs/stdio.c
gcc -Ikern/libs/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/libs/stdio.c -o obj/kern/libs/stdio.o
+ cc kern/libs/readline.c
gcc -Ikern/libs/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/libs/readline.c -o obj/kern/libs/readline.o
+ cc kern/debug/panic.c
gcc -Ikern/debug/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/debug/panic.c -o obj/kern/debug/panic.o
+ cc kern/debug/kdebug.c
gcc -Ikern/debug/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/debug/kdebug.c -o obj/kern/debug/kdebug.o
+ cc kern/debug/kmonitor.c
gcc -Ikern/debug/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/debug/kmonitor.c -o obj/kern/debug/kmonitor.o
+ cc kern/driver/clock.c
gcc -Ikern/driver/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/driver/clock.c -o obj/kern/driver/clock.o
+ cc kern/driver/console.c
gcc -Ikern/driver/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/driver/console.c -o obj/kern/driver/console.o
+ cc kern/driver/picirq.c
gcc -Ikern/driver/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/driver/picirq.c -o obj/kern/driver/picirq.o
+ cc kern/driver/intr.c
gcc -Ikern/driver/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/driver/intr.c -o obj/kern/driver/intr.o
+ cc kern/trap/trap.c
gcc -Ikern/trap/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/trap/trap.c -o obj/kern/trap/trap.o
+ cc kern/trap/vectors.S
gcc -Ikern/trap/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/trap/vectors.S -o obj/kern/trap/vectors.o
+ cc kern/trap/trapentry.S
gcc -Ikern/trap/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/trap/trapentry.S -o obj/kern/trap/trapentry.o
+ cc kern/mm/pmm.c
gcc -Ikern/mm/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/ -Ikern/trap/ -Ikern/mm/ -c kern/mm/pmm.c -o obj/kern/mm/pmm.o
+ cc libs/string.c
gcc -Ilibs/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/  -c libs/string.c -o obj/libs/string.o
+ cc libs/printfmt.c
gcc -Ilibs/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/  -c libs/printfmt.c -o obj/libs/printfmt.o
+ ld bin/kernel
ld -m    elf_i386 -nostdlib -T tools/kernel.ld -o bin/kernel  obj/kern/init/init.o obj/kern/libs/stdio.o obj/kern/libs/readline.o obj/kern/debug/panic.o obj/kern/debug/kdebug.o obj/kern/debug/kmonitor.o obj/kern/driver/clock.o obj/kern/driver/console.o obj/kern/driver/picirq.o obj/kern/driver/intr.o obj/kern/trap/trap.o obj/kern/trap/vectors.o obj/kern/trap/trapentry.o obj/kern/mm/pmm.o  obj/libs/string.o obj/libs/printfmt.o
+ cc boot/bootasm.S
gcc -Iboot/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootasm.S -o obj/boot/bootasm.o
+ cc boot/bootmain.c
gcc -Iboot/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootmain.c -o obj/boot/bootmain.o
+ cc tools/sign.c
gcc -Itools/ -g -Wall -O2 -c tools/sign.c -o obj/sign/tools/sign.o
gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
+ ld bin/bootblock
ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
'obj/bootblock.out' size: 500 bytes
build 512 bytes boot sector: 'bin/bootblock' success!
dd if=/dev/zero of=bin/ucore.img count=10000
10000+0 records in
10000+0 records out
5120000 bytes (5.1 MB, 4.9 MiB) copied, 0.0333522 s, 154 MB/s
dd if=bin/bootblock of=bin/ucore.img conv=notrunc
1+0 records in
1+0 records out
512 bytes copied, 0.000129699 s, 3.9 MB/s
dd if=bin/kernel of=bin/ucore.img seek=1 conv=notrunc
154+1 records in
154+1 records out
78964 bytes (79 kB, 77 KiB) copied, 0.000418797 s, 189 MB/s
```

### dd命令

dd 命令用于读取、转换并输出数据。dd 可从标准输入或文件中读取数据，根据指定的格式来转换数据，再输出到文件、设备或标准输出。

仅针对出现的参数进行解释：

- if=文件名：输入文件名，默认为标准输入。即指定源文件。
- of=文件名：输出文件名，默认为标准输出。即指定目的文件。
- seek=blocks：从输出文件开头跳过blocks个块后再开始复制。
- count=blocks：仅拷贝blocks个块，块大小等于ibs指定的字节数。

这样可以看出，我们最后生成的文件就是`bin/ucore.img`这个镜像文件，而最后的三个`dd`命令

```bash
dd if=/dev/zero of=bin/ucore.img count=10000
// 将文件bin/ucore.img进行清空
dd if=bin/bootblock of=bin/ucore.img conv=notrunc
// 向img的开始写入512字节的bootloader
dd if=bin/kernel of=bin/ucore.img seek=1 conv=notrunc
// 跳过第一个块512字节，写入内核
```

接着，我们就从Makefile中看看，为了得到`bin/ucore.img`，我们要提前准备那些文件

> Makefile就是这样的，在其中指定了代码编译的规则，更重要的是指定了程序之间的依赖关系，所以从头看是不行的，要从最后的结果来推导整个文件的结构。

### ucore.img

```makefile
# create ucore.img
UCOREIMG	:= $(call totarget,ucore.img)

$(UCOREIMG): $(kernel) $(bootblock)
	$(V)dd if=/dev/zero of=$@ count=10000
	$(V)dd if=$(bootblock) of=$@ conv=notrunc
	$(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc

$(call create_target,ucore.img)
```

为了得到`ucore.img`，需要`kernel`和`bootblock`。

### bootblock

```makefile
# create bootblock
bootfiles = $(call listf_cc,boot)
$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))
# 这里遍历 boot 目录下的所有文件 asm.h bootasm.S bootmain.c
bootblock = $(call totarget,bootblock)
# 生成目标文件 asm.o bootasm.o bootmain.o sign.o
$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
	@$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
	@$(OBJDUMP) -t $(call objfile,bootblock) | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,bootblock)
	@$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
	@$(call totarget,sign) $(call outfile,bootblock) $(bootblock)
# 将目标文件 链接起来 同时指定代码段开始地址 为 0x7c00
$(call create_target,bootblock)
```

生成`bootblock`，需要`bootasm.o`、`bootmain.o`、`sign`

生成`bootasm.o`需要`bootasm.S`，实际执行命令为

```bash
gcc -Iboot/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootasm.S -o obj/boot/bootasm.o
```

其中关键的参数为

- -ggdb  生成可供gdb使用的调试信息。这样才能用qemu+gdb来调试bootloader or ucore。
- -m32  生成适用于32位环境的代码。我们用的模拟硬件是32bit的80386，所以ucore也要是32位的软件。
- -gstabs  生成stabs格式的调试信息。这样要ucore的monitor可以显示出便于开发者阅读的函数调用栈信息
- -nostdinc  不使用标准库。标准库是给应用程序用的，我们是编译ucore内核，OS内核是提供服务的，所以所有的服务要自给自足。
- -fno-stack-protector  不生成用于检测缓冲区溢出的代码。这是for 应用程序的，我们是编译内核，ucore内核好像还用不到此功能。
- -Os  为减小代码大小而进行优化。根据硬件spec，主引导扇区只有512字节，我们写的简单bootloader的最终大小不能大于510字节。
- -I\<dir>  添加搜索头文件的路径

生成`bootmain.o`需要`bootmain.c`

实际执行命令为

```bash
gcc -Iboot/ -fno-builtin -fno-PIC -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootmain.c -o obj/boot/bootmain.o
```

- -fno-builtin  除非用\__builtin_前缀，否则不进行builtin函数的优化

### sign

```makefile
# create 'sign' tools
$(call add_files_host,tools/sign.c,sign,sign)
$(call create_target_host,sign,sign)
```

实际执行命令为

```bash
gcc -Itools/ -g -Wall -O2 -c tools/sign.c -o obj/sign/tools/sign.o
gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
```

首先生成bootblock.o

```bash
ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
```

其中关键的参数为

- -m \<emulation>  模拟为i386上的连接器
- -nostdlib  不使用标准库
- -N  设置代码段和数据段均可读写
- -e \<entry>  指定入口
- -Ttext  制定代码段开始位置

拷贝二进制代码bootblock.o到bootblock.out

```bash
objcopy -S -O binary obj/bootblock.o obj/bootblock.out
其中关键的参数为
```

- -S  移除所有符号和重定位信息
- -O \<bfdname>  指定输出格式

使用sign工具处理bootblock.out，生成bootblock

```bash
bin/sign obj/bootblock.out bin/bootblock
```

### kernel

```makefile
# create kernel target
kernel = $(call totarget,kernel)

$(kernel): tools/kernel.ld

$(kernel): $(KOBJS)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
	@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
	@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

$(call create_target,kernel)
```

`kernel.ld`是已存在的链接器，这一步将`kern`目录下生成的所有`.o`文件，通过`kernel.ld`链接为`kernel`。

- -T\<链接器路径>，使用指定的链接器

其前置命令就是将`kern`下面的所有文件编译，生成目标文件

```makefile
# kernel

KINCLUDE	+= kern/debug/ \
			   kern/driver/ \
			   kern/trap/ \
			   kern/mm/

KSRCDIR		+= kern/init \
			   kern/libs \
			   kern/debug \
			   kern/driver \
			   kern/trap \
			   kern/mm

KCFLAGS		+= $(addprefix -I,$(KINCLUDE))

$(call add_files_cc,$(call listf_cc,$(KSRCDIR)),kernel,$(KCFLAGS))

KOBJS	= $(call read_packet,kernel libs)
```

**一个被系统认为是符合规范的硬盘主引导扇区的特征是什么？**

code: sign.c

```c
    ...
	buf[510] = 0x55;
    buf[511] = 0xAA;
	...
```

## 练习2

**使用qemu执行并调试lab1中的软件**

在开始debug之前，我们参考其实验报告中的提示将`/tools/gdbinit`的内容修改如下：

```bash
file bin/kernel
set architecture i8086
target remote :1234
b* 0x7c00

define hook-stop
x/i $eip
end
continue
```

之后使用`make debug`就可以进行调试。

> 这里pwndbg插件无法进行调试，只能使用peda了

![image-20210610205636075](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210610205649.png)

也可以直接对答案进行调试，使用`make lab1-mon`。

下面我们将反汇编得到的代码与bootasm.S和 bootblock.asm进行比较：

```assembly
gdb-peda$ x/10i
   0x7c02:	xor    eax,eax
   0x7c04:	mov    ds,eax
   0x7c06:	mov    es,eax
   0x7c08:	mov    ss,eax
   0x7c0a:	in     al,0x64
   0x7c0c:	test   al,0x2
   0x7c0e:	jne    0x7c0a
   0x7c10:	mov    al,0xd1
   0x7c12:	out    0x64,al
   0x7c14:	in     al,0x64
```

而在`bootblock.asm`中

```assembly
00007c00 <start>:

# start address should be 0:7c00, in real mode, the beginning address of the running bootloader
.globl start
start:
.code16                                             # Assemble for 16-bit mode
    cli                                             # Disable interrupts
    7c00:	fa                   	cli    
    cld                                             # String operations increment
    7c01:	fc                   	cld    

    # Set up the important data segment registers (DS, ES, SS).
    xorw %ax, %ax                                   # Segment number zero
    7c02:	31 c0                	xor    %eax,%eax
    movw %ax, %ds                                   # -> Data Segment
    7c04:	8e d8                	mov    %eax,%ds
    movw %ax, %es                                   # -> Extra Segment
    7c06:	8e c0                	mov    %eax,%es
    movw %ax, %ss                                   # -> Stack Segment
    7c08:	8e d0                	mov    %eax,%ss
```

当你删除`gdbinit`中的`continue`后，就可以调试从BIOS开始的指令。非常有趣的一点是，记得吗，执行BIOS时，cpu还在实模式，而gdb默认只输出`$ip` 所指向地址的指针，而不是`cs:ip`。正确的指令应该是这样：

```bash
gdb-peda$ x/5i (($cs<<4)+$eip)
   0xffff0:     jmp    0x3630:0xf000e05b
   0xffff7:     das
   0xffff8:     xor    dh,BYTE PTR [ebx]
   0xffffa:     das
   0xffffb:     cmp    DWORD PTR [ecx],edi
   
gdb-peda$ x/5i (($cs<<4)+$eip)
   0xfe05b:     cmp    WORD PTR cs:[esi],0xffc8
   0xfe060:     bound  eax,QWORD PTR [eax]
   0xfe062:     jne    0xd241d0b2
   0xfe068:     mov    ss,edx
   0xfe06a:     mov    sp,0x7000
```

（感谢[@2st](https://github.com/M-ouse)&[@kiprey](https://github.com/Kiprey)）

## 练习3

**分析bootloader进入保护模式的过程**

```assembly
start:
.code16                                             # Assemble for 16-bit mode
    cli                                             # Disable interrupts
    cld                                             # String operations increment

    # Set up the important data segment registers (DS, ES, SS).
    xorw %ax, %ax                                   # Segment number zero
    movw %ax, %ds                                   # -> Data Segment
    movw %ax, %es                                   # -> Extra Segment
    movw %ax, %ss                                   # -> Stack Segment
```

首先，`cli`禁用中断，它的全称为`Clear Interupt`。`cld(Clear Direction)`设置了字节的传输从低位开始。清空重要的段寄存器。

> cld指令使变址寄存器SI或DI的地址指针自动增加，从前向后处理。

### 有关A20？

- 为什么要开启A20？

  Intel早期的8086 CPU提供了20根地址线，但寄存器只有16位，所以使用**段寄存器值 << 4 + 段内偏移值**的方法来访问到所有内存，但按这种方式来计算出的地址的最大值为1088KB，超过20根地址线所能表示的范围，会发生“回卷”(memory wraparound)（和整数溢出有点类似）。但下一代的基于Intel 80286 CPU的计算机系统提供了24根地址线，当CPU计算出的地址超过1MB时便**不会发生回卷**，而这就造成了**向下不兼容**。为了保持完全的向下兼容性，IBM在计算机系统上加个硬件逻辑来模仿早期的回绕特征，而这就是**A20 Gate**。

- 如何开启A20？

  - A20 Gate的方法是把A20地址线控制和键盘控制器的一个输出进行AND操作，这样来控制A20地址线的打开（使能）和关闭（屏蔽\禁止）。一开始时A20地址线控制是被屏蔽的（总为0），直到系统软件通过一定的IO操作去打开它。当A20 地址线控制禁止时，则程序就像在8086中运行，1MB以上的地址不可访问；保护模式下A20地址线控制必须打开。A20控制打开后，内存寻址将不会发生回卷。
  - 通常的方法是通过设置键盘控制器的端口值，不过有些系统觉得键盘控制器很慢，为此引入了一个Fast Gate A20，它用IO端口的0x92来处理A20信号线。还有一种方法是通过读取0xee端口来开启A20地址线，写端口则会禁止地址线。
  - 从理论上讲，打开A20 Gate的方法是通过设置8042芯片输出端口（64h）的2nd-bit，但事实上，当你向8042芯片输出端口进行写操作的时候，在键盘缓冲区中或许还有别的数据尚未处理，因此你必须首先处理这些数据。  所以，激活A20地址线的流程为：  1.禁止中断；2.等待，直到8042 Input buffer为空为止； 3.发送Write 8042 Output Port命令到8042 Input buffer；4.等待，直到8042 Input buffer为空为止；5.向P2写入数据，将OR2置1
  
  （关于激活我没有找到很详细的资料，只有[A20激活详解](https://wenku.baidu.com/view/d6efe68fcc22bcd126ff0c00.html)）

![image-20210611190136028](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210611190136.png)

启动A20的汇编代码如下

```assembly
    # Enable A20:
    #  For backwards compatibility with the earliest PCs, physical
    #  address line 20 is tied low, so that addresses higher than
    #  1MB wrap around to zero by default. This code undoes this.
seta20.1:               # 等待8042键盘控制器不忙
    inb $0x64, %al      # 从0x64键盘缓冲区接收消息
    testb $0x2, %al     # 如果接受到2则表明键盘缓冲区为空
    jnz seta20.1        #

    movb $0xd1, %al     # 发送写8042输出端口的指令
    outb %al, $0x64     # 0xd1表示写输出端口P2

seta20.1:               # 等待8042键盘控制器不忙
    inb $0x64, %al      # 
    testb $0x2, %al     #
    jnz seta20.1        #

    movb $0xdf, %al     # 0xdf --> P2
    outb %al, $0x60     # 1101 1111 ，P2的P21置为1
```

### 如何初始化GDT表？

```assembly
# Bootstrap GDT
.p2align 2                                          # force 4 byte alignment
gdt:
    SEG_NULLASM                                     # null seg
    SEG_ASM(STA_X|STA_R, 0x0, 0xffffffff)           # code seg for bootloader and kernel
    SEG_ASM(STA_W, 0x0, 0xffffffff)                 # data seg for bootloader and kernel

gdtdesc:
    .word 0x17                                      # sizeof(gdt) - 1
    .long gdt                                       # address gdt
```

- 设置表中第一项为`NULL`
- 表中第二项为代码段描述符，可读可执行
- 表中第二项为数据段描述符，可写

回到bootloader的代码

```assembly
    # Switch from real to protected mode, using a bootstrap GDT
    # and segment translation that makes virtual addresses
    # identical to physical addresses, so that the
    # effective memory map does not change during the switch.
    lgdt gdtdesc
    movl %cr0, %eax
    orl $CR0_PE_ON, %eax
    movl %eax, %cr0
```

在开启A20之后，加载了`GDT`全局描述符表，它是被静态储存在引导区中的，载入即可。

接着，将`cr0`寄存器的bit 0置为1，标志着从实模式转换到保护模式。

```assembly
    # Jump to next instruction, but in 32-bit code segment.
    # Switches processor into 32-bit mode.
    ljmp $PROT_MODE_CSEG, $protcseg
```
因为长跳转可以设置其`cs`寄存器，所以使用一个长跳转进入32位指令模式执行。
```assembly
.code32                                             # Assemble for 32-bit mode
protcseg:
    # Set up the protected-mode data segment registers
    movw $PROT_MODE_DSEG, %ax                       # Our data segment selector
    movw %ax, %ds                                   # -> DS: Data Segment
    movw %ax, %es                                   # -> ES: Extra Segment
    movw %ax, %fs                                   # -> FS
    movw %ax, %gs                                   # -> GS
    movw %ax, %ss                                   # -> SS: Stack Segment

    # Set up the stack pointer and call into C. The stack region is from 0--start(0x7c00)
    movl $0x0, %ebp
    movl $start, %esp
    call bootmain

    # If bootmain returns (it shouldn't), loop.
spin:
    jmp spin
```

设置各段寄存器，并建立堆栈（0~0x7c00），最后进入`bootmain`函数（in bootmain.c）中。

## 练习4

#### 分析bootloader加载ELF格式的OS的过程

```c
unsigned int    SECTSIZE  =      512 ;
struct elfhdr * ELFHDR    =      ((struct elfhdr *)0x10000) ;     // scratch space

/* bootmain - the entry of bootloader */
void
bootmain(void) {
    // read the 1st page off disk
    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);

    // is this a valid ELF?
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }

    struct proghdr *ph, *eph;

    // load each program segment (ignores ph flags)
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }

    // call the entry point from the ELF header
    // note: does not return
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();

bad:
    outw(0x8A00, 0x8A00);
    outw(0x8A00, 0x8E00);

    /* do nothing */
    while (1);
}
```

首先，从硬盘读取一页（512*8）的内容加载到`0x10000`。

现在考虑它是如何读取的？

bootloader让CPU进入保护模式后，下一步的工作就是从硬盘上加载并运行OS。考虑到实现的简单性，bootloader的访问硬盘都是LBA模式的PIO（Program IO）方式，即所有的IO操作是通过CPU访问硬盘的IO地址寄存器完成。

一般主板有2个IDE通道，每个通道可以接2个IDE硬盘。访问第一个硬盘的扇区可设置IO地址寄存器0x1f0-0x1f7实现的，具体参数见下表。一般第一个IDE通道通过访问IO地址0x1f0-0x1f7来实现，第二个IDE通道通过访问0x170-0x17f实现。每个通道的主从盘的选择通过第6个IO偏移地址寄存器来设置。

第6位：为1=LBA模式；0 = CHS模式 第7位和第5位必须为1

| IO地址 | 功能                                                         |
| :----: | :----------------------------------------------------------- |
| 0x1f0  | 读数据，当0x1f7不为忙状态时，可以读。                        |
| 0x1f2  | 要读写的扇区数，每次读写前，你需要表明你要读写几个扇区。最小是1个扇区 |
| 0x1f3  | 如果是LBA模式，就是LBA参数的0-7位                            |
| 0x1f4  | 如果是LBA模式，就是LBA参数的8-15位                           |
| 0x1f5  | 如果是LBA模式，就是LBA参数的16-23位                          |
| 0x1f6  | 第0~3位：如果是LBA模式就是24-27位 第4位：为0主盘；为1从盘    |
| 0x1f7  | 状态和命令寄存器。操作时先给命令，再读取，如果不是忙状态就从0x1f0端口读数据 |
当前 硬盘数据是储存到硬盘扇区中，一个扇区大小为512字节。读一个扇区的流程大致如下：

1. 等待磁盘准备好
2. 发出读取扇区的命令
3. 等待磁盘准备好
4. 把磁盘扇区数据读到指定内存

在c代码中是这样实现的，`readseg()`是`readsect()`的一个封装：

```c
/* readsect - read a single sector at @secno into @dst */
static void
readsect(void *dst, uint32_t secno) {
    // wait for disk to be ready
    waitdisk();

    outb(0x1F2, 1);                         // count = 1
    outb(0x1F3, secno & 0xFF);
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    outb(0x1F7, 0x20);                      // cmd 0x20 - read sectors

    // wait for disk to be ready
    waitdisk();

    // read a sector
    insl(0x1F0, dst, SECTSIZE / 4);
}

/* waitdisk - wait for disk ready */
static void
waitdisk(void) {
    while ((inb(0x1F7) & 0xC0) != 0x40)
        /* do nothing */;
}

static inline void
outb(uint16_t port, uint8_t data) {
    asm volatile ("outb %0, %1" :: "a" (data), "d" (port) : "memory");
}
```

加载到磁盘后，判断其是否是一个合法的ELF：

```c
    // is this a valid ELF?
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }
```

如果合法则：

```c
    // load each program segment (ignores ph flags)
    // 在ELF文件头中，有描述符表记录了ELF文件应该加载到什么位置 
    // 将描述符表保存到ph中
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    // 按照描述表将ELF文件中数据载入内存 
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }

    // call the entry point from the ELF header
    // note: does not return
    // 内核入口
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();
```

## 练习5

**实现函数调用堆栈跟踪函数**

```c
void
print_stackframe(void) {
    uint32_t ebp = read_ebp();
    uint32_t eip = read_eip();

    for(uint32_t i = 0; ebp != 0 && i < STACKFRAME_DEPTH; i++) {
        cprintf("ebp: 0x%08x eip: 0x%08x, arg:", ebp, eip);
        uint32_t *arg = (uint32_t *)ebp + 2;
        for(uint32_t j = 0; j< 4; j++) {
            cprintf("0x%08x ", arg[j]);
        }
        cprintf("\n");
        print_debuginfo(eip - 1);
        eip = *((uint32_t *)ebp + 1);
        ebp = *(uint32_t *)ebp;
    }
}
```

这里需要对32位c的函数调用有充分的理解

![](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210611230013.jpeg)

涉及到很多指针操作，还有一点要注意的是，`eip`指向的是即将执行的指令，所以如果想要查看当前函数需要`-1`。

## 练习6

**完善中断初始化和处理**

- 中断描述符表（也可简称为保护模式下的中断向量表）中一个表项占多少字节？其中哪几位代表中断处理代码的入口？

code in /kern/mm/mmu.h：

```c
/* Gate descriptors for interrupts and traps */
struct gatedesc {
    unsigned gd_off_15_0 : 16;        // low 16 bits of offset in segment
    unsigned gd_ss : 16;            // segment selector
    unsigned gd_args : 5;            // # args, 0 for interrupt/trap gates
    unsigned gd_rsv1 : 3;            // reserved(should be zero I guess)
    unsigned gd_type : 4;            // type(STS_{TG,IG32,TG32})
    unsigned gd_s : 1;                // must be 0 (system)
    unsigned gd_dpl : 2;            // descriptor(meaning new) privilege level
    unsigned gd_p : 1;                // Present
    unsigned gd_off_31_16 : 16;        // high bits of offset in segment
};
```

一个表项共有`8*8 = 64 bit`即8字节。其中`gd_ss`是段选择子，`gd_off_15_0`是偏移，通过这两项我们就可以找到中断处理代码的入口。

```c
void
idt_init(void) {
    extern uintptr_t __vectors[];
    uint32_t i;
    for(i = 0; i < sizeof(idt) / sizeof(struct gatedesc); i ++)
    {	// 使用宏设置IDT的每一项
        // IDT的每一项都是中断且在内核态处理的所以设为`GD_LTEXT`，特权级为`DPL_KERNEL`
        SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_KERNEL);
    }
    // 系统调用是提供给用户，供其调用的，所以我们要修改其特权级，使其可以在用户态调用
    SETGATE(idt[T_SWITCH_TOK], 0, GD_KTEXT, __vectors[T_SWITCH_TOK], DPL_USER);
    // 加载idt
    lidt(&idt_pd);
}
```
除了系统调用中断(T_SYSCALL)使用陷阱门描述符且权限为用户态权限以外，其它中断均使用特权级(DPL)为０的中断门描述符，权限为内核态权限；而ucore的应用程序处于特权级３，需要采用｀int 0x80`指令操作（这种方式称为软中断，软件中断，Tra中断，在lab5会碰到）来发出系统调用请求，并要能实现从特权级３到特权级０的转换，所以系统调用中断(T_SYSCALL)所对应的中断门描述符中的特权级（DPL）需要设置为３。
```c
    char c;

    switch (tf->tf_trapno) {
    case IRQ_OFFSET + IRQ_TIMER:
        ticks++;
        if(ticks % TICK_NUM ==0)
            print_ticks();
        break;
```

每100次时钟中断调用`print_ticks`，这部分看其代码中给的提示很容易编写出来，实验指导中的很模糊。

## Challenge 1

> 为完成挑战请仔细阅读trap相关的代码、test相关代码以及《操作系统真象还原》-特权级深入浅出一章

在所有中断处理程序中都使用`__alltraps`，它将`trapframe`保存在栈上。在由内核态切换成用户态的时候，一开始调用中断时，由于是从内核态调用的，没有权限切换，故ss、esp没有压栈，而iret返回时，是返回到用户态，故ss、esp会出栈，于是为了保证栈的正确性，需要在调用中断前将esp减8以预留空间，中断返回后，由于esp被修改，还需要手动恢复esp为正确值。

这样之后，系统特权级已经成功切换，但是由于切换到了用户态，导致IO操作没有权限，故之后的printf无法成功输出，为了能够正常输出，我们需要将eflags中的IOPL设成用户级别，即3，同样也是通过修改栈中值来达到修改的目的。

**ring3 -> ring0**

```c
// 全局变量
struct trapframe switchk2u;
// ......
case T_SWITCH_TOK:
    if (tf->tf_cs != KERNEL_CS) {
    tf->tf_cs = KERNEL_CS;			// 修改CPL DPL IOPL
    tf->tf_ds = tf->tf_es = KERNEL_DS;
    tf->tf_eflags &= ~FL_IOPL_MASK;
    // 计算将要保存新trapFrame的用户栈地址
    // 数值减8是因为内核调用中断时CPU没有压入ss和esp
    switchu2k = (struct trapframe *)(tf->tf_esp - (sizeof(struct trapframe) - 8));
    // 将修改后的trapFrame写入用户栈(注意当前是内核栈)。注意trapFrame中ss和esp的值不需要写入。
    memmove(switchu2k, tf, sizeof(struct trapframe) - 8);
    // 设置弹出esp的值为用户栈的新地址
    *((uint32_t *)tf - 1) = (uint32_t)switchu2k;
}
break;
```

**ring0 -> ring3**

```c
// 全局变量
struct trapframe *switchu2k;
// ......
case T_SWITCH_TOU:
    if (tf->tf_cs != USER_CS) {
    // 将中断的栈帧赋给临时中断帧
    switchk2u = *tf;
    // 修改可执行代码段为USER_CS
    switchk2u.tf_cs = USER_CS;
    // 修改数据段为USER_DS
    switchk2u.tf_ds = switchk2u.tf_es = switchk2u.tf_ss = USER_DS;
    // 设置从中断处理程序返回时的栈地址
    // 数值减8是因为iret不会弹出ss和esp，所以不需要这8个字节
    switchk2u.tf_esp = (uint32_t)tf + sizeof(struct trapframe) - 8;
    // 为了使得程序在低CPL的情况下仍然能够使用IO
    // 需要将eflags中对应的IOPL位置成表示用户态的3
    switchk2u.tf_eflags |= FL_IOPL_MASK;
    // 设置中断处理例程结束时pop出的%esp，这样可以用修改后的数据来恢复上下文。
    *((uint32_t *)tf - 1) = (uint32_t)&switchk2u;
    }
    // 事实上上述代码并没有实际完成一个从内核栈到用户态栈的切换
    // 仅仅是完成了特权级的切换。这属于正常现象。
break;
```

**中断**

```c
static void
lab1_switch_to_user(void) {
	asm volatile (
	    "sub $0x8, %%esp \n"
	    "int %0 \n"
	    "movl %%ebp, %%esp"
	    : 
	    : "i"(T_SWITCH_TOU)
	);
}

static void
lab1_switch_to_kernel(void) {
	asm volatile (
	    "int %0 \n"
	    "movl %%ebp, %%esp \n"
	    : 
	    : "i"(T_SWITCH_TOK)
	);
}
```

最后为了完成挑战不要忘了在`kern_init`中，开启test。

## Challenge 2

使用键盘完成用户态与内核态的切换

```c
   case IRQ_OFFSET + IRQ_KBD:
        c = cons_getc();		// 从控制台获取键盘消息
        cprintf("kbd [%03d] %c\n", c, c);
        if(c == '0')			// 输入 0 进行 用户态到内核态的切换
        {
            if (tf->tf_cs != KERNEL_CS) {
                cprintf("+++ switch to  kernel  mode +++\n");
                tf->tf_cs = KERNEL_CS;
                tf->tf_ds = tf->tf_es = KERNEL_DS;
                tf->tf_eflags &= ~FL_IOPL_MASK;
                switchu2k = (struct trapframe *)(tf->tf_esp - (sizeof(struct trapframe) - 8));
                memmove(switchu2k, tf, sizeof(struct trapframe) - 8);
                *((uint32_t *)tf - 1) = (uint32_t)switchu2k;
            }
        }
        else if(c == '3')		// 输入 3 进行 内核态到用户态的切换
        {
            if (tf->tf_cs != USER_CS) {
                cprintf("+++ switch to  user  mode +++\n");
                switchk2u = *tf;
                switchk2u.tf_cs = USER_CS;
                switchk2u.tf_ds = switchk2u.tf_es = switchk2u.tf_ss = USER_DS;
                switchk2u.tf_esp = (uint32_t)tf + sizeof(struct trapframe) - 8;
                switchk2u.tf_eflags |= FL_IOPL_MASK;
                *((uint32_t *)tf - 1) = (uint32_t)&switchk2u;
            }
        }
        break;
```

切换部分的代码与challenge1相同。

**check**

```bash
neibelungen@neibelungen:~/os_kernel_lab/labcodes/lab1$ make grade
Check Output:            (2.5s)
  -check ring 0:                             OK
  -check switch to ring 3:                   OK
  -check switch to ring 0:                   OK
  -check ticks:                              OK
Total Score: 40/40
```


