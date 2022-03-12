# uCore-lab-4


# 概述

在前几次实验的基础上，我们将实现CPU的虚拟化。可以理解为让每个用户态进程认为自己“独占”CPU资源。

# 进程

对于进程的**定义**：进程是指一个具有一定独立功能的程序在一个数据集合上的一次动态执行过程。

进程包含了正在运行的一个程序的所有状态信息。（代码，数据，寄存器，进程所占资源等）

**进程与程序**
程序是一个静态可执行文件，是有序代码的集合。而进程是执行中的程序，有内核态和用户态。

## 进程控制块PCB

- PCB描述进程的基本情况以及运行变化的过程
- 进程控制块是进程的唯一标识。
- 调度和状态信息、进程间通信信息、存储管理信息、进程所用的资源和与PCB相关的进程队列。如用链表维护正在就绪态的所有进程。

## 进程状态

进程生命周期的划分：进程创建、进程执行、进程等待、进程抢占、进程唤醒和进程结束。

### 进程创建

进程创建的情况：

- 系统初始化时
- 用户请求创建一个新进程
- 正在运行的进程执行了创建进程的系统调用

创建的进程，在为其准备好相应的资源后，会加入就绪队列。

### 进程执行

CPU的分时执行，当一个进程执行了一个时间片后，内核从就绪队列基于某种策略选择一个进程执行。

### 进程等待

进程等待（阻塞）的情况：

- 请求并等待系统服务，无法马上完成
- 启动某种操作，无法马上完成
- 需要的数据没有到达（例如磁盘读写）

进程进入等待状态只会是进程自身的原因。

### 进程唤醒

当等待状态的进程所要求的条件（资源准备好，某事件的发生）满足后，会加入到就绪状态。

进程只会被别的进程或操作系统唤醒。

### 进程结束

释放进程所占的所有资源

结束的情况：正常退出、错误退出、致命错误、被其他进程杀死

### 进程挂起

系统的内存不足时，需要将某些进程放到磁盘中，称为进程挂起。

-   等待挂起（Blocked-suspend）： 进程在外存并等待某事件的出现。
-   就绪挂起（Ready-suspend）：进程在外存，但只要进入内存，即可运行。
-   挂起（Suspend）：把一个进程从内存转到外存。
    -   等待到等待挂起：没有进程处于就绪状态或就绪进程要求更多内存资源。
    -   就绪到就绪挂起：当有高优先级进程处于等待状态（系统认为很快会就绪的），低优先级就绪进程会挂起，为高优先级进程提供更大的内存空间。
    -   运行到就绪挂起：当有高优先级等待进程因事件出现而进入就绪挂起。
    -   等待挂起到就绪挂起：当有等待挂起进程因相关事件出现而转换状态。
-   激活（Activate）：把一个进程从外存转到内存
    -   就绪挂起到就绪：没有就绪进程或挂起就绪进程优先级高于就绪进程。
    -   等待挂起到等待：当一个进程释放足够内存，并有高优先级等待挂起进程。

# 线程

 线程的出现：我们希望进程之间有更好的并发性，并实现更高程度的数据共享。而这与进程的独立性相矛盾，所以有了线程。

## 概念

线程是进程的一部分，描述指令流执行状态，是进程中的指令执行流最小单位，是CPU调度的基本单位。

- 进程的资源分配角色：进程由一组相关资源构成，包括地址空间、打开的文件等各种资源。

- 线程的处理机调度角色：线程描述在进程资源环境中指令流执行状态。

进程变成了资源分配的单位，线程是CPU调度的单位。

### 优缺点

-   优点：
    -   一个进程中可以存在多个线程
    -   各个线程可以并发执行
    -   各个线程之间可以共享地址空间和文件等资源。
-   缺点：
    -   一个线程崩溃，会导致其所属的进程的所有线程崩溃。

## 用户线程

由一组用户级的线程库函数来完成线程的管理，包括线程的创建、终止、同步和调度等。

### 特点

用户线程不依赖操作系统，在操作系统的角度面对的依然只有每个进程的PCB。而在用户态，有各个进程内部实现线程控制块TCB。并实现自定义的线程调度算法。

由于不经过操作系统，所有没有了用户态和内核态的切换，减少了很大的开销。且有更自由的线程调用策略。

### 缺点

线程发起系统调用请求操作系统服务时，对操作系统来说是以一个进程的名义操作的。如果阻塞，整个进程都会进入等待状态。而且不支持基于线程的处理机抢占。操作系统仅分配一个进程的时间片，这样所有线程分配到的执行时间很少，只能按进程分配CPU时间。

## 内核线程

将线程的操作加入到内核中，由内核通过系统调用实现的线程机制，由内核完成线程的创建、终止和管理。

这样解决了用户线程的很多问题，但是加大了线程用户态与内核态之间切换的消耗。

## 轻权线程

-   内核支持的用户线程。一个进程可包含一个或多个轻权进程，每个轻权进程由一个单独的内核线程来支持。

-   过于复杂以至于优点没有体现出来，最后演化为单一的内核线程支持。（笑）

## 线程与进程的比较

-   进程是资源分配单元，而线程是CPU调度单位。
-   进程拥有一个完整的资源平台，而线程只独享指令流执行的必要资源，例如寄存器与栈。
-   线程具有就绪、等待和运行三种基本状态和状态间的转换关系。
-   线程能减小并发执行的事件和空闲开销。
    -   线程的创建时间和终止时间比进程短。
    -   同一进程内的线程切换时间比进程短。
    -   由于同一进程的各线程间共享内存和文件资源，可不通过内核进行直接通信。

# 进程切换

暂停当前进程，并从运行状态变成其他状态。调度另一个进程，并从就绪状态转为运行状态。
进程切换要求：

- 切换前，保存上下文
- 切换后，恢复上下文
- 速度要快

## ucore的PCB

```c
enum proc_state {
    PROC_UNINIT = 0,  // 未初始化的     -- alloc_proc
    PROC_SLEEPING,    // 等待状态       -- try_free_pages, do_wait, do_sleep
    PROC_RUNNABLE,    // 就绪/运行状态   -- proc_init, wakeup_proc,
    PROC_ZOMBIE,      // 僵死状态       -- do_exit
};

struct context {  // 保存的上下文寄存器，注意没有eax寄存器和段寄存器
    uint32_t eip;
    uint32_t esp;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
};

struct proc_struct {
    enum proc_state state;                      // Process state
    int pid;                                    // Process ID
    int runs;                                   // the running times of Proces
    uintptr_t kstack;                           // Process kernel stack
    volatile bool need_resched;                 // bool value: need to be rescheduled to release CPU?
    struct proc_struct *parent;                 // the parent process
    struct mm_struct *mm;                       // Process's memory management field
    struct context context;                     // Switch here to run process
    struct trapframe *tf;                       // Trap frame for current interrupt
    uintptr_t cr3;                              // CR3 register: the base addr of Page Directroy Table(PDT)
    uint32_t flags;                             // Process flag
    char name[PROC_NAME_LEN + 1];               // Process name
    list_entry_t list_link;                     // Process link list 
    list_entry_t hash_link;                     // Process hash list
};
```

- mm：内存管理的信息，包括内存映射列表、页表指针等。mm成员变量在lab3中用于虚存管理。但在实际OS中，内核线程常驻内存，不需要考虑swap page问题，在lab5中涉及到了用户进程，才考虑进程用户内存空间的swap page问题，mm才会发挥作用。所以在lab4中mm对于内核线程就没有用了，这样内核线程的proc_struct的成员变量\*mm=0是合理的。mm里有个很重要的项pgdir，记录的是该进程使用的一级页表的物理地址。由于\*mm=NULL，所以在proc_struct数据结构中需要有一个代替pgdir项来记录页表起始地址，这就是proc_struct数据结构中的cr3成员变量。
- state：进程所处的状态。
- parent：用户进程的父进程（创建它的进程）。在所有进程中，只有一个进程没有父进程，就是内核创建的第一个内核线程idleproc。内核根据这个父子关系建立一个树形结构，用于维护一些特殊的操作，例如确定某个进程是否可以对另外一个进程进行某种操作等等。
- context：进程的上下文，用于进程切换（参见switch.S）。在 uCore中，所有的进程在内核中也是相对独立的（例如独立的内核堆栈以及上下文等等）。使用 context 保存寄存器的目的就在于在内核态中能够进行上下文之间的切换。实际利用context进行上下文切换的函数是在kern/process/switch.S中定义switch_to。
- tf：中断帧的指针，总是指向内核栈的某个位置：当进程从用户空间跳到内核空间时，中断帧记录了进程在被中断前的状态。当内核需要跳回用户空间时，需要调整中断帧以恢复让进程继续执行的各寄存器值。除此之外，uCore内核允许嵌套中断。因此为了保证嵌套中断发生时tf 总是能够指向当前的trapframe，uCore 在内核栈上维护了 tf 的链，可以参考trap.c::trap函数做进一步的了解。
- cr3: cr3 保存页表的物理地址，目的就是进程切换的时候方便直接使用 lcr3实现页表切换，避免每次都根据 mm 来计算 cr3。mm数据结构是用来实现用户空间的虚存管理的，但是内核线程没有用户空间，它执行的只是内核中的一小段代码（通常是一小段函数），所以它没有mm 结构，也就是NULL。当某个进程是一个普通用户态进程的时候，PCB 中的 cr3 就是 mm 中页表（pgdir）的物理地址；而当它是内核线程的时候，cr3 等于boot_cr3。而boot_cr3指向了uCore启动时建立好的饿内核虚拟空间的页目录表首地址。
- kstack: 每个线程都有一个内核栈，并且位于内核地址空间的不同位置。对于内核线程，该栈就是运行时的程序使用的栈；而对于普通进程，该栈是发生特权级改变的时候使保存被打断的硬件信息用的栈。uCore在创建进程时分配了 2 个连续的物理页（参见memlayout.h中KSTACKSIZE的定义）作为内核栈的空间。这个栈很小，所以内核中的代码应该尽可能的紧凑，并且避免在栈上分配大的数据结构，以免栈溢出，导致系统崩溃。kstack记录了分配给该进程/线程的内核栈的位置。主要作用有以下几点。首先，当内核准备从一个进程切换到另一个的时候，需要根据kstack 的值正确的设置好 tss （可以回顾一下在实验一中讲述的 tss 在中断处理过程中的作用），以便在进程切换以后再发生中断时能够使用正确的栈。其次，内核栈位于内核地址空间，并且是不共享的（每个线程都拥有自己的内核栈），因此不受到 mm 的管理，当进程退出的时候，内核能够根据 kstack 的值快速定位栈的位置并进行回收。uCore 的这种内核栈的设计借鉴的是 linux 的方法（但由于内存管理实现的差异，它实现的远不如 linux 的灵活），它使得每个线程的内核栈在不同的位置，这样从某种程度上方便调试，但同时也使得内核对栈溢出变得十分不敏感，因为一旦发生溢出，它极可能污染内核中其它的数据使得内核崩溃。如果能够通过页表，将所有进程的内核栈映射到固定的地址上去，能够避免这种问题，但又会使得进程切换过程中对栈的修改变得相当繁琐。感兴趣的同学可以参考 linux kernel 的代码对此进行尝试。

为了管理系统中所有的进程控制块，uCore维护了如下全局变量（位于kern/process/proc.c）：

- `static struct proc *current`：当前占用CPU且处于“运行”状态进程控制块指针。通常这个变量是只读的，只有在进程切换的时候才进行修改，并且整个切换和修改过程需要保证操作的原子性，目前至少需要屏蔽中断。
- `static struct proc *initproc`：本实验中，指向一个内核线程。本实验以后，此指针将指向第一个用户态进程。
- `static list_entry_t hash_list[HASH_LIST_SIZE]`：所有进程控制块的哈希表，proc_struct中的成员变量hash_link将基于pid链接入这个哈希表中
- `list_entry_t proc_list`：所有进程控制块的双向线性列表，proc_struct中的成员变量list_link将链接入这个链表中。

## 切换流程

- 开始调度：uCore中，内核的第一个进程`idleproc`会执行`cpu_idle`函数，并从中调用`schedule`函数，准备开始调度进程。
- 清除调度标志：`schedule`清除调度标志，不能再次修改
- 查找就绪进程：`schedule`并从当前进程在链表中的位置开始，遍历进程控制块，直到找出处于**就绪状态**的进程。可能找到的还是当前进程。
- 修改进程状态：`schedule`当前进程进入就绪态或等待状态，新的进程改为运行
- 进程切换：`switch_to`

**swtich_to**
`switch_to`进行进程的切换，为了保证切换速度，这部分的代码使用汇编实现。在不同的操作系统上需要保存的寄存器等信息不同，所以实现也不同。大致为前半段保存进程信息，切换后，从新进程的PCB恢复进程上下文。

```c
.text
.globl switch_to
switch_to:                      # switch_to(from, to)

    # save from's registers
    movl 4(%esp), %eax          # eax points to from
    popl 0(%eax)                # save eip !popl
    movl %esp, 4(%eax)          # save esp::context of from
    movl %ebx, 8(%eax)          # save ebx::context of from
    movl %ecx, 12(%eax)         # save ecx::context of from
    movl %edx, 16(%eax)         # save edx::context of from
    movl %esi, 20(%eax)         # save esi::context of from
    movl %edi, 24(%eax)         # save edi::context of from
    movl %ebp, 28(%eax)         # save ebp::context of from

    # restore to's registers
    movl 4(%esp), %eax          # not 8(%esp): popped return address already
                                # eax now points to to
    movl 28(%eax), %ebp         # restore ebp::context of to
    movl 24(%eax), %edi         # restore edi::context of to
    movl 20(%eax), %esi         # restore esi::context of to
    movl 16(%eax), %edx         # restore edx::context of to
    movl 12(%eax), %ecx         # restore ecx::context of to
    movl 8(%eax), %ebx          # restore ebx::context of to
    movl 4(%eax), %esp          # restore esp::context of to

    pushl 0(%eax)               # push eip

    ret
```

## 进程创建

Windows API：`CreateProcess()`
Unix API：`fork`和`exec`

-   其中，`fork`把一个进程复制成两个**除PID以外完全相同**的进程。
-   `exec`用新进程来重写当前进程，PID没有改变。


fork创建一个继承的子进程。该子进程复制父进程的所有变量和内存，以及父进程的所有CPU寄存器（除了某个特殊寄存器，以区分是子进程还是父进程）。
fork函数一次调用，返回两个值。父进程中返回子进程的PID，子进程中返回0。

fork函数的开销十分昂贵，其实现开销来源于

- 对子进程分配内存。
- 复制父进程的内存和寄存器到子进程中。

而且，在大多数情况下，调用fork函数后就紧接着调用exec，此时fork中的内存复制操作是无用的。因此，fork函数中使用写时复制技术(Copy on Write， COW)。

### 空闲进程的创建

空闲进程`idle`主要工作是完成内核中各个子系统的初始化，并最后用于调度其他进程。该进程最终会一直在`cpu_idle`函数中判断当前是否可调度。

由于该进程是为了调度进程而创建的，所以其`need_resched`成员初始时为1。

### 第一个内核线程的创建

第一个内核进程是未来所有新进程的父进程或祖先进程。

- `initproc`：在`proc_init()`创建
- 初始化trapframe：`kernel_thread` --> `do_fork` --> `copy_thread()`
- 初始化initproc：初始化它的PCB，`alloc_proc`
- 初始化内核堆栈：`setup_stack()`
- 内存共享：`copy_stack()`与其他内核线程共享内核地址空间
- 把initproc放到就绪队列
- 唤醒

## 进程终止

### wait

`wait`系统调用用于父进程等待子进程的结束

- 子进程结束时，通过`exit()`向父进程返回一个值
- 父进程通过`wait`接收并处理返回值

 `wait`函数调用的功能

 - 有子进程存活时，父进程进入等待状态，等待子进程返回结果
   当某子进程调用 `exit()`时，唤醒父进程，将`exit()`的返回值作为父进程中`wait`的返回值
- 有僵尸子进程等待时，`wait()`立即返回其中一个值
- 无子进程存活时，`wait()`立即返回

### exit

进程结束时调用`exit()`，完成进程资源回收。
`exit`函数调用的功能

   - 将调用参数作为进程的“结果”
   - 关闭所有打开的文件等占用资源。
   - 释放内存
   - 释放大部分进程相关的内核数据结构
   - 检查父进程是否存活
     -   如果存活，则保留结果的值，直到父进程使用。同时当前进程进入僵尸(zombie)状态。
     -   如果没有，它将释放所有的数据结构，进程结束。
  - 清理所有等待的僵尸进程。

  进程终止是最终的垃圾收集（资源回收）。

# uCore进程的初始化

```c
// proc_init - set up the first kernel thread idleproc "idle" by itself and 
//           - create the second kernel thread init_main
void
proc_init(void) {
    int i;

    list_init(&proc_list);
    for (i = 0; i < HASH_LIST_SIZE; i ++) {
        list_init(hash_list + i);
    }

    if ((idleproc = alloc_proc()) == NULL) {
        panic("cannot alloc idleproc.\n");
    }

    idleproc->pid = 0;
    idleproc->state = PROC_RUNNABLE;
    idleproc->kstack = (uintptr_t)bootstack;
    idleproc->need_resched = 1;
    set_proc_name(idleproc, "idle");
    nr_process ++;

    current = idleproc;

    int pid = kernel_thread(init_main, "Hello world!!", 0);
    if (pid <= 0) {
        panic("create init_main failed.\n");
    }

    initproc = find_proc(pid);
    set_proc_name(initproc, "init");

    assert(idleproc != NULL && idleproc->pid == 0);
    assert(initproc != NULL && initproc->pid == 1);
}
```

首先初始化了进程相关的链表，然后通过`alloc_proc`手动构造了进程`idle`并设置其中的参数值。
接着创建了内核线程`initproc`，使其执行`init_main`。

主要函数是`kernel_thread`

```c
int
kernel_thread(int (*fn)(void *), void *arg, uint32_t clone_flags) {
    struct trapframe tf;
    memset(&tf, 0, sizeof(struct trapframe));
    tf.tf_cs = KERNEL_CS;
    tf.tf_ds = tf.tf_es = tf.tf_ss = KERNEL_DS;
    tf.tf_regs.reg_ebx = (uint32_t)fn;
    tf.tf_regs.reg_edx = (uint32_t)arg;
    tf.tf_eip = (uint32_t)kernel_thread_entry;
    return do_fork(clone_flags | CLONE_VM, 0, &tf);
}
```

首先设置了`trapframe`的必要字段，之后使用`do_fork`做真正的创建。

# 练习1

**分配并初始化一个进程控制块**

```c
// alloc_proc - alloc a proc_struct and init all fields of proc_struct
static struct proc_struct *
alloc_proc(void) {
    struct proc_struct *proc = kmalloc(sizeof(struct proc_struct));
    if (proc != NULL) {
        proc->state = PROC_UNINIT;
        proc->pid = -1;
        proc->kstack = 0;
        proc->need_resched = 0;
        proc->parent = NULL;
        proc->mm = NULL;
        memset(&proc->context, 0, sizeof(struct context));
        proc->tf = NULL;
        proc->cr3 = boot_cr3;
        proc->flags = 0;
        memset(proc->name, 0, sizeof(proc->name));
    }
    return proc;
}
```

请说明proc_struct中`struct context context`和`struct trapframe *tf`成员变量含义和在本实验中的作用是啥？

可以注意到，在进程在我们的内核出现之前，仅有`trapframe`的存在。`trapframe`在中断处理时，保存到切换后的栈中，用于在从内核态返回到用户态的进程上下文保存。

而在内核中断中没有这种结构，只有线程/进程的切换。这时候就要使用到`context`结构了。在`context`结构中，只有寄存器的保存，没有段寄存器。因为进程之间切换不涉及特权级的变化。

# 练习2

**为新创建的内核线程分配资源**

```c
/* do_fork -     parent process for a new child process
 * @clone_flags: used to guide how to clone the child process
 * @stack:       the parent's user stack pointer. if stack==0, It means to fork a kernel thread.
 * @tf:          the trapframe info, which will be copied to child process's proc->tf
 */
int
do_fork(uint32_t clone_flags, uintptr_t stack, struct trapframe *tf) {
    int ret = -E_NO_FREE_PROC;
    struct proc_struct *proc;
    if (nr_process >= MAX_PROCESS) {
        goto fork_out;
    }
    ret = -E_NO_MEM;
	
    proc = alloc_proc();
    if(proc == NULL)
    {
        cprintf("alloc_proc faile in do_fork");
        goto bad_fork_cleanup_proc;
    }
    if((ret = setup_kstack(proc)) != 0)
    {
        cprintf("setup_kstack faile in do_fork");
        goto bad_fork_cleanup_proc;
    }
    if((ret = copy_mm(clone_flags, proc)) != 0)
    {
        cprintf("copy_mm faile in do_fork");
        goto bad_fork_cleanup_kstack;        
    }
    copy_thread(proc, stack, tf);
    
    bool intr_flag;
    local_intr_save(intr_flag);
    {
        proc->pid = get_pid();
        hash_proc(proc);
        list_add(proc_list.prev, &proc->list_link);
        nr_process++;
    }
    local_intr_restore(intr_flag);
    wakeup_proc(proc);
    ret = proc->pid;
    

fork_out:
    return ret;

bad_fork_cleanup_kstack:
    put_kstack(proc);
bad_fork_cleanup_proc:
    kfree(proc);
    goto fork_out;
}
```

在fork中，为进程申请PCB，设置堆栈，还要将其加入到相关链表中。注意进程相关的一些链表是全局变量！这意味着，多个内核线程都可以访问或修改，所以为了避免条件竞争，我们在进行对应的操作时要屏蔽中断。

请说明ucore是否做到给每个新fork的线程一个唯一的id？请说明你的分析和理由。

```c
// get_pid - alloc a unique pid for process
static int
get_pid(void) {
    static_assert(MAX_PID > MAX_PROCESS);
    struct proc_struct *proc;
    list_entry_t *list = &proc_list, *le;
    static int next_safe = MAX_PID, last_pid = MAX_PID;
    if (++ last_pid >= MAX_PID) {
        last_pid = 1;
        goto inside;
    }
    if (last_pid >= next_safe) {
    inside:
        next_safe = MAX_PID;
    repeat:
        le = list;
        while ((le = list_next(le)) != list) {
            proc = le2proc(le, list_link);
            if (proc->pid == last_pid) {
                if (++ last_pid >= next_safe) {
                    if (last_pid >= MAX_PID) {
                        last_pid = 1;
                    }
                    next_safe = MAX_PID;
                    goto repeat;
                }
            }
            else if (proc->pid > last_pid && next_safe > proc->pid) {
                next_safe = proc->pid;
            }
        }
    }
    return last_pid;
}
```

系统第一次调用`get_pid`时，`next_safe == last_pid == MAX_PID`，当`last_pid`自增后大于等于`MAX_PID`，则当前可能是第一次调用，所以先设置`last_pid`为1。pid为0的进程是我们手动创建的。接着遍历进程链表，如果这是第一此调用，循环跳出后，`last_pid = 1 ~ next_safe = MAX_PID`，则下一次只需要在这个范围寻找即可。如果`last_pid`小于`MAX_PID`和`next_safe`那么就可以直接返回。

如果超过了`next_safe`，则需要遍历进程列表，若当前进程列表中有PID等于`last_pid`的进程，则要重新设置`last_pid`的值。还要判断是否超过了`next_safe`。

总之就是在函数中维护了`last_pid ~ next_safe`的区间减少搜索范围。


## fork的两次返回

在`copy_thread`中

```c
// copy_thread - setup the trapframe on the  process's kernel stack top and
//             - setup the kernel entry point and stack of process
static void
copy_thread(struct proc_struct *proc, uintptr_t esp, struct trapframe *tf) {
    proc->tf = (struct trapframe *)(proc->kstack + KSTACKSIZE) - 1;
    *(proc->tf) = *tf;
    proc->tf->tf_regs.reg_eax = 0;
    proc->tf->tf_esp = esp;
    proc->tf->tf_eflags |= FL_IF;

    proc->context.eip = (uintptr_t)forkret;
    proc->context.esp = (uintptr_t)(proc->tf);
}
```

可以看到新线程的eip被设置为`forkret`

```c
// forkret -- the first kernel entry point of a new thread/process
// NOTE: the addr of forkret is setted in copy_thread function
//       after switch_to, the current proc will execute here.
static void
forkret(void) {
    forkrets(current->tf);
}
```

`forkrets`以当前进程的tf为参数执行一下代码：

```assmebly
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

.globl forkrets
forkrets:
    # set stack to this new process's trapframe
    movl 4(%esp), %esp
    jmp __trapret
```

从tf恢复段寄存器和通用寄存器的值，并返回。而在`copu_thread`中将eax的值设置为了0。

所以，父进程的fork通过`do_fork`返回新创建进程的PID，而子进程跳转到`forkrets`通过`current->tf`恢复寄存器的值，返回0。由此，实现了一次调用返回两个不同的值。

# 练习3

**理解 proc_run 函数和它调用的函数如何完成进程切换的**

```c
// proc_run - make process "proc" running on cpu
// NOTE: before call switch_to, should load  base addr of "proc"'s new PDT
void
proc_run(struct proc_struct *proc) {
    if (proc != current) {
        bool intr_flag;
        struct proc_struct *prev = current, *next = proc;
        local_intr_save(intr_flag);
        {
            current = proc;
            load_esp0(next->kstack + KSTACKSIZE);
            lcr3(next->cr3);
            switch_to(&(prev->context), &(next->context));
        }
        local_intr_restore(intr_flag);
    }
}
```

在`swtich_to`之前，设置current、esp和页表寄存器cr3。这个调度过程不能被打断。
使用根据进程PCB中的context保存之前进程的上下文，恢复下一个进程的上下文。

```c
void
schedule(void) {
    bool intr_flag;
    list_entry_t *le, *last;
    struct proc_struct *next = NULL;
    local_intr_save(intr_flag);
    {
        current->need_resched = 0;
        last = (current == idleproc) ? &proc_list : &(current->list_link);
        le = last;
        do {
            if ((le = list_next(le)) != &proc_list) {
                next = le2proc(le, list_link);
                if (next->state == PROC_RUNNABLE) {
                    break;
                }
            }
        } while (le != last);
        if (next == NULL || next->state != PROC_RUNNABLE) {
            next = idleproc;
        }
        next->runs ++;
        if (next != current) {
            proc_run(next);
        }
    }
    local_intr_restore(intr_flag);
}
```

`proc_run`由`schedule`调用。它从进程链表中取出一个就绪态的进程调用`proc_run`。
在本实验的执行过程中，创建且运行了几个内核线程？

-   两个内核线程，分别是`idleproc`和`initproc`。
-   `idleproc`负责进程调度
-   `initproc`是之后所有新进程的祖先

语句`local_intr_save(intr_flag);....local_intr_restore(intr_flag);`在这里有何作用?请说明理由。

 -   这两句代码的作用分别是**阻塞中断**和**解除中断的阻塞**。
 -   这两句的配合，使得这两句代码之间的代码块形成**原子操作**，可以使得某些关键的代码不会被打断，从而避免引起一些未预料到的错误，避免条件竞争。
 -   以进程切换为例，在`proc_run`中，当刚设置好`current`指针为下一个进程，但还未完全将控制权转移时，如果该过程突然被一个中断所打断，则中断处理例程的执行可能会引发异常，因为`current`指针指向的进程与实际使用的进程资源不一致。

