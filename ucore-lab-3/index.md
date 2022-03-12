# uCore-lab-3


通过lab2知识的讲解，我们已经对虚拟内存有了一个初步认识，

有了内存地址虚拟化，我们就可以通过设置页表项来限定软件运行时的访问空间，确保软件运行不越界，完成内存访问保护的功能。

通过内存地址虚拟化，可以使得软件在没有访问某虚拟内存地址时不分配具体的物理内存，而只有在实际访问某虚拟内存地址时，操作系统再动态地分配物理内存，建立虚拟内存到物理内存的页映射关系，这种技术称为按需分页（demand paging）。

把不经常访问的数据所占的内存空间临时写到硬盘上，这样可以腾出更多的空闲内存空间给经常访问的数据；当CPU访问到不经常访问的数据时，再把这些数据从硬盘读入到内存中，这种技术称为页换入换出（page　swap in/out）。这种内存管理技术给了程序员更大的内存“空间”，从而可以让更多的程序在内存中并发运行。

需要注意的是：

- 虚拟内存单元不一定有实际的物理内存单元对应，即实际的物理内存单元可能不存在；
- 如果虚拟内存单元对应有实际的物理内存单元，那二者的地址一般是不相等的；
- 通过操作系统实现的某种内存映射可建立虚拟内存与物理内存的对应关系，使得程序员或CPU访问的虚拟内存地址会自动转换为一个物理内存地址。

# Page fault

产生页访问异常的原因主要有：

- 目标页帧不存在（页表项全为0，即该线性地址与物理地址尚未建立映射或者已经撤销)；
- 相应的物理页帧不在内存中（页表项非空，但Present标志位=0，比如在swap分区或磁盘文件上)，这在本次实验中会出现，我们将在下面介绍换页机制实现时进一步讲解如何处理；
- 不满足访问权限(此时页表项P标志=1，但低权限的程序试图访问高权限的地址空间，或者有程序试图写只读页面).

当出现上面情况之一，那么就会产生页面page fault（#PF）异常。CPU会把产生异常的线性地址存储在CR2中，并且把表示页访问异常类型的值（简称页访问异常错误码，errorCode）保存在中断栈中。

> 页访问异常错误码有32位。位0为１表示对应物理页不存在；位１为１表示写异常（比如写了只读页；位２为１表示访问权限异常（比如用户态程序访问内核空间的数据）
>
> CR2是页故障线性地址寄存器，保存最后一次出现页故障的全32位线性地址。CR2用于发生页异常时报告出错信息。当发生页异常时，处理器把引起页异常的线性地址保存在CR2中。操作系统中对应的中断服务例程可以检查CR2的内容，从而查出线性地址空间中的哪个页引起本次异常。

## uCore的处理

CPU在当前内核栈保存当前被打断的程序现场，即依次压入当前被打断程序使用的EFLAGS，CS，EIP，errorCode；由于页访问异常的中断号是0xE，CPU把异常中断号0xE对应的中断服务例程的地址（vectors.S中的标号vector14处）加载到CS和EIP寄存器中，开始执行中断服务例程。这时ucore开始处理异常中断，首先需要保存硬件没有保存的寄存器。在vectors.S中的标号vector14处先把中断号压入内核栈，然后再在trapentry.S中的标号`__alltraps`处把DS、ES和其他通用寄存器都压栈。自此，被打断的程序执行现场（context）被保存在内核栈中。接下来，在trap.c的trap函数开始了中断服务例程的处理流程，大致调用关系为：

> trap--> trap_dispatch-->pgfault_handler-->do_pgfault

下面需要具体分析一下`do_pgfault`函数。`do_pgfault`的调用关系如下图所示：

![image](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210620120536.png)

产生页访问异常后，CPU把引起页访问异常的线性地址装到寄存器CR2中，并给出了出错码errorCode，说明了页访问异常的类型。ucore OS会把这个值保存在`struct trapframe` 中`tf_err`成员变量中。而中断服务例程会调用页访问异常处理函数`do_pgfault`进行具体处理。这里的页访问异常处理是实现按需分页、页换入换出机制的关键之处。

ucore中`do_pgfaul`t函数是完成页访问异常处理的主要函数，它根据从CPU的控制寄存器CR2中获取的页访问异常的物理地址以及根据errorCode的错误类型来查找此地址是否在某个VMA的地址范围内以及是否满足正确的读写权限，如果在此范围内并且权限也正确，这认为这是一次合法访问，但没有建立虚实对应关系。所以需要分配一个空闲的内存页，并修改页表完成虚地址到物理地址的映射，刷新TLB，然后调用iret中断，返回到产生页访问异常的指令处重新执行此指令。如果该虚地址不在某VMA范围内，则认为是一次非法访问。

# 页替换

## 局部页面置换算法

> 置换页面的选择范围仅限于当前进程占用的物理页面内.

### 最优页面置换算法

最佳(Optimal, OPT)置换算法所选择的被淘汰页面将是以后永不使用的，或者是在最长时间内不再被访问的页面,这样可以保证获得最低的缺页率。但由于人们目前无法预知进程在内存下的若千页面中哪个是未来最长时间内不再被访问的，因而该算法无法实现。

可用作其他算法的评价的依据（在一个模拟器上运行某个程序，并记录每一次的页面的访问情况，在第二遍运行时间可使用最优算法）

### 最近最少用算法（LRU）

#### 简介

- 思路：选择**最长时间没有被引用**的页面进行置换。
- 实现：缺页时，计算内存中每个逻辑页面的上一个访问时间，并选择**上一个使用到当前时间最长**的页面。
- 特征：最优置换算法的一种近似。

#### b. 具体实现

- 页面链表
  - 系统维护一个按最近一次访问时间排序的页面链表
    - 链表首节点是最近刚刚使用过的页面
    - 链表尾结点是最久未使用的页面
  - 访问内存时，找到相应页面并将其移至链表之首
  - 缺页时，置换链表尾结点的页面
- 活动页面栈
  - 访问页面时，将此页号压入栈底。并将栈内相同的页号抽出
  - 缺页时，置换栈底的页面。

> 上述的两种实现都需要维护以及遍历搜索某个数据结构，
>
> 同时LRU对于过去的访问情况统计**过于细致**，所以该方法较为复杂。

### 先进先出算法（FIFO）

- 基本思路：选择在内存中驻留时间最长的页面并淘汰之。

  具体来说，系统维护着一个链表，记录了所有位于内存当中的逻辑页面。从链表的排列顺序来看，链首页面的驻留时间最长，链尾页面的驻留时间最短。当发生一个缺页中断时，把链表首页面淘汰出局，并把新的页面添加到链表的末尾。

- 性能较差，调出的页面有可能是经常要访问的页面，并且有Belady现象。FIFO算法很少单独使用。

- 实现：一个单一的指针就够了

### Belady现象

- 现象： 采用FIFO等算法时，可能出现分配的物理页面数增加，缺页次数反而升高的异常情况。
- 原因：
  - FIFO算法的置换特征与进程访问内存的动态特征矛盾
  - 被置换出去的页面并不一定是进程近期不会访问的。

LRU算法和FIFO本质上都是先进先出的思路，只不过LRU是针对页面的最近访问时间来进行排序，所以需要在每一次页面访问的时候动态的调整各个页面之间的先后顺序（有一个页面的最近访问时间变了）；

而FIFO是针对页面进入内存的时间来进行排序。这个时间是固定不变的，所以各页面之间的先后顺序是固定的。如果一个页面在进入内存之后没有被访问，那么它的最近访问时间就是它进入内存的时间。

换句话说，如果内存当中的所有页面都未曾访问过，那么LRU就退化为FIFO算法。

### 改进的时钟页面置换算法（Clock）

#### 简介

- 思路：
  - 仅对页面的访问情况进行大致统计
  - 减小修改页的缺页处理开销
- 数据结构：
  - 在页表项中增加访问位，描述页面在过去一段时间的内访问情况。
  - 在页表项中增加修改位，以判断当前页面是否修改过但没有存入外存。
  - 各页面组织成环形链表，同时指针指向最先调入的页面。
- 算法
  - 访问页面时，在页表项记录页面访问情况
  - 缺页时，从指针处开始顺序查找**未被访问与未被修改**的页面进行置换。
- 特征： 时钟算法是LRU与FIFO的折中。

#### 具体实现

- 页面装入内存时，访问位初始化为0
- 访问页面（读/写）时，访问位置为1
- 缺页时，从指针当前位置顺序检查环形链表。
  - 若当前遍历到的页面访问位为0，则**置换该页**
  - 若当前遍历到的页面访问位为1，则**设置该页的访问位为0**，并移动指针到下一个页面，直到找到可置换的页面。

## 全局置换算法

- 思路：全局置换算法为进程分配可变数目的物理页面。
- 要解决的问题：
  - 进程在不同阶段的内存需求是有变化的。
  - 分配给进程的内存也需要在不同阶段有所变化。
  - 全局置换算法需要确定分配给进程的物理页面数。
- CPU利用率与并发进程数存在相互制约的关系。
  - 进程数少时，提高并发进程数，可提高CPU利用效率。
  - 并发进程导致内存访问增加
  - 并发进程的内存访问会降低了访存的局部性特征。
  - 局部性特征的下降会导致缺页率上升和CPU利用率下降。

全局页面置换算法置换内存中所有可换出的物理页面，即换进内存的是进程A的页面，换出内存的可能是进程B的页面，所以进程在内存中占用的页面总数是可变的。

### 工作集置换算法

#### 工作集与常驻集

- 工作集

  是一个进程当前正在使用的逻辑页面集合，可表示为二元函数W(t,Δ)W(t,Δ)

  - tt是当前的执行时刻
  - Δ 称为**工作集窗口**(working-set window)，即一个定长的页面访问时间的窗口。
  - W(t,Δ)W(t,Δ)指在当前时刻tt前的Δ时间窗口中的**所有访问页面**所组成的集合。
  - |W(t,Δ)||W(t,Δ)|指工作集的大小，即页面数目。
  
- **常驻集**是当前时刻进程**实际驻留**在内存中的页面集合。

- 工作集与常驻集的关系

  - 工作集是进程在运行过程中固有的性质
  - 常驻集取决于系统分配给进程的物理页面数目和页面置换算法。

#### 思路

- 当前时刻前ττ个内存访问的页引用是工作集。其中ττ被称为**窗口大小**。
- 换出不在工作集中的页面

#### 具体实现

- 访存链表：维护窗口内的访存页面
- **访存时，换出不在工作集的页面；** 更新访存链表。
- 缺页时，换入页面，更新访存链表。

### 缺页率置换算法（PPF）

#### 简介

通过调节常驻集大小，使每个进程的缺页率保持在一个合理的范围内。

- 若进程缺页率过高，则增加常驻集以分配更多的物理内存
- 若进程缺页率过低，则减小常驻集以减小它的物理页面数。

#### 具体实现

- 访存时，设置引用位标志
- 缺页时，计算从上次缺页时间$t_{last}$到现在$t_{current}$的时间间隔
  - 如果$t_{current}−t_{last}>T$，则置换所有在$[t_{last},t_{current}]$时间内**没有被引用**的页。
  - 如果$t_{current}−t_{last}<T$，则增加缺失页到常驻集中。

### 抖动问题（thrashing）

如果分配给一个进程的物理页面太少，不能包含整个的工作集，即常驻集属于工作集，那么进程将会造成很多的页面中断，需要频繁的在内存和外存之间替换页面，从而使进程的运行速度变得很慢，这种状态称为抖动。

产生抖动的原因：随着驻留内存的进程数目增加，分配给每个进程的物理页面数不断减小，缺页率不断上升。所以操作系统要选择一个适当的进程数目和进程所需要的帧数，以便在并发水平和缺页率之间达到一个平衡。

# 练习1
**给未被映射的地址映射上物理页**
注意发生`page falut`的两种情况：
- 物理页未被映射，页表项为空
- 页表项不为空，对应的物理页面被换出到swap

```c
    /*LAB3 EXERCISE 1: YOUR CODE*/
    //(1) try to find a pte, if pte's PT(Page Table) isn't existed, then create a PT.
    if((ptep = get_pte(mm->pgdir, addr, 1)) == NULL)              
    {
        cprintf("get_pte in do_pgfalut failed\n");
        goto failed;
    }
    if (*ptep == 0) {
        //(2) if the phy addr isn't exist, then alloc a page & map the phy addr with logical addr
        if(pgdir_alloc_page(mm->pgdir, addr, perm) == NULL) {                    
            cprintf("pgdir_alloc_page in do_pgfalut failed\n");
            goto failed;
        }        
    }
    else {
    /*LAB3 EXERCISE 2: YOUR CODE
    * Now we think this pte is a swap entry, we should load data from disk to a page with phy addr,
    * and map the phy addr with logical addr, trigger swap manager to record the access situation of this page.
    *
    *  Some Useful MACROs and DEFINEs, you can use them in below implementation.
    *  MACROs or Functions:
    *    swap_in(mm, addr, &page) : alloc a memory page, then according to the swap entry in PTE for addr,
    *                               find the addr of disk page, read the content of disk page into this memroy page
    *    page_insert ： build the map of phy addr of an Page with the linear addr la
    *    swap_map_swappable ： set the page swappable
    */

        if(swap_init_ok) {
            struct Page *page = NULL;
            //(1）According to the mm AND addr, try to load the content of right disk page
            //    into the memory which page managed.
            if((ret = swap_in(mm, addr, &page)) != 0)
            {
                cprintf("swap_in in do_pgfalut failed\n");
                goto failed;
            }
            //(2) According to the mm, addr AND page, setup the map of phy addr <---> logical addr
            page_insert(mm->pgdir, page, addr, perm);
            //(3) make the page swappable.
            swap_map_swappable(mm, addr, page, 1);
            page->pra_vaddr = addr;
        }
        else {
            cprintf("no swap_init_ok but ptep is %x, failed\n", *ptep);
            goto failed;
        }
   }
```
# 练习2
**补充完成基于FIFO的页面替换算法**

FIFO的PRA维护了一个链表，链表中的页按照从旧（驻留时间最长）到新（最近驻留）的顺序排列。

所以在换入一个页面时，需要将其加入到链表的尾部。换出时，只要将链表头指向的页换出。
```c
static int
_fifo_map_swappable(struct mm_struct *mm, uintptr_t addr, struct Page *page, int swap_in)
{
    list_entry_t *head=(list_entry_t*) mm->sm_priv;
    list_entry_t *entry=&(page->pra_page_link);
 
    assert(entry != NULL && head != NULL);
    //record the page access situlation
    /*LAB3 EXERCISE 2: YOUR CODE*/ 
    //(1)link the most recent arrival page at the back of the pra_list_head qeueue.
    list_add(head->prev, entry);
    
    return 0;
}

static int
_fifo_swap_out_victim(struct mm_struct *mm, struct Page ** ptr_page, int in_tick)
{
    list_entry_t *head=(list_entry_t*) mm->sm_priv;
        assert(head != NULL);
    assert(in_tick==0);
    /* Select the victim */
    /*LAB3 EXERCISE 2: YOUR CODE*/ 
    //(1)  unlink the  earliest arrival page in front of pra_list_head qeueue
    //(2)  assign the value of *ptr_page to the addr of this page
    list_entry_t *le = head->next;
    struct Page *p = le2page(le, pra_page_link);
    list_del(le);
    *ptr_page = p;
    return 0;
}
```
