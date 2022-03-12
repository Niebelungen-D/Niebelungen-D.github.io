# UCore Lab 2


在正式开始写代码之前，我们先看看，整个内存管理的框架

参考：[内存管理迷雾](https://jishuin.proginn.com/p/763bfbd248c0)

<!--more-->

# 虚拟内存

在虚拟地址产生之前，cpu中使用的都是物理地址。所有的程序面对的都是主存的那块空间。这造成了一个问题，如果两个程序之间共享了一块物理内存空间，这两个程序就会相互影响。无论那块区域存放的是什么，被修改之后，就极有可能造成程序的崩溃。这样根本无法运行多个程序。

这里关键的问题是这两个程序都引用了绝对物理地址，而这正是我们最需要避免的。

我们可以把进程所使用的地址隔离开来，即让操作系统为每个进程分配独立的一套虚拟地址，每个进程面对的同样大小的虚拟内存空间，但所对应的物理地址不同。

如果程序要访问虚拟地址的时候，由操作系统转换成不同的物理地址，这样不同的进程运行的时候，写入的是不同的物理地址，这样就不会冲突了。

于是，这里就引出了两种地址的概念：

- 我们程序所使用的内存地址叫做**虚拟内存地址**（*Virtual Memory Address*）
- 实际存在硬件里面的空间地址叫**物理内存地址**（*Physical Memory Address*）。

操作系统引入了虚拟内存，进程持有的虚拟地址会通过 CPU 芯片中的内存管理单元（MMU）的映射关系，来转换变成物理地址，然后再通过物理地址访问内存，如下图所示：

![](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210614010408.webp)

# 内存分段

程序是由若干个逻辑分段组成的，如可由代码分段、数据分段、栈段、堆段组成。不同的段是有不同的属性的，所以就用分段（Segmentation）的形式把这些段分离出来。

关于分段的映射我们在lab1中说过，是通过段选择子和偏移得到物理地址的。现在我们知道了虚拟地址是通过段表与物理地址进行映射的，分段机制会把程序的虚拟地址分成 4 个段，每个段在段表中有一个项，在这一项找到段的基地址，再加上偏移量，于是就能找到物理内存中的地址，如下图：

![](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210614011409.webp)

分段的办法很好，解决了程序本身不需要关心具体的物理内存地址的问题，但它也有一些不足之处：

- 第一个就是**内存碎片**的问题。
- 第二个就是**内存交换的效率低**的问题。

## 内存碎片

我们来看看这样一个例子。假设有 1G 的物理内存，用户执行了多个程序，其中：

- 游戏占用了 512MB 内存
- 浏览器占用了 128MB 内存
- 音乐占用了 256 MB 内存。

这个时候，如果我们关闭了浏览器，则空闲内存还有 1024 - 512 - 256 = 256MB。如果这个 256MB 不是连续的，被分成了两段 128 MB 内存，这就会导致没有空间再打开一个 200MB 的程序。

![](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210614011629.webp)

内存碎片的问题这里的内存碎片的问题共有两处地方：

- 外部内存碎片，也就是产生了多个不连续的小物理内存，导致新的程序无法被装载；
- 内部内存碎片，程序所有的内存都被装载到了物理内存，但是这个程序有部分的内存可能并不是很常使用，这也会导致内存的浪费；

针对上面两种内存碎片的问题，解决的方式会有所不同。解决外部内存碎片的问题就是**内存交换**。可以把音乐程序占用的那 256MB 内存写到硬盘上，然后再从硬盘上读回来到内存里。不过再读回的时候，我们不能装载回原来的位置，而是紧紧跟着那已经被占用了的 512MB 内存后面。这样就能空缺出连续的 256MB 空间，于是新的 200MB 程序就可以装载进来。这个内存交换空间，在 Linux 系统里，也就是我们常看到的 Swap 空间，这块空间是从硬盘划分出来的，用于内存与硬盘的空间交换。

## 内存交换效率

对于多进程的系统来说，用分段的方式，内存碎片是很容易产生的，产生了内存碎片，那不得不重新 `Swap` 内存区域，这个过程会产生性能瓶颈。因为硬盘的访问速度要比内存慢太多了，每一次内存交换，我们都需要把一大段连续的内存数据写到硬盘上。所以，如果内存交换的时候，交换的是一个占内存空间很大的程序，这样整个机器都会显得卡顿。为了解决内存分段的内存碎片和内存交换效率低的问题，就出现了内存分页。

# 内存分页

分段的好处就是能产生连续的内存空间，但是会出现内存碎片和内存交换的空间太大的问题。要解决这些问题，那么就要想出能少出现一些内存碎片的办法。另外，当需要进行内存交换的时候，让需要交换写入或者从磁盘装载的数据更少一点，这样就可以解决问题了。这个办法，也就是**内存分页**（*Paging*）。分页是把整个虚拟和物理内存空间切成一段段固定尺寸的大小。这样一个连续并且尺寸固定的内存空间，我们叫**页**（*Page*）。在 Linux 下，每一页的大小为 `4KB`。虚拟地址与物理地址之间通过**页表**来映射，如下图：

![](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20210614011925.webp)

内存映射页表实际上存储在 CPU 的**内存管理单元** （*MMU*) 中，于是 CPU 就可以直接通过 MMU，找出要实际要访问的物理内存地址。而当进程访问的虚拟地址在页表中查不到时，系统会产生一个**缺页异常**，进入系统内核空间分配物理内存、更新进程页表，最后再返回用户空间，恢复进程的运行。

> 分页是怎么解决分段的内存碎片、内存交换效率低的问题？

由于内存空间都是预先划分好的，也就不会像分段会产生间隙非常小的内存，这正是分段会产生内存碎片的原因。而**采用了分页，那么释放的内存都是以页为单位释放的，也就不会产生无法给进程使用的小内存。**如果内存空间不够，操作系统会把其他正在运行的进程中的「最近没被使用」的内存页面给释放掉，也就是暂时写在硬盘上，称为**换出**（*Swap Out*）。一旦需要的时候，再加载进来，称为**换入**（*Swap In*）。所以，一次性写入磁盘的也只有少数的一个页或者几个页，不会花太多时间，**内存交换的效率就相对比较高。**

![](https://filescdn.proginn.com/42b29acc6b942673c6a9fde72d5d7ad9/d038971eea97e8a598de6b71dda59c55.webp)

换入换出更进一步地，分页的方式使得我们在加载程序的时候，不再需要一次性都把程序加载到物理内存中。我们完全可以在进行虚拟内存和物理内存的页之间的映射之后，并不真的把页加载到物理内存里，而是**只有在程序运行中，需要用到对应虚拟内存页里面的指令和数据时，再加载到物理内存里面去。**

## 分页机制下虚拟地址和物理地址的映射

在分页机制下，虚拟地址分为两部分，**页号**和**页内偏移**。页号作为页表的索引，**页表**包含物理页每页所在**物理内存的基地址**，这个基地址与页内偏移的组合就形成了物理内存地址，见下图。

![](https://filescdn.proginn.com/000a32bafcf1f4efbbf4ef1d4baabf42/f1c6099a8417248b935d6de406d80f1e.webp)

内存分页寻址总结一下，对于一个内存地址转换，其实就是这样三个步骤：

- 把虚拟内存地址，切分成页号和偏移量；
- 根据页号，从页表里面，查询对应的物理页号；
- 直接拿物理页号，加上前面的偏移量，就得到了物理内存地址。

下面举个例子，虚拟内存中的页通过页表映射为了物理内存中的页，如下图：

![](https://filescdn.proginn.com/458d67e16cb613758ef2cabc567fba0d/2a708dadfafd95f0b6f62a334221c023.webp)

虚拟页与物理页的映射这看起来似乎没什么毛病，但是放到实际中操作系统，这种简单的分页是肯定是会有问题的。

## 分页的缺陷

有空间上的缺陷。因为操作系统是可以同时运行非常多的进程的，那这不就意味着页表会非常的庞大。在 32 位的环境下，虚拟地址空间共有 4GB，假设一个页的大小是 4KB（2^12），那么就需要大约 100 万 （2^20） 个页，每个「页表项」需要 4 个字节大小来存储，那么整个 4GB 空间的映射就需要有 `4MB` 的内存来存储页表。这 4MB 大小的页表，看起来也不是很大。但是要知道每个进程都是有自己的虚拟地址空间的，也就说都有自己的页表。那么，`100` 个进程的话，就需要 `400MB` 的内存来存储页表，这是非常大的内存了，更别说 64 位的环境了。

## 多级页表

要解决上面的问题，就需要采用的是一种叫作**多级页表**（Multi-Level Page Table）的解决方案。在前面我们知道了，对于单页表的实现方式，在 32 位和页大小 `4KB` 的环境下，一个进程的页表需要装下 100 多万个「页表项」，并且每个页表项是占用 4 字节大小的，于是相当于每个页表需占用 4MB 大小的空间。我们把这个 100 多万个「页表项」的单级页表再分页，将页表（一级页表）分为 `1024` 个页表（二级页表），每个表（二级页表）中包含 `1024` 个「页表项」，形成**二级分页**。如下图所示：

![7eed3de6ba39047cef23e556d22dd905.webp](https://filescdn.proginn.com/d99d544f15a0decd70b7b28192843407/7eed3de6ba39047cef23e556d22dd905.webp)

**你可能会问，分了二级表，映射 4GB 地址空间就需要 4KB（一级页表）+ 4MB（二级页表）的内存，这样占用空间不是更大了吗？**

当然如果 4GB 的虚拟地址全部都映射到了物理内上的，二级分页占用空间确实是更大了，但是，我们往往不会为一个进程分配那么多内存。其实我们应该换个角度来看问题，还记得计算机组成原理里面无处不在的**局部性原理**么？每个进程都有 4GB 的虚拟地址空间，而显然对于大多数程序来说，其使用到的空间远未达到 4GB，因为会存在部分对应的页表项都是空的，根本没有分配，对于已分配的页表项，如果存在最近一定时间未访问的页表，在物理内存紧张的情况下，操作系统会将页面换出到硬盘，也就是说不会占用物理内存。如果使用了二级分页，一级页表就可以覆盖整个 4GB 虚拟地址空间，但**如果某个一级页表的页表项没有被用到，也就不需要创建这个页表项对应的二级页表了，即可以在需要时才创建二级页表**。做个简单的计算，假设只有 20% 的一级页表项被用到了，那么页表占用的内存空间就只有 4KB（一级页表） + 20% * 4MB（二级页表）= `0.804MB`，这对比单级页表的 `4MB` 是不是一个巨大的节约？那么为什么不分级的页表就做不到这样节约内存呢？我们从页表的性质来看，保存在内存中的页表承担的职责是将虚拟地址翻译成物理地址。假如虚拟地址在页表中找不到对应的页表项，计算机系统就不能工作了。所以**页表一定要覆盖全部虚拟地址空间，不分级的页表就需要有 100 多万个页表项来映射，而二级分页则只需要 1024 个页表项**（此时一级页表覆盖到了全部虚拟地址空间，二级页表在需要时创建）。我们把二级分页再推广到多级页表，就会发现页表占用的内存空间更少了，这一切都要归功于对局部性原理的充分应用。对于 64 位的系统，两级分页肯定不够了，就变成了四级目录，分别是：

- 全局页目录项 PGD（Page Global Directory）；
- 上层页目录项 PUD（Page Upper Directory）；
- 中间页目录项 PMD（Page Middle Directory）；
- 页表项 PTE（Page Table Entry）；


![](https://filescdn.proginn.com/58874e400c0c8b36e344f430efdeb4dd/539b58702b9718caca85a9c5f634a471.webp)

## TLB

多级页表虽然解决了空间上的问题，但是虚拟地址到物理地址的转换就多了几道转换的工序，这显然就降低了这俩地址转换的速度，也就是带来了时间上的开销。程序是有局部性的，即在一段时间内，整个程序的执行仅限于程序中的某一部分。相应地，执行所访问的存储空间也局限于某个内存区域。

![](https://filescdn.proginn.com/ac414fbee9d8dc201589e56768383824/ad1705993fd49a31f1d9d4a4c0e29b1c.webp)

程序的局部性我们就可以利用这一特性，把最常访问的几个页表项存储到访问速度更快的硬件，于是计算机科学家们，就在 CPU 芯片中，加入了一个专门存放程序最常访问的页表项的 Cache，这个 Cache 就是 TLB（Translation Lookaside Buffer） ，通常称为页表缓存、转址旁路缓存、快表等。

![](https://filescdn.proginn.com/37909023bf8ff3a158595707d720be21/514601902c0745134f593e2437759bd9.webp)

地址转换在 CPU 芯片里面，封装了内存管理单元（Memory Management Unit）芯片，它用来完成地址转换和 TLB 的访问与交互。有了 TLB 后，那么 CPU 在寻址时，会先查 TLB，如果没找到，才会继续查常规的页表。TLB 的命中率其实是很高的，因为程序最常访问的页就那么几个。

------

# 段页式内存管理

内存分段和内存分页并不是对立的，它们是可以组合起来在同一个系统中使用的，那么组合起来后，通常称为**段页式内存管理**。

![](https://filescdn.proginn.com/d934905aadcfbc076386ca9378b00a20/6bc2b842e39f002badb1552342394f98.webp)

段页式地址空间段页式内存管理实现的方式：

- 先将程序划分为多个有逻辑意义的段，也就是前面提到的分段机制；
- 接着再把每个段划分为多个页，也就是对分段划分出来的连续空间，再划分固定大小的页；

这样，地址结构就由**段号、段内页号和页内位移**三部分组成。用于段页式地址变换的数据结构是每一个程序一张段表，每个段又建立一张页表，段表中的地址是页表的起始地址，而页表中的地址则为某页的物理页号，如图所示：

![](https://filescdn.proginn.com/0515890face19fce8c14f08bbe2c8456/16c67c839c5ccb9a1ddf5bf05b5f36ab.webp)

段页式管理中的段表、页表与内存的关系段页式地址变换中要得到物理地址须经过三次内存访问：

- 第一次访问段表，得到页表起始地址；
- 第二次访问页表，得到物理页号；
- 第三次将物理页号与页内位移组合，得到物理地址。

可用软、硬件相结合的方法实现段页式地址变换，这样虽然增加了硬件成本和系统开销，但提高了内存的利用率。

# Linux 内存管理

那么，Linux 操作系统采用了哪种方式来管理内存呢？

在回答这个问题前，我们得先看看 Intel 处理器的发展历史。

早期 Intel 的处理器从 80286 开始使用的是段式内存管理。但是很快发现，光有段式内存管理而没有页式内存管理是不够的，这会使它的 X86 系列会失去市场的竞争力。因此，在不久以后的 80386 中就实现了对页式内存管理。也就是说，80386 除了完成并完善从 80286 开始的段式内存管理的同时还实现了页式内存管理。但是这个 80386 的页式内存管理设计时，没有绕开段式内存管理，而是建立在段式内存管理的基础上，这就意味着，**页式内存管理的作用是在由段式内存管理所映射而成的的地址上再加上一层地址映射。**由于此时段式内存管理映射而成的地址不再是“物理地址”了，Intel 就称之为“线性地址”（也称虚拟地址）。于是，段式内存管理先将逻辑地址映射成线性地址，然后再由页式内存管理将线性地址映射成物理地址。

![](https://filescdn.proginn.com/1d65bf652e7749b299e9b4b6838e3c67/9ccebef28964377c3f7dae7a3f854e43.webp)

Intel X86 逻辑地址解析过程这里说明下逻辑地址和线性地址：

- 程序所使用的地址，通常是没被段式内存管理映射的地址，称为逻辑地址；
- 通过段式内存管理映射的地址，称为线性地址，也叫虚拟地址；

逻辑地址是「段式内存管理」转换前的地址，线性地址则是「页式内存管理」转换前的地址。

**Linux 内存主要采用的是页式内存管理，但同时也不可避免地涉及了段机制**。这主要是上面 Intel 处理器发展历史导致的，因为 Intel X86 CPU 一律对程序中使用的地址先进行段式映射，然后才能进行页式映射。既然 CPU 的硬件结构是这样，Linux 内核也只好服从 Intel 的选择。但是事实上，Linux 内核所采取的办法是使段式映射的过程实际上不起什么作用。也就是说，“上有政策，下有对策”，若惹不起就躲着走。**Linux 系统中的每个段都是从 0 地址开始的整个 4GB 虚拟空间（32 位环境下），也就是所有的段的起始地址都是一样的。这意味着，Linux 系统中的代码，包括操作系统本身的代码和应用程序代码，所面对的地址空间都是线性地址空间（虚拟地址），这种做法相当于屏蔽了处理器中的逻辑地址概念，段只被用于访问控制和内存保护。**

### Linux 的虚拟地址空间分布？

在 Linux 操作系统中，虚拟地址空间的内部又被分为**内核空间和用户空间**两部分，不同位数的系统，地址空间的范围也不同。比如最常见的 32 位和 64 位系统，如下所示：

![](https://filescdn.proginn.com/2dd7d3b26dc0bcdffd28ef2c328cc595/f40c149fa8eee75cf19b355f9a55afea.webp)

用户空间与内存空间通过这里可以看出：

- `32` 位系统的内核空间占用 `1G`，位于最高处，剩下的 `3G` 是用户空间；
- `64` 位系统的内核空间和用户空间都是 `128T`，分别占据整个内存空间的最高和最低处，剩下的中间部分是未定义的。

再来说说，内核空间与用户空间的区别：

- 进程在用户态时，只能访问用户空间内存；
- 只有进入内核态后，才可以访问内核空间的内存；

虽然每个进程都各自有独立的虚拟内存，但是**每个虚拟内存中的内核地址，其实关联的都是相同的物理内存**。这样，进程切换到内核态后，就可以很方便地访问内核空间内存。

![](https://filescdn.proginn.com/2e7b7360c363c03411571ec738ff7be5/51b7cc6cfd05a32cb47146c5e34955f8.webp)

每个进程的内核空间都是一致的接下来，进一步了解虚拟空间的划分情况，用户空间和内核空间划分的方式是不同的，内核空间的分布情况就不多说了。我们看看用户空间分布的情况，以 32 位系统为例：

![](https://filescdn.proginn.com/d5be4dfe743a10ff5aaa84ebbdf2d04c/36cb3bd975aec1849407dae3640c8abe.webp)

虚拟内存空间划分通过这张图你可以看到，用户空间内存，从**低到高**分别是 7 种不同的内存段：

- 程序文件段，包括二进制可执行代码；
- 已初始化数据段，包括静态常量；
- 未初始化数据段，包括未初始化的静态变量；
- 堆段，包括动态分配的内存，从低地址开始向上增长；
- 文件映射段，包括动态库、共享内存等，从低地址开始向上增长（跟硬件和内核版本有关）
- 栈段，包括局部变量和函数调用的上下文等。栈的大小是固定的，一般是 `8 MB`。当然系统也提供了参数，以便我们自定义大小；

在这 7 个内存段中，堆和文件映射段的内存是动态分配的。比如说，使用 C 标准库的 `malloc()` 或者 `mmap()` ，就可以分别在堆和文件映射段动态分配内存。

# uCore物理内存探测

当操作系统被启动之后，最重要的事情就是知道还有多少内存可用，一般来说，获取内存大小的方法由 BIOS 中断调用和直接探测两种。但BIOS 中断调用方法是一般只能在实模式下完成，而直接探测方法必须在保护模式下完成。通过 BIOS 中断获取内存布局有三种方式，都是基于`int 15h`中断，分别为`88h`, `e801h`, `e820h`。但是并非在所有情况下这三种方式都能工作。在 Linux kernel 里，采用的方法是依次尝试这三 种方法。而在本实验中，我们通过e820h中断获取内存信息。因为e820h中断必须在实模式下使用，所以我们在 bootloader 进入保护模式之前调用这个 BIOS 中断，并且把 e820 映射结构保存在物理地址0x8000处。

BIOS通过系统内存映射地址描述符（Address Range Descriptor）格式来表示系统物理内存布局，其具体表示如下：

```c
Offset  Size    Description
00h    8字节   base address               #系统内存块基地址
08h    8字节   length in bytes            #系统内存大小
10h    4字节   type of address range     	#内存类型
```

INT15h BIOS中断的详细调用参数:

```
eax：e820h：INT 15的中断调用参数；
edx：534D4150h (即4个ASCII字符“SMAP”) ，这只是一个签名而已；
ebx：如果是第一次调用或内存区域扫描完毕，则为0。 如果不是，则存放上次调用之后的计数值；
ecx：保存地址范围描述符的内存大小,应该大于等于20字节；
es:di：指向保存地址范围描述符结构的缓冲区，BIOS把信息写入这个结构的起始地址。
```

此中断的返回值为:

```
cflags的CF位：若INT 15中断执行成功，则不置位，否则置位；
eax：534D4150h ('SMAP') ；
es:di：指向保存地址范围描述符的缓冲区,此时缓冲区内的数据已由BIOS填写完毕
ebx：下一个地址范围描述符的计数地址
ecx：返回BIOS往ES:DI处写的地址范围描述符的字节大小
ah：失败时保存出错代码
```

这样，我们通过调用INT 15h BIOS中断，递增di的值（20的倍数），让BIOS帮我们查找出一个一个的内存布局entry，并放入到一个保存地址范围描述符结构的缓冲区中，供后续的ucore进一步进行物理内存管理。这个缓冲区结构定义在memlayout.h中：

```c
struct e820map {	//  e820 映射结构保存在物理地址0x8000处
    int nr_map;		// map中的元素个数
    struct {
        uint64_t addr;		// 内存块的起始地址
        uint64_t size;		// 内存块的大小
        uint32_t type;		// 内存块的类型，1标识可被使用内存块；2表示保留的内存块，不可映射。
    } __attribute__((packed)) map[E820MAX];
};
```

这样就在`bootmain.S`中新增了一段代码：

```assembly
probe_memory:
    movl $0, 0x8000			;首先，设置`nr_map = 0`
    xorl %ebx, %ebx			;int 15h的参数，第一次调用置为0
    movw $0x8004, %di		;rdi置为第一块map结构的起始地址
start_probe:
    movl $0xE820, %eax		;中断调用参数，赋值给eax
    movl $20, %ecx			;保存地址范围描述符的内存大小
    movl $SMAP, %edx		;签名“SMAP”
    int $0x15				;调用中断
    jnc cont				;如果eflags的CF位为0，则表示还有内存段需要探测，如果该中断执行失败，则CF标志位会置1
    movw $12345, 0x8000		 ;探测有问题，向结构e820map中的成员nr_map中写入特殊信息，结束探测
    jmp finish_probe
cont:
    addw $20, %di			;如果中断执行正常，则目标写入地址就向后移动一个位置+20字节
    incl 0x8000				;`nr_map++`
    cmpl $0, %ebx			;执行中断后，返回的ebx是原先的ebx加一。如果ebx为0，则说明当前内存探测完成
    jnz start_probe
finish_probe:
```

上述代码正常执行完毕后，在0x8000地址处保存了从BIOS中获得的内存分布信息，此信息按照struct e820map的设置来进行填充。这部分信息将在bootloader启动ucore后，由ucore的`page_init`函数来根据struct e820map的`memmap`（定义了起始地址为0x8000）来完成对整个机器中的物理内存的总体管理。

# uCore物理页管理

在获得可用物理内存范围后，系统需要建立相应的数据结构来管理以物理页为最小单位的整个物理内存，以配合后续涉及的分页管理机制。每个物理页可以用一个 Page数据结构来表示。由于一个物理页需要占用一个Page结构的空间，Page结构在设计时须尽可能小，以减少对内存的占用。Page的定义在kern/mm/memlayout.h中。以页为单位的物理内存分配管理的实现在kern/default_pmm.[ch]。

为了与以后的分页机制配合，我们首先需要建立对整个计算机的每一个物理页的属性用结构Page来表示，它包含了映射此物理页的虚拟页个数，描述物理页属性的flags和双向链接各个Page结构的page_link双向链表。

```c
struct Page {
    int ref;        		// page frame's reference counter
    uint32_t flags; 		// array of flags that describe the status of the page frame
    unsigned int property;	// the num of free block, used in first fit pm manager
    list_entry_t page_link;	// free list link
};
```

- ref表示这个页被页表的引用记数。如果这个页被页表引用了，即在某页表中有一个页表项设置了一个虚拟页到这个Page管理的物理页的映射关系，就会把Page的ref加一；反之，若页表项取消，即映射关系解除，就会把Page的ref减一。
- flags表示此物理页的状态标记，进一步查看kern/mm/memlayout.h中的定义，可以看到：

    ```c
    /* Flags describing the status of a page frame */
    #define PG_reserved                 0       // the page descriptor is reserved for kernel or unusable
    #define PG_property                 1       // the member 'property' is valid
    ```
    
    这表示flags目前用到了两个bit表示页目前具有的两种属性，bit 0表示此页是否被保留（reserved），如果是被保留的页，则bit 0会设置为1，且不能放到空闲页链表中，即这样的页不是空闲页，不能动态分配与释放。比如目前内核代码占用的空间就属于这样“被保留”的页。在本实验中，bit 1表示此页是否是free的，如果设置为1，表示这页是free的，可以被分配；如果设置为0，表示这页已经被分配出去了，不能再被二次分配。

- 在本实验中，Page数据结构的成员变量`property`用来记录某连续内存空闲块的大小（即地址连续的空闲页的个数）。这里需要注意的是用到此成员变量的这个Page比较特殊，是这个连续内存空闲块地址最小的一页（即头一页， Head Page）。连续内存空闲块利用这个页的成员变量property来记录在此块内的空闲页的个数。

为了有效地管理这些小连续内存空闲块。所有的连续内存空闲块可用一个双向链表管理起来，便于分配和释放，为此定义了一个free_area_t数据结构，包含了一个`list_entry`结构的双向链表指针和记录当前空闲页的个数的无符号整型变量`nr_free`。其中的链表指针指向了空闲的物理页。

```c
/* free_area_t - maintains a doubly linked list to record free (unused) pages */
typedef struct {
            list_entry_t free_list;                                // the list header
            unsigned int nr_free;                                 // # of free pages in this free list
} free_area_t;
```

有了这两个数据结构，ucore就可以管理起来整个以页为单位的物理内存空间。接下来需要解决两个问题：

- 管理页级物理内存空间所需的Page结构的内存空间从哪里开始，占多大空间？
- 空闲内存空间的起始地址在哪里？

对于这两个问题，我们首先根据bootloader给出的内存布局信息找出最大的物理内存地址`maxpa`（定义在page_init函数中的局部变量），由于x86的起始物理内存地址为0，所以可以得知需要管理的物理页个数为

```c
npage = maxpa / PGSIZE
```

这样，我们就可以预估出管理页级物理内存空间所需的Page结构的内存空间所需的内存大小为：

```c
sizeof(struct Page) * npage)
```

由于bootloader加载ucore的结束地址（用全局指针变量end记录）以上的空间没有被使用，所以我们可以把end按页大小为边界向上取整后，作为管理页级物理内存空间所需的Page结构的内存空间，记为：

```c
pages = (struct Page *)ROUNDUP((void *)end, PGSIZE);
```

为了简化起见，从地址0到地址`pages+ sizeof(struct Page) * npage)`结束的物理内存空间设定为已占用物理内存空间（起始0~640KB的空间是空闲的），地址`pages+ sizeof(struct Page) * npage)`以上的空间为空闲物理内存空间，这时的空闲空间起始地址为

```c
uintptr_t freemem = PADDR((uintptr_t)pages + sizeof(struct Page) * npage);
```

为此我们需要把这两部分空间给标识出来。首先，对于所有物理空间，通过如下语句即可实现占用标记：

```c
for (i = 0; i < npage; i ++) {
	SetPageReserved(pages + i);
}
```

然后，根据探测到的空闲物理空间，通过如下语句即可实现空闲标记：

```c
//获得空闲空间的起始地址begin和结束地址end
……
init_memmap(pa2page(begin), (end - begin) / PGSIZE);
```

其实`SetPageReserved`只需把物理地址对应的Page结构中的flags标志设置为`PG_reserved` ，表示这些页已经被使用了，将来不能被用于分配。而`init_memmap`函数则是把空闲物理页对应的Page结构中的flags和引用计数ref清零，并加到`free_area.free_list`指向的双向列表中，为将来的空闲页管理做好初始化准备工作。

其实实验二在内存分配和释放方面最主要的作用是建立了一个物理内存页管理器框架，这实际上是一个函数指针列表，定义如下：

```c
struct pmm_manager {
            const char *name; //物理内存页管理器的名字
            void (*init)(void); //初始化内存管理器
            void (*init_memmap)(struct Page *base, size_t n); //初始化管理空闲内存页的数据结构
            struct Page *(*alloc_pages)(size_t n); //分配n个物理内存页
            void (*free_pages)(struct Page *base, size_t n); //释放n个物理内存页
            size_t (*nr_free_pages)(void); //返回当前剩余的空闲页数
            void (*check)(void); //用于检测分配/释放实现是否正确的辅助函数
};
```

重点是实现init_memmap/ alloc_pages/ free_pages这三个函数。当完成物理内存页管理初始化工作后，计算机系统的内存布局如下图所示：

```c
+----------------------+ <- 0xFFFFFFFF(4GB)       ----------------------------  4GB
|  一些保留内存，例如用于|                                保留空间
|   32bit设备映射空间等  |
+----------------------+ <- 实际物理内存空间结束地址 ----------------------------
|                      |
|                      |
|     用于分配的         |                                 可用的空间
|    空闲内存区域        |
|                      |
|                      |
|                      |
+----------------------+ <- 空闲内存起始地址      ----------------------------  
|     VPT页表存放位置      |                                VPT页表存放的空间   (4MB左右)
+----------------------+ <- bss段结束处           ----------------------------
|uCore的text、data、bss |                              uCore各段的空间
+----------------------+ <- 0x00100000(1MB)       ---------------------------- 1MB
|       BIOS ROM       |
+----------------------+ <- 0x000F0000(960KB)
|     16bit设备扩展ROM  |                             显存与其他ROM映射的空间
+----------------------+ <- 0x000C0000(768KB)
|     CGA显存空间       |
+----------------------+ <- 0x000B8000            ---------------------------- 736KB
|        空闲内存       |
+----------------------+ <- 0x00011000(+4KB)          uCore header的内存空间
| uCore的ELF header数据 |
+----------------------+ <-0x00010000             ---------------------------- 64KB
|       空闲内存        |
+----------------------+ <- 基于bootloader的大小          bootloader的
|      bootloader的   |                                    内存空间
|     text段和data段    |
+----------------------+ <- 0x00007C00            ---------------------------- 31KB
|   bootloader和uCore  |
|      共用的堆栈       |                                 堆栈的内存空间
+----------------------+ <- 基于栈的使用情况
|     低地址空闲空间    |
+----------------------+ <-  0x00000000           ---------------------------- 0KB
```

# 地址映射

在uCore中地址映射的关系为

```c
virt addr = linear addr = phy addr + 0xC0000000
```

在kernel.ld中

```assembly
    /* Load the kernel at this address: "." means the current address */
    . = 0xC0100000;
```

可以看到kernel被加载到`0xC0100000`，这个地址是虚拟地址。转换为物理地址为`0x100000`。在lab1中，这里为

```c
	/* Load the kernel at this address: "." means the current address */
	. = 0x100000;
```

最终的物理地址是一致的。

在lab2/kern/init/init.c的kern_init函数中，声明了外部全局变量：

```c
extern char edata[], end[];
```

但搜寻所有源码文件*.[ch]，没有发现有这两个变量的定义。那这两个变量从哪里来的呢？其实在lab2/tools/kernel.ld中，可以看到如下内容：

```c
…
.text : {
        *(.text .stub .text.* .gnu.linkonce.t.*)
}
…
    .data : {
        *(.data)
}
…
PROVIDE(edata = .);
…
    .bss : {
        *(.bss)
}
…
PROVIDE(end = .);
…
```

这里的“.”表示当前地址，“.text”表示代码段起始地址，“.data”也是一个地址，可以看出，它即代表了代码段的结束地址，也是数据段的起始地址。类推下去，“edata”表示数据段的结束地址，“.bss”表示数据段的结束地址和BSS段的起始地址，而“end”表示BSS段的结束地址。即整个kernel的结束地址。

`edata[]`和 `end[]`这些变量是ld根据kernel.ld链接脚本生成的全局变量，表示相应段的结束地址，它们不在任何一个.S、.c或.h文件中定义，但仍然可以在源码文件中使用。

在uCore中采用的二级页表的方式进行内存管理，为把0~KERNSIZE（明确ucore设定实际物理内存不能超过KERNSIZE值，即0x38000000字节，896MB，3670016个物理页）的物理地址一一映射到页目录项和页表项的内容，其大致流程如下：

1. 先通过alloc_page获得一个空闲物理页，用于页目录表；

2. 调用boot_map_segment函数建立一一映射关系，具体处理过程以页为单位进行设置，即

   ```c
   virt addr = phy addr + 0xC0000000
   ```

   设一个32bit线性地址la有一个对应的32bit物理地址pa，如果在以la的高10位为索引值的页目录项中的存在位（PTE_P）为0，表示缺少对应的页表空间，则可通过alloc_page获得一个空闲物理页给页表，页表起始物理地址是按4096字节对齐的，这样填写页目录项的内容为

   ```c
   页目录项内容 = (页表起始物理地址 &0x0FFF) | PTE_U | PTE_W | PTE_P
   ```

   进一步对于页表中以线性地址la的中10位为索引值对应页表项的内容为

   ```c
   页表项内容 = (pa & ~0x0FFF) | PTE_P | PTE_W
   ```

   其中：

3. PTE_U：位3，表示用户态的软件可以读取对应地址的物理内存页内容

4. PTE_W：位2，表示物理内存页内容可写

5. PTE_P：位1，表示物理内存页存在

# Lab2

## 练习1

**实现 first-fit 连续物理内存分配算法**

Code:default_pmm.c

```c
static void
default_init(void) {
    list_init(&free_list);
    nr_free = 0;
}
```

`free_list`用来维护所有空闲的内存块，是一个空闲链表，在最开始它的`prev`和`next`都指向自身。`nr_free`记录了`free_list`中空闲`page`的数目。

```c
static void
default_init_memmap(struct Page *base, size_t n) {
    assert(n > 0);
    struct Page *p = base;
    for (; p != base + n; p ++) {
        assert(PageReserved(p));
        p->flags = p->property = 0;
        set_page_ref(p, 0);
    }
    base->property = n;
    SetPageProperty(base);
    nr_free += n;
    list_add(&free_list, &(base->page_link));
}
```

`default_init_memmap`用来对块中的每个`page`进行初始化，并将`block`加入到`free_list`中。

在我们实现的`first_fit`算法中，要求`block`按照地址进行排序。而`list_add`中实现的是`list_add_after(listelm, elm);`，即在`free_list`后添加。所以，这里要改成`list_add_before`。

```c
static struct Page *
default_alloc_pages(size_t n) {
    assert(n > 0);
    if (n > nr_free) {
        return NULL;
    }
    struct Page *page = NULL;
    list_entry_t *le = &free_list;
    while ((le = list_next(le)) != &free_list) {
        struct Page *p = le2page(le, page_link);
        if (p->property >= n) {
            page = p;
            break;
        }
    }
    if (page != NULL) {
        list_del(&(page->page_link));
        if (page->property > n) {
            struct Page *p = page + n;
            p->property = page->property - n;
            list_add(&free_list, &(p->page_link));
    }
        nr_free -= n;
        ClearPageProperty(page);
    }
    return page;
}
```

`default_alloc_pages`用来申请指定数目的空闲`page`。当n大于`nr_free`时，`free_list`必然不能满足需求，返回NULL。

之后遍历`free_list`，查看每一个`page_header`，其`property`记录了该链表中`page`的数目。找到第一个合适的返回。

如果找到了这样的`block`，则将其进行切割（如果必要的话），将剩余的再加入到链表中。

所以对应处改为:

```c
    if (page != NULL) {
        if (page->property > n) {
            struct Page *p = page + n;
            p->property = page->property - n;
            SetPageProperty(p);
            list_add_after(&(page->page_link), &(p->page_link));
    }
        list_del(&(page->page_link));
        nr_free -= n;
        ClearPageProperty(page);
    }
```

```c
static void
default_free_pages(struct Page *base, size_t n) {
    assert(n > 0);
    struct Page *p = base;
    for (; p != base + n; p ++) {
        assert(!PageReserved(p) && !PageProperty(p));
        p->flags = 0;
        set_page_ref(p, 0);
    }
    base->property = n;
    SetPageProperty(base);
    list_entry_t *le = list_next(&free_list);
    while (le != &free_list) {
        p = le2page(le, page_link);
        le = list_next(le);
        if (base + base->property == p) {
            base->property += p->property;
            ClearPageProperty(p);
            list_del(&(p->page_link));
        }
        else if (p + p->property == base) {
            p->property += base->property;
            ClearPageProperty(base);
            base = p;
            list_del(&(p->page_link));
        }
    }
    nr_free += n;
    list_add(&free_list, &(base->page_link));
}
```

`default_free_pages`将被free的`block`重新加入到`free_list`中，并做了相应的合并操作。然而，在这个版本中，将合并后的`block`加入到了链表头部。

所以对应处改为：

```c
    nr_free += n;
    for(le = list_next(le); le != &free_list; le = list_next(le)) {
        p = le2page(le, page_link);
        if(base + base->property <= p) {
            assert(base + base->property != p);
            break;
        }
    }
    list_add_before(&(p->page_link), &(base->page_link));
```

## 练习2

```c
#if 1
	// &pgdir[PDX(la)] 根据一级页表项索引从一级页表中找到对应的页目录项指针
    pde_t *pdep = &pgdir[PDX(la)];   	// (1) find page directory entry
    if (!(*pdep & PTE_P)) {				// (2) check if entry is not present
        struct Page *page;              
        if(!create || (page = alloc_page()) == NULL) // (3) check if creating is needed, then alloc page for page table
            return NULL;                  			// CAUTION: this page is used for page table, not for common data page
        set_page_ref(page, 1);                  	// (4) set page reference
        uintptr_t pa =  page2pa(page);              // (5) get linear address of page
        // 使用KADDR(pa)将物理地址转化为虚拟地址，使用`memset`进行清空
        memset(KADDR(pa), 0, PGSIZE);               // (6) clear page content using memset
        // 将对应的物理地址设置权限后填入二级页表
        *pdep = pa | PTE_U | PTE_W | PTE_U;         // (7) set page directory entry's permission
    }
    return &((pte_t *)KADDR(PDE_ADDR(*pdep)))[PTX(la)];          // (8) return page table entry
#endif
```

`get_pte`给定一个虚拟地址，返回这个虚拟地址在二级页表中对应的项。

`PTX(la)`获得逻辑地址在二级页表中的下标。`&((pte_t *)KADDR(PDE_ADDR(*pdep)))`获得`la`所对应的二级页表的内核虚拟地址，并将其转换为了二级页表表项指针。这样再通过下标，就可以获得对应的虚拟地址在二级页表中对应的项。

## 练习3

**释放某虚地址所在的页并取消对应二级页表项的映射**

```c
	if(*ptep & PTE_P) {							//(1) check if this page table entry is present
        struct Page *page = pte2page(*ptep);	//(2) find corresponding page to pte
        if (page_ref_dec(page) == 0) {			//(3) decrease page reference
            free_page(page);					//(4) and free this page when page reference reachs 0
        }
        *ptep = NULL;							//(5) clear second page table entry
        tlb_invalidate(pgdir, la);				//(6) flush tlb
    }
```

`page_remove_pte`用来解除页的映射。如果该页的存在，清空该页的引用，并将其free。清空其二级页表项和对应的tlb。

对于每一个练习，其实都给了详细的注释，只要理解了概念，那代码不是问题。

## Challenge 1: Buddy system







## Challenge 2: Slub

