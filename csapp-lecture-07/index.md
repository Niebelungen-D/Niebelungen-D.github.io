# CSAPP Lecture 07


# Lecture 07: Cache Memories

<!--more-->

## 高速缓存存储器

### 通用的高速缓存存储器组织结构

较早期的计算机系统的存储器层次结构只有三层：CPU寄存器、主存和磁盘，但是随着CPU的发展，使得主存和CPU之间的读取速度逐渐拉大，由此在CPU和主存之间插入一个小而快速的SRAM高速缓存存储器，称为**L1高速缓存**，随着后续的发展，又增加了**L2高速缓存**和**L3高速缓存**。

![](https://imgbed.niebelungen-d.top/images/2021/02/13/9fooj.jpg)

考虑一个计算机系统，其中每个存储器地址有 m 位，形成 M=2mM=2m 个不同的地址。这样一个机器的高速缓存被组织成一个有 S=2sS=2s 个高速缓存组（cache set）的数组。每个组包含 E 个**高速缓存行（cache line）**。每个行是由一个 B=2bB=2b 字节的**数据块（block）**组成的，一个**有效位（valid bit）**指明这个行是否包含有意义的信息（为了方便），还有 t = m-(b+s) 个**标记位（tag bit）**（是当前块的内存地址的位的一个子集），它们唯一地标识存储在这个高速缓存行中的块。该高速缓存的结构可以通过元组`(S, E, B, m)`来描述，且容量C为所有块的大小之和，$C=S*E*B$。

参数 S 和 B 将 m 个地址位分为了三个字段。

- 地址 A 中有 s 个组索引位是一个到 S 个组的数组的索引，是一个无符号整数。
- 地址 A 中的 t 个标记位告诉我们这个组中的哪一行包含这个字。当且仅当设置了有效位并且该行的标记位与地址 A 中的标记位相匹配时，组中的这一行才包含这个字。(Valid bits are also used in the context of multiprocessors)
- 一旦我们在由组索引标识的组中定位了由标号所标识的行，那么 b 个块偏移位给出了 B 个字节的数据块中的字偏移。

### 直接映射高速缓存（single block/line per set）

![](https://imgbed.niebelungen-d.top/images/2021/02/13/0u9ml.jpg)

当E=1 时，高速缓存称为**直接映射高速缓存（Direct-mapped Cache）**，每个高速缓存组中只含有一个高速缓存行。

- 组选择

  ![](https://imgbed.niebelungen-d.top/images/2021/02/13/h30cu.jpg)

- 行匹配

  ![](https://imgbed.niebelungen-d.top/images/2021/02/13/hnx69.jpg)

- 字抽取

  如果找到了对应的高速缓存行，则可以将b位表示为无符号数作为块偏移量，得到对应位置的字。最后，如果不命中则进行行替换，需要驱逐出一个现存的行。

x 与 y 块之间的**抖动（thrash）**，即高速缓存反复地加载和驱逐相同的高速缓存块的组。

### 组相联高速缓存（E-way Set-Associative Cache or E blocks/lines per set）

![](https://imgbed.niebelungen-d.top/images/2021/02/13/bbzww.jpg)

直接映射高速缓存的冲突不命中是由于每个高速缓存组中只有一个高速缓存行，所以扩大E的值，当$1<E<C/B$ 时，称为**E路组相联高速缓存（Set Associative Cache）**，此时需要额外的硬件逻辑来进行行匹配，所以更加昂贵。（$E<C/B$即要求$S>1$)

当缓存不命中时需要进行缓存行替换，如果对应的高速缓存组中有空的高速缓存行，则直接将其保存到空行中。但是如果没有空行，就要考虑合适的**替换策略**：

- 最简单的替换策略是随机选择要替换的行
- **最不常使用（Least-Frequently-Used，LFU）策略：**替换过去某个时间窗口内引用次数最少的一行。
- **最近最少使用（Least-Recently-Used，LRU）策略：**替换最后一次访问时间最久远的那一行

### 全相联高速缓存

**全相联高速缓存（Full Associative Cache）**是用一个包含所有高速缓存行的组组成的，其中$E=C/B$ ，即$S=1$ 。

由于全相联高速缓存只有一个组，所以不包含组索引编码

### 写操作

当CPU想要对地址A进行写操作时，会通过地址A判断是否缓存了该地址，如果缓存了称为**写命中（Write Hit）**，否则称为**写不命中（Write Miss）**。

- **写命中：**高速缓存会先更新缓存的副本，然后可以采取不同方法更新下一层的副本

- - **直写（Write-Though）：**立即更新下一层的副本值。缺点是每次写都会引起总线流量。
  - **写回（Write-Back）：**为每个高速缓存行维护一个**修改位（Dirty Bit）**，表明这个高速缓存块是否被修改。当被修改的高速缓存块被驱逐时，会查看修改位，判断该块是否被修改，只有被修改才会更新下一层的副本值。能够显著减少总线流量，但是复杂性高。

- **写不命中：**

- - **写不分配（Not-Write-Allocate）：**直接将字写到下一层中。
  - **写分配（Write-Allocate）：**加载相应的下一层的块到当前层的高速缓存中，然后更新当前高速缓存块。得益于空间局部性，进行一次写分配后，下一次有较高几率会写命中，但是缺点是每次写不命中就要将块从第一层向上传输。

### 真实高速缓存结构

可以将高速缓存分成以下几种：

- **i-cache：**只保存指令的高速缓存
- **d-cache：**只保存程序数据的高速缓存
- **Unified Cache：**即能保存指令，也能保存程序数据的高速缓存

### 参数对性能的影响

衡量高速缓存的指标有：

- **命中率（Hit Rate）：**内存引用命中的比率，`命中数量/引用数量`。
- **不命中率（Miss Rate）：**内存引用不命中的比率，`不命中数量/引用数量`。通常，L1高速缓存为3~10%，L2高速缓存为<1%。
- **命中时间（Hit Time）：** 从高速缓存传输一个字到CPU的时间，包括组选择、行匹配和字选择时间。通常，L1高速缓存需要4个时钟周期，L2高速缓存需要10个时钟周期。
- **不命中处罚（Miss Penalty）：**当缓存不命中时，要从下一层的存储结构中传输对应块到当前层中，需要额外的时间（不包含命中时间）。通常，主存需要50~200个时钟周期。

想要编写高速缓存友好（Cache Friendly）的代码，**基本方法为：**

- 让最常见的情况运行得快，将注意力集中在核心函数的循环中
- 尽可能减少每个循环内部的缓存不命中，可以对局部变量反复引用，因为编译器会将其保存到寄存器中，其他的变量最好使用步长为1的引用模式。

之后就是大段的数据分析不同的参数对性能的影响，这里最重要的一点是命中率，命中和不命中两者对性能影响很大，比如99%命中率的性能会比97%命中率高两倍。

## 改善程序

**重新排列循环来改善空间局部性**

对循环重排列，来提高空间局部性，增加命中率。

**使用分块来提高时间局部性**

分块的主要思想是将一个程序中的数据结构组织成大的**片（Chunk）**，使得能够将一个片加载到L1高速缓存中，并在这个偏重进行读写。分块降低不命中率是因为加载一个块后，就反复使用该块，提高了空间局部性。
