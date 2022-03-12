# CSAPP Lecture 03




# Lecture 03

# Machine-Level Programming Ⅰ: Basics

<!-- more -->

## History of Intel processors and architectures

介绍了Intel x86的历史，不重要。

## C, assmbly, machine code

**CPU: **

- PC: Programmer counter
  - Address of next instruction
  - Called "RIP" (x86-64)
- Register file
  - Heaviy used program data（程序主要使用寄存器来实现功能）
- Condition codes
  - 储存状态信息

由**指令集体系结构**或**指令集架构（Instruction Set Architecture，ISA）**来定义机器级程序的格式和行为，它定义了处理器状态、指令的格式，以及每条指令对状态的影响。大多数ISA都将程序的行为描述为按顺序执行每条指令。这是编译器的目标，提供一系列指令告诉机器要做什么。而微结构是指这个架构的实现。

**Memory:**

- 内存可认为是个字节数组
- 代码和数据
- 栈支持程序运行

x86-64，它是Intel 64位体系结构，它的前身是32位的IA32。x86是对Intel处理器的口头称呼，因为第一个芯片被称为8086。x86又被称为**复杂指令集计算机（Complex Instruction Set Computer，CISC）**。目前处理器和常用的另一大类是**ARM（Acorn RISC Machine）**，RISC是**精简指令集计算机（Reduced Instruction Set Computer）**，由于它更简单，所以它比x86机器功耗更低。

`gcc -Og -S xxx.c`: 编译命令，最后生成，xxx.o文件。

- `-Og`：是生成机器代码的优化等级，这个表示编译器会生成符合原始C代码整体结构的机器代码，这是用于调试的级别，便于我们学习观察。其他的`-O1`或`-O2`会得到更好的程序性能，但是机器代码和源代码的关系就比较难以理解。
- `-S`：只生成到汇编代码
- `-c`：生成二进制文件

`objdump -d xxx.o`: 反汇编命令。将机器码反编译为汇编代码。

## 汇编代码

汇编指令的两种格式Intel和AT&T。书中展示的为AT&T的格式。

| C声明  | Intel数据结构 | 汇编代码后缀 | 大小（字节） |
| :----: | :-----------: | :----------: | :----------: |
|  char  |     字节      |      b       |      1       |
| short  |      字       |      w       |      2       |
|  int   |     双字      |      l       |      4       |
|  long  |     四字      |      q       |      8       |
| char*  |     四字      |      q       |      8       |
| float  |    单精度     |      s       |      4       |
| double |    双精度     |      l       |      8       |

**寄存器信息：**

![寄存器](https://ctf-wiki.org/pwn/linux/stackoverflow/figure/register.png)

**AT&T指令操作格式：**




# Machine-Level Programming Ⅱ: Control

## 数据传送指令

|  指令  |        描述        |
| :----: | :----------------: |
| movzbw |  零扩展的字节到字  |
| movzbl | 零扩展的字节到双字 |
| movzwl |  零扩展的字到双字  |
| movzbq | 零扩展的字节到四字 |
| movzwq |  零扩展的字到四字  |

|  指令  |         描述         |
| :----: | :------------------: |
| movsbw |  符号扩展的字节到字  |
| movsbl | 符号扩展的字节到双字 |
| movswl |  符号扩展的字到双字  |
| movsbq | 符号扩展的字节到四字 |
| movswq |  符号扩展的字到四字  |
| movslq | 符号扩展的双字到四字 |
|  cltq  | 把%eax符号扩展到%rax |

**整数算术操作**


## 控制

**条件码**

- **ZF：**零标志，最近的操作得到的结果是否为0。

- **无符号数：**

- - **CF：**进位标志，最近的操作使得最高位产生进位。可用来检查无符号数是否存在溢出。

- **补码：**

- - **SF：**符号标志，最近的操作得到的结果为负数。
  - **OF：**溢出标志，最近的操作导致补码溢出。

- `lea`不会设置条件码，因为它只是单纯计算地址。

- `CMP S1, S2`：用来比较`S1`和`S2`，根据`S2-S1`的结果来设置条件码。
- `TEST S1, S2`：根据`S1 & S2`的结果来设置条件码。

还有一系列的`set`指令专门用来设置条件码


无条件跳转：`jmp`

有条件跳转：

在汇编中通过条件码实现分支控制与循环。

x86-64上提供了一些条件传送指令`CMOV`，只有在满足条件时，才会将源数据传送到目的中：


## 循环

**do-while：**

```c
long fact_do(long n){
  long result = 1;
  do{
    result *= n;
    n = n-1;
  }while(n>1);
  return result;
}
```

```assembly
fact_do:
  movl $1, %eax
.L1:
  imulq %rdi, %rax
  subq $1, %rdi
  cmpq $1, %rdi
  jg .L1
  rep; ret
```

在循环体的结尾处进行判断或跳转。

**while：**

```c
long fact_while(long n){
  long result = 1;
  while(n>1){
    result *= n;
    n = n-1;
  }
  return resul;
}
```

- Jump-to-middle：一开始就有一个无条件跳转指令，用来跳转到判断语句。就是相等于在do-while循环的外面套了一层跳转。

  ```assembly
  fact_while:
    movl $1, %eax
    jmp .JUDGE
  .L1:
    imulq %rdi, %rax
    subq $1, %rdi
  .JUDGE:
    cmpq $1, %rdi
    jg .L1
    rep; ret
  ```

- guarded-do：在开始直接进行判断。这个之所以更加高效，是因为一开始进入循环时，通常不会不满足循环条件，即一开始不会跳转到后面，所以会直接顺序一直执行循环体。，当使用较高优化等级时，比如`-O1`时，GCC会使用这种策略。

  ```assembly
  fact_while:
    cmpq $1, %rdi
    jle .L1
    movl $1, %eax
  .L2:
    imulq %rdi, %rax
    subq $1, %rdi
    cmpq $1, %rdi
    jne .L2
    rep; ret
  .L1:
    movl $1, %eax
    ret 
  ```

**for:**

```c
long fact_for(long n){
  long i;
  long result = 1;
  for(i=2; i<=n; i++){
    result *= i;
  }
  return result;
}
```

将其转化为while语句，按照while循环的方式进行优化。

**switch:**

`switch`语句可以根据一个整数索引数值进行多重分支。通常使用**跳转表（Jump Table）**数据结构使得实现更加高效，它是一个数组，每个元素是对应的代码块起始地址，根据整数索引得到对应的代码地址后，就可以直接跳转到对应的代码块。相比很长的`if-else`语句的优势在于：执行`switch`语句的时间与分支数目无关，只需要计算一次偏移。

# Machine-Level Programming Ⅲ: Procedures

函数调用约定。

stack的思想，`pop`与`push`指令。

保存到内存中进行参数传输时，要求每个参数大小为8字节的倍数，即要求相对`%rsp`的偏移量为8的倍数

`call`: 下一条指令地址入栈，栈地址`rbp`入栈，`rip`变为目的地址。返回值放入`rax`

# Machine-Level Programming Ⅳ: Data

结构体的内存分布

- 结构的所有组成部分都存放在内存中一段**连续的**区域内，指向结构的**指针**是结构第一字节的地址。
- 要求结构的初始地址一定是结构体中最大对象大小的倍数，使得偏移量加上初始地址才是真的满足倍数关系的。
- 在结构体末尾填充，使其是结构体中最大对象大小的倍数，使得结构数组中下一个元素的地址也是成倍数关系的。我们可以改变声明的顺序，按照从大到小的形式进行声明，可以减少填充的字节数目，节省该结构的空间大小

对齐原则是任何K字节的基本对象的地址必须是K的倍数

共用体的内存分布

- 保存在**公共的**一块内存中，通过不同对象的类型来赋予这块内存不同的含义。内存大小为最大字段的大小。

- 如果我们事先知道两个不同字段是互斥的，就能将其定义在一个union中，就能节省内存空间。

### 数组与指针运算

在c语言中，二维数组的定义：char buf[x\][y]，其中x可缺省，y不能缺省。对于二维数组，我们可以这样理解：二维数组是一维数组的嵌套，即一维数组中所有元素为同类型数组。 
例如：char array[3\][3],我们可以将其理解成array数组是一个一维数组，数组的元素分别是array[0],array[1],array[2]三个char[3]型数组。
而对于一个数组元素的访问，c是这样实现的：先取出数组首元素地址，目标元素地址=首地址+sizeof(type)*N，得到被访问元素的地址，type是指针指向数据类型。
如上面提到的array，它是一个二维数组的函数名其每个元素为一个行数组，它就是数组指针，在这个指针上加减一个整数都是移动整行。
而array[0],array[1],array[2]其每个元素为一个char，将它们视作单独的数组，那么其函数名就是指针！在其上进行加减是对移动一个type(char)的大小。
注意，区别指针数组，指针数组的元素是指针。

一个重要的数据访问思想：基址+`offset`

### 浮点数

![](https://i.stack.imgur.com/aMt3C.png)

在浮点运算中，指令被分成了**标量指令（Scalar Operations）**和**SIMD指令**，在指令中分别用`s`和`p`表示。


标量指令只对低4字节或8字节进行操作，而向量指令会对其他的字节采取并行的操作。

**浮点传送**


其中，最后两个指令的a表示对齐，当读写内存时，要求满足16字节对齐（因为XMM是16字节的），否则会报错。

传入参数，如果是浮点数，就保存在XMM寄存器中，如果是指针或整型，就保存在常规寄存器中。而返回值也是如此。

**浮点转换**

- 浮点数-->整型

  ![](https://imgbed.niebelungen-d.top/images/2021/02/04/1506992-20181208151250319-378942177.png)

- 整型-->浮点数


  在整型转换成浮点数时，提供了三操作数指令，这里通常可以忽略第二个操作数，因为它的值只会影响高位字节，通常使用目的寄存器。

**运算操作**


和整数运算操作不同，AVX浮点操作不能用立即数作为常数。编译器会为浮点常数分配和初始化存储空间，然后代码再从内存中读取这些值。比如以下代码

**浮点数位级操作**


**比较操作**


# Machine-Level ProgrammingⅤ: Advanced Topics

## Linux的内存结构：

- Stack 
  - 8MB limit
- Heap 
  - Dynamically allocated as needed
  - `malloc`, `calloc`, `new`
- Data
  - statically allocated data
- Text / Shared Libraries
  - read-only
  - executable machine instructions

## Buffer overflow

### 保护机制

- ASLR

  栈地址随机化

- Canary

  金丝雀保护，栈破坏随机化

- NX

  限制可执行代码区域

ROP
