# CSAPP Lecture 04


# Lecture 04: 处理器体系结构

<!-- more -->

## Y86-64ISA

定义一个简单的指令集，作为处理器实现的运行示例。

**寄存器**：15个程序寄存器：%rax，%rcx，%rdx，%rbx，%rsp，%rbp，%rsi，%rdi，%r8到%r14。这里省略了%r15，为了简化指令编码。

它们分别对应编码数字`0-0xE`，而`0xF`代表当前指令不需要寄存器操作数。

**条件码**：ZF、SF和OF。

**PC**：程序计数器

**Stat**：程序状态

- 1：AOK，正常操作
- 2：HLT，处理器执行了halt指令
- 3：ADR，遇到非法地址
- 4：INS，遇到非法指令

**一些指令细节**

`movq`：Y86-64中该操作被分成：`irmovq`，`rrmovq`，`mrmovq`，`rmmovq`

整数操作指令：`addq`，`subq`，`andq`，`xorq`

七个跳转指令：`jmp`, `jle`, `je`, `jne`, `jl`, `jge`, `jg`

条件传送指令：`cmovle`, `cmovl`, `cmove`, `cmovne`, `cmovge`, `cmovg`

`halt`：停止指令的执行

![](https://imgbed.niebelungen-d.top/images/2021/02/04/3046658_1533293064491_CD1128DE27210C50E46FA6BA1F31980F.png)

**pushq, popq的一些约定**
我们知道`push`指令会将rsp-8，那么如果`push rsp`那么入栈的rsp是原始值，还是rsp-8后的值呢？
规定在Y86-64，采用前者。
同时，`pop rsp`也会有歧义，Y86-64也会弹出原值，而不是+8后的。

## HCL
一些数电知识略过~
HCL类似于用布尔表达式来书写门电路的组合方式, 像这个`bool eq = (a && b) || (!a && !b)`;

HCL语言看上去很像C语言表达式, 相比C语言, HCL有一些特点:

1. HCL的值是持续响应的, 并不是像语句一样遇到才求值
2. C的判断条件是不是0都是真, 而是0就是假. HCL中的值只有0和1代表高低电压, 不存在其他值.
3. C表达式有短路作用, 而HCL一直响应输入变化, 不存在求值与否的问题.
4. 将所有输入都假设为数据类型是int的字来解释, 其实底层是没有数据类型一说的, 这样假设是为了说起来方便.
5. 允许比较字是否相等, 即 `bool eq = (A==B)`

**多路复用器（Multiplexor，MUX）**

实际就是数据选择器，在HCL可以使用

```HCL
[
  select1 : expr1;
  select2 : expr2;
  ...
  selectk : exprk;
]
```

其中，`select`是布尔表达式，`expr`是字级表达式。在HCL中，不要求不同的选择表达式之间是互斥的，但是实际的多路复用器的信号必须互斥。选择表达式是顺序求值的，所以后续的选择表达式可以在之前的选择表达式的基础上进行简化。例如：

```HCL
int Out={
	s : A;
	1 : B;
};
```

四选一数据选择器的表达式可以写作：

```HCL
bool s1 = code == 2 || code ==3
bool s0 = code == 1 || code ==3
```

还可以进一步简化为：

```HCL
bool s1 = code in {2, 3}
bool s0 = code in {1, 3}
```

当code在集合{2, 3}中时，s1为1，而code在集合{1, 3}中时，s0为1。

**存储器和时钟**

时序电路，触发沿产生后才改变存储器的值。

主要有**两类存储器设备：**

- **时钟寄存器（寄存器）：**存储单个位或字，主要作为电路不同部分的组合逻辑之间的屏障。

- **随机访问存储器（内存）：**存储多个字，用地址来选择读写哪个字。**包括：**

- - **处理器的虚拟内存系统：**通过操作系统对存储器进行抽象，使得处理器可以在很大的地址空间中访问，地址为虚拟内存的索引值。
  - **寄存器文件：**是一个以寄存器标识符为地址，存储着对应程序寄存器值的随机访问存储器。在IA32或Y86-64处理器中，有15个程序寄存器（`%rax`~`%r14`）。

这里要注意区分机器级编程中的寄存器和硬件中的寄存器

- **硬件：**寄存器指的是时钟寄存器，直接将它的输入和输出连接到电路的其他部分。这里称为硬件寄存器。
- **机器级编程：**寄存器代表的是存储在寄存器文件中的，CPU中少数可寻址的字，地址为寄存器标识符。这里称为程序寄存器。

**硬件寄存器：**

当触发沿时，寄存器的输出状态才会变成新值。在此之前，寄存器的状态会一直保存。

Y86-64处理器会使用硬件寄存器保存程序计数器（PC）、条件代码（CC）和程序状态（Stat）。

**寄存器文件：**

寄存器文件包含两个读端口和一个写端口，意味着能读取两个程序寄存器的同时对第三个程序寄存器进行写操作。这里的地址就是程序寄存器标识符。

寄存器文件的写入操作受时钟信号控制，只有当时钟为高电平时，才将`valW`中的值写入`dstw`指示的程序寄存器中。

**虚拟内存系统：**

处理器用虚拟内存来保存程序数据。`read`和`write`是两个标志位，用来控制当前是要读还是写。包含通过逻辑电路实现的边界检查，如果地址超过虚拟内存地址空间，就会使得`error=1`。

虚拟内存的写入操作受时钟信号控制，只有当`write=1`并且时钟为高电平时，才会将`data in`的数据保存到对应地址的位置。

## Y86-64的顺序实现

处理一条指令我们可以将其划分成若干个阶段：

1. **取指（Fetch）：**根据程序计数器PC从内存中读取指令字节。然后完成以下步骤

   1. 从指令中提取出指令指示符字节，并且确定出指令代码（`icode`）和指令功能（`ifun`）
   2. 如果存在寄存器指示符，则从指令中确定两个寄存器标识符`rA`和`rB`
   3. 如果存在常数字，则从指令中确定`ValC`
   4. 根据指令指令长度以及指令地址，可确定下一条指令的地址`valP`

2. **译码（Decode）：**如果存在`rA`和`rB`，则译码阶段会从寄存器文件中读取`rA`和`rB`的值`valA`和`valB`。对于`push`和`pop`指令，译码阶段还会从寄存器文件中读取`%rsp`的值。

3. **执行（Execute）：**算术逻辑单元（ALU）会根据`ifun`的值执行对应的计算，得到结果`valE`，包括
1. 计算运算结果，会设置条件码的值，则条件传送和跳转指令会根据`ifun`来确定条件码组合，确定是否跳转或传送。
   2. 计算内存引用的有效地址
   3. 增加或减少栈指针
   
4. **访存（Memory）：**写入内存或从内存读取数据`valM`。

5. **写回（Write Back）：**将结果写入寄存器文件中。

6. **更新PC（PC Update）：**将PC更新为`valP`，使其指向下一条指令。

|    阶段    |                          OPq rA, rB                          |                        rrmovq rA, rB                         |                         irmovq V, rB                         |
| :--------: | :----------------------------------------------------------: | :----------------------------------------------------------: | :----------------------------------------------------------: |
|   Fetch    | `icode`: `ifun`&larr; $M_1[PC]$  <br>`rA`: `rB`&larr; $M_1[PC+1]$ <br>  <br>`valP` &larr; PC+2 | `icode`: `ifun`&larr; $M_1[PC]$  <br/>`rA`: `rB`&larr; $M_1[PC+1]$ <br/>  <br/>`valP` &larr; PC+2 | `icode`: `ifun`&larr; $M_1[PC]$  <br/>`rA`: `rB`&larr; $M_1[PC+1]$ <br/> `valC` &larr; $M_s[PC+2]$  <br/>`valP` &larr; PC+10 |
|   Decode   |      `valA` &larr; $R[rA]$ <br/> `valB` &larr; $R[rB]$       |                    `valA` &larr; $R[rA]$                     |                                                              |
|  Execute   |          `valE` &larr; `valA` or `valB`<br/>Set CC           |                    `valE` &larr; 0+`valA`                    |                    `valE` &larr; 0+`valC`                    |
|   Memory   |                                                              |                                                              |                                                              |
| Write Back |                     R[rB] &larr; `valE`                      |                     R[rB] &larr; `valE`                      |                     R[rB] &larr; `valE`                      |
| PC Update  |                       PC &larr; `valP`                       |                       PC &larr; `valP`                       |                       PC &larr; `valP`                       |

`OPq`中会将`ifun`传入给ALU来确定`OP`的类型。

|    阶段    |                       rmmovq rA, D(rB)                       |                       mrmovq D(rB), rA                       |
| :--------: | :----------------------------------------------------------: | :----------------------------------------------------------: |
|   Fetch    | `icode`: `ifun`&larr; $M_1[PC]$  <br/>`rA`: `rB`&larr; $M_1[PC+1]$ <br/>`valC` &larr; $M_s[PC+2]$  <br/>`valP` &larr; PC+2 | `icode`: `ifun`&larr; $M_1[PC]$  <br/>`rA`: `rB`&larr; $M_1[PC+1]$ <br/> `valC` &larr; $M_s[PC+2]$  <br/>`valP` &larr; PC+10 |
|   Decode   |        `valA` &larr; $R[rA]$<br>`valB` &larr; $R[rB]$        |                  <br>`valB` &larr; $R[rB]$                   |
|  Execute   |                    `valE` &larr; 0+`valA`                    |                    `valE` &larr; 0+`valC`                    |
|   Memory   |                  $M_s[valE]$ &larr; `valA`                   |                  `valE` &larr; $M_s[valE]$                   |
| Write Back |                                                              |                   <br>R[rA] &larr; `valM`                    |
| PC Update  |                       PC &larr; `valP`                       |                       PC &larr; `valP`                       |

|    阶段    |                           pushq rA                           |                           popq rA                            |
| :--------: | :----------------------------------------------------------: | :----------------------------------------------------------: |
|   Fetch    | `icode`: `ifun`&larr; $M_1[PC]$  <br/>`rA`: `rB`&larr; $M_1[PC+1]$ <br/>  <br/>`valP` &larr; PC+2 | `icode`: `ifun`&larr; $M_1[PC]$  <br/>`rA`: `rB`&larr; $M_1[PC+1]$ <br/>  <br/>`valP` &larr; PC+2 |
|   Decode   |        `valA` &larr; $R[rA]$<br>`valB` &larr; R[%rsp]​        |        `valA` &larr; R[%rsp]<br>`valB` &larr; R[%rsp]        |
|  Execute   |                  `valE` &larr; `valB`+(-8)                   |                    `valE` &larr; `valB`+8                    |
|   Memory   |                  $M_s[valE]$ &larr; `valA`                   |                  `valE` &larr; $M_s[valE]$                   |
| Write Back |                  R[%rsp] &larr; `valE`<br>                   |         R[%rsp] &larr; `valE`<br>R[rA] &larr; `valM`         |
| PC Update  |                       PC &larr; `valP`                       |                       PC &larr; `valP`                       |

pop在译码阶段读了两次栈顶指针的值，这是为了使后续流程和别的指令相似。

|    阶段    |                           jxx Dest                           |                          call Dest                           |                             ret                              |
| :--------: | :----------------------------------------------------------: | :----------------------------------------------------------: | :----------------------------------------------------------: |
|   Fetch    | `icode`: `ifun`&larr; $M_1[PC]$  <br/><br/> `valC` &larr; $M_s[PC+2]$  <br/>`valP` &larr; PC+9 | `icode`: `ifun`&larr; $M_1[PC]$  <br/><br/> `valC` &larr; $M_s[PC+2]$  <br/>`valP` &larr; PC+9 | `icode`: `ifun`&larr; $M_1[PC]$  <br/><br/>  <br/>`valP` &larr; PC+1 |
|   Decode   |                                                              |                  <br>`valB` &larr; R[%rsp]                   |       `valA` &larr; R[%rsp]<br/>`valB` &larr; R[%rsp]        |
|  Execute   |                  Cnd &larr; Cond(CC, ifun)                   |                `valE` &larr; `valB`+(-8)<br>                 |                  `valE` &larr; `valB`+8<br>                  |
|   Memory   |                                                              |                  $M_s[vale]$ &larr; `valP`                   |                  `valM` &larr; $M_s[valA]$                   |
| Write Back |                                                              |                    R[%rsp] &larr; `valE`                     |                    R[%rsp] &larr; `valE`                     |
| PC Update  |                PC &larr; Cnd? `valC`: `valP`                 |                       PC &larr; `valC`                       |                       PC &larr; `valM`                       |

**SEQ**

![](https://imgbed.niebelungen-d.top/images/2021/02/05/2016-11-25-16-37-57.png)

- 数据内存和指令内存都是在相同的内存空间中，只是根据不同的功能对其进行划分
- 寄存器文件包含两个读端口`A`和`B`，以及两个写端口`M`和`E`，分别接收来自内存的值`valM`以及ALU计算的结构`valE`。
- PC更新的值可能来自于：下一条指令地址`valP`、来自内存的值`valM`、调用指令或跳转指令的目标地址`valC`。
- 白色方框为时钟寄存器；蓝色方框为硬件单元，当做黑盒子而不关心细节设计；白色圆圈表示线路名字。
- 宽度为字长的数据使用粗线；宽度为字节或更窄的数据用细线；单个位的数据用虚线，主要表示控制值。
- 灰色圆角矩形表示控制逻辑块，能在不同硬件单元之间传递数据，以及操作这些硬件单元，使得对每个不同的指令执行指定的运算。

SEQ的实现包括组合逻辑和两种存储器：时钟寄存器（程序计数器和条件码寄存器）和随机访问存储器（寄存器文件、指令内存和数据内存）。我们知道组合逻辑和存储器的读取是没有时序的，只要输入一给定，输出就会发生对应的变化。但是存储器的写入是受到时钟的控制的，只有当时钟为高电位时，才会将值写入存储器中。

所以涉及到写数据的存储器（程序计数器、条件码寄存器、寄存器文件和数据内存）就需要对时序进行明确的控制，才能控制好指令各阶段的执行顺序。为了保证每条指令执行的结果能和上一节中介绍的顺序执行的结果相同，我们要保证指令的计算**不会回读**，即处理器不需要为了完成一条指令的执行而去读取由该指令更新的状态。因为该指令更新的状态是写入数据，需要经过一个时钟周期，如果该指令需要读取更新过的状态，就需要空出一个时钟周期。

**SEQ的HCL表达式**

|  Name   | Hex  |      Meaning       |
| :-----: | :--: | :----------------: |
|  IHALT  |  0   |       `halt`       |
|  INOP   |  1   |       `nop`        |
| IRRMOVQ |  2   |      `rrmovq`      |
| IIRMOVQ |  3   |      `irmovq`      |
| IRMMOVQ |  4   |      `rmmovq`      |
| IMRMOVQ |  5   |      `mrmovq`      |
|  IOPL   |  6   |    整数运算指令    |
|  IJXX   |  7   |      跳转指令      |
|  ICALL  |  8   |       `call`       |
|  IRET   |  9   |       `ret`        |
| IPUSHQ  |  A   |      `pushq`       |
|  IPOPQ  |  B   |       `popq`       |
|  FNONE  |  0   |     默认功能码     |
|  RRSP   |  4   |   %rsp的寄存器ID   |
|  RNONE  |  F   | 没有寄存器文件访问 |
| ALUADD  |  0   |      加法运算      |
|  SAOK   |  1   |      正常操作      |
|  SADR   |  2   |      地址异常      |
|  SINS   |  3   |      非法指令      |
|  SHLT   |  4   |    `halt`状态码    |

**取指**

- `icode`为第一字节的高4位，当指令地址越界时，指令内存会返回`imem_error`信号，此时直接将其表示为`nop`指令，否则获得高4位值

```text
word icode = [
  imem_error : INOP;
  1          : imem_icode;
];
```

- `ifun`为第一字节的低4位，当出现`imem_error`信号时，会使用默认功能码，否则获得低4位值

```text
word ifun = [
  imem_error : FNONE;
  1          : imem_ifun;
];
```

- `instr_valid`表示是否为合法指令

```text
bool instr_valid = icode in {
  INOP, IHALT, IRRMOVQ, IIRMOVQ, IRMMOVQ, IMRMOVQ, IOPQ, IJXX, ICALL, IRET, IPUSHQ, IPOPQ
};
```

- `need_regids`表示该指令否包含寄存器指示符字节，如果指令不含有寄存器指示符字节，则会将其赋值为`0xFF`。

```text
bool need_regids = icode in {
  IRRMOVQ, IOPQ, IPUSHQ, IPOPQ, IIRMOVQ, IRMMOVQ, IMRMOVQ
};
```

- `need_valC`表示该指令是否含有常数字节

```text
bool need_valC = icode in {
  IIRMOVQ, IRMMOVQ, IMRMOVQ, IJXX, ICALL
};
```

PC增加器会根据PC值、`need_valC`和`need_regids`来确定`valP`值，则

```
valP = PC+1+need_regids+8*need_valC
```

**译码与写回**

- 写入的目的`dstE`和`dstM`

```text
word dstE = [
  icode in {IRRMOVQ} && Cnd             : rB; #cmovXX指令，可以将其看成是rrmovq和条件信号Cnd的组合 
  icode in {IIRMOVQ, IOPQ}              : rB;
  icode in {IPUSHQ, IPOPQ, ICALL, IRET} : RRSP; #获取%rsp
  1                                     : RNONE;
];
word dstM = [
  icode in {IMRMOVQ, IPOPQ} : rA;
  1                         : RNONE;
];
```

- 读取的源`srcA`和`srcB`

```text
word srcA = [
  icode in {IRRMOVQ, IRMMOVQ, IOPQ, IPUSHQ} : rA;
  icode in {IPOPQ, IRET}                    : RRSP;
  1                                         : RNONE;
];
word srcB = [
  icode in {IOPQ, IRMMOVQ, IMRMOVQ}     : rB;
  icode in {IPUSHQ, IPOPQ, ICALL, IRET} : RRSP;
  1                                     : RNONE;
];
```

**执行阶段**

- 进入ALU进行计算的两个值`aluA`和`aluB`

```text
word aluA = [
  icode in {IRRMOVQ, IOPQ}             : valA; #包含两个寄存器时，aluA为寄存器的值valA
  icode in {IIRMOVQ, IRMMOVQ, IMRMOVQ} : valC; #当出现立即数、偏移量时，aluA为常数值
  icode in {ICALL, IPUSHQ}             : -8; #入栈需要将栈顶地址下移8字节
  icode in {IRET, IPOPQ}               : 8; #出栈需要将栈顶地址上移8字节
];
word aluB = [
  icode in {IRMMOVQ, IMRMOVQ, IOPQ, ICALL, IPUSHQ, IRET, IPOPQ} : valB;
  icode in {IRRMOVQ, IIRMOVQ}                                   : 0;
];
```

- 设置ALU进行的函数`alufun`

```text
word alufun = [
  icode == IOPQ : ifun;
  1             : ALUADD;
];
```

- 获得是否设置条件码`set_cc`

```text
bool set_cc = icode in {IOPQ};
```

**访存**

- 定是从内存中读取数据还是写入数据

```text
bool mem_read = icode in {IMRMOVQ, IPOPQ, IRET};
bool mem_write = icode in {IRMMOVQ, IPUSHQ, ICALL};
```

- 获得内存地址`mem_addr`

```text
mem_addr = [
  icode in {IRMMOVQ, IPUSHQ, ICALL, IMRMOVQ} : valE; #IPUSHQ和ICALL设计栈地址计算，IRMMOVQ和IMRMOVQ设计内存引用计算，所以都是ALU的计算结果
  icode in {IPOPQ, IRET}                     : valA; #这部分没涉及ALU计算
];
```

- 获得输入内存的数据`mem_data`

```text
word mem_data = [
  icode in {IRMMOVQ, IPUSHQ} : valA; #从寄存器获得值
  icode == ICALL             : valP; #当调用函数时，会将返回地址写入内存中
  #默认不写入任何信息
];
```

- 确定程序状态`Stat`

```text
word Stat = [
  imem_error || dmem_error: ASDR;
  !instr_valid            : SINS;
  icode == IHALT          : SHLT;
  1                       : SAOK;
];
```

**更新PC**

```text
word new_pc = [
  icode == ICALL       : valC; #调用函数时，会直接将PC更新为目标函数的地址
  icode == IJXX && Cnd : valC; #当条件跳转指令满足时，会跳转到目标地址
  icode == IRET        : valM; #ret会从内存中读取返回地址，所以是valM
  1                    : valP; #默认为valP
];
```

## 流水线

我们发现，指令执行的不同阶段是在处理器的不同硬件部分进行的，所以我们可以让不同的指令同时运行，只要它们处在不同的阶段。

若不使用流水线，每个指令都要等待其上一个指令完成后才可以进行，这降低了程序的运行速度。使用流水线可以提高系统的吞吐量，但是回轻微增加延迟。

想要吞吐量最大，我们需要使得时钟周期尽可能小，而时钟周期受到最慢的组合逻辑的限制，所以我们可以将最小的组合逻辑的时间加上一个寄存器的时延作为时钟周期。想要延迟最小，就不使用流水线。

如果将每个组合逻辑变得更小，虽然可以大大增加吞吐量，但是延迟在一个时间周期的占比也增加。 另一方面，处理器中某些硬件单元，如ALU和内存，并不能被划分成多个延迟很小的单元。所以，很难找到一个统一的足够小的单元来平衡各个阶段，在Y86-64中，不去深入这部分研究。

**带反馈的流水线**

在很多时候，相邻的两条指令数据是有关联的，即下一条指令可能回用到上一条指令计算的结果，这被称为**数据相关（data dependency）**。另一种情况，是当跳转指令在进行时，其后的两个指令是执行跳转前的，还是跳转后的，这成为**控制相关（control dependency）**。

为了解决上述问题一种思路是加入反馈路线，但是某一阶段产生的结果会成为N个阶段后的输入，而不是当前程序的状态，这改变了系统的行为，在实际中我们无法接受这样的后果。所以这种方式并不适用于流水线化的Y86-64。

**SEQ+**

为了平衡一个流水线系统各个阶段的延迟，需要使用**电路重定时（Circuit Retiming）**在不改变逻辑行为的基础上，修改系统的状态表示。顺序实现的SEQ中，更新PC阶段是在时钟周期结束时才执行的，通过组合电路计算得到的`icode`、`Cnd`、`valC`、`valM`和`valP`通过组合电路计算得到新的PC，将其保存到PC的时钟寄存器中。但是这些值是在不同阶段中计算出来的，所以SEQ+新增了一系列**状态寄存器**来保存之前计算出来的结果，然后将更新PC阶段放到了时钟周期开始执行，这样在每个阶段时钟周期变成高电平时就会将该阶段计算出来的值保存到状态寄存器中，然后PC逻辑电路就能根据当前的状态寄存器的值来预测下一步的PC值。

注意在SEQ+中，PC是动态移动的，即根据每一阶段的值来移动，没有特定的硬件寄存器来保存。

**插入流水线的PIPE-**

![](https://imgbed.niebelungen-d.top/images/2021/02/06/f4603bcc32d3bcc36d38654072276cfa.jpg)

- 分别插入了5个流水线寄存器用来保存后续阶段所需的信号，编号为`F`、`D`、`E`、`M`和`W`。我们可以发现在`D`和`E`中都有`stat`信号，分别表示为`D_stat`和`E_stat`。在取指阶段和访存阶段都有通过逻辑计算得到`stat`信号，分别表示为`f_stat`和`m_stat`。
- 在SEQ+中，在译码阶段通过逻辑电路计算得到`dstE`和`dstM`，会直接将其连接到寄存器文件的写端口的地址输入，当计算出`valE`和`valM`时直接写回到对应寄存器中。但是`dstE`和`dstM`是在译码阶段计算出来的，而`valE`是在执行阶段计算得到，`valM`是在访存阶段获得的，在流水线系统PIPE-中各个阶段是相互独立的，当某条指令运行到写回阶段时，得到了`valE`和`valM`，但是当前的`dstE`和`dstM`是处于译码阶段的指令计算出来的，会出现错误，所以需要将`dstE`和`dstM`一直保存到后续的流水线寄存器中。**通用规则：**我们要保存处于一个流水线阶段中的指令的所有信息。
- 我们可以发现，只有`call`指令需要将`valP`保存到内存中，即我们为了`call`指令需要将取指阶段得到的`valP`一直保存到后续的流水线寄存器中，直到访存阶段将其保存到内存中。但是我们发现`call`指令只使用`valB`保存`%rsp`的值，并不会使用`valA`，所以我们可以通过PIPE-中的`selectA`模块将`valP`保存到`valA`，由此就不需要保存`valP`了。同理条件跳转指令，当不选择跳转分支时，后面也需要`valP`，也可以将其保存到`valA`中，由此也不需要保存`valP`了。**通用规则：**通过合并信号来减少寄存器状态和线路的数量。

**注意：**大写字母`F`、`D`等代表流水线寄存器，所以`D_stat`代表是寄存器的状态字段，而小写前缀代表的是流水线阶段，所以`m_stat`代表访存阶段中由控制逻辑块产生的状态信号。

**预测下一个PC**

对于`call`和`jmp`指令，下一条指令的地址就是`valC`，而除了条件分支和`ret`指令外，下一条指令的地址就是`valP`，这些指令不存在控制相关，使得流水线处理器能够每个时钟周期就处理一条指令。如果出现了条件分支，则需要该指令运行到执行阶段后才知道是否选择该分支，如果出现了`ret`指令，则需要该指令运行到访存阶段，才知道返回地址。我们选择预测PC值总是为`valC`。

**流水线冒险**

流水线冒险主要包含数据冒险和控制冒险，当程序状态的读写**不处于同一阶段**，就可能出现数据冒险，当出现分支预测错误或`ret`指令时，会出现控制冒险。

解决方法：

- 用暂停来避免数据冒险：我们可以在执行阶段中插入一段自动产生的`nop`指令，来保持寄存器、内存、条件码和程序状态不变，使得当前指令停在译码阶段，并且会控制程序计数器不变，使得下一条指令停在取指阶段，直到产生指令的源操作数的指令通过了写回阶段。该方法指令要停顿最少一个最多三个时钟周期，严重降低整体的吞吐量。

- 用转发来避免数据冒险：通过ALU的计算结果来转发，虽然值没有写入寄存器，但是其确实被计算出来了`M_valE`和`e_valE`，所以可以改变译码方式来避免暂停和冒险。

  除了通过ALU的计算结果来转发，还能通过内存来进行转发，并且通过当前阶段的`dstE`和`dstM`与目标指令的`srcA`和`srcB`进行判断来决定是否转发。在处理器中，`valA`和`valB`一共有5个转发源：

  - `e_valE`：在执行阶段，ALU中计算得到的结果`valE`，通过`E_dstE`与`d_srcA`和`d_src_B`进行比较决定是否转发。
  - `M_valE`：将ALU计算的结果`valE`保存到流水线寄存器M中，通过`M_dstE`与`d_srcA`和`d_src_B`进行比较决定是否转发。
  - `m_valM`：在访存阶段，从内存中读取的值`valM`，通过`M_dstM`与`d_srcA`和`d_src_B`进行比较决定是否转发。
  - `W_valM`：将内存中的值`valM`保存到流水线寄存器W中，通过`W_dstM`与`d_srcA`和`d_src_B`进行比较决定是否转发。
  - `W_valE` ：将ALU计算的结果`valE`保存到流水线寄存器W中，通过`W_dstE`与`d_srcA`和`d_src_B`进行比较决定是否转发。

- 加载/使用数据冒险：有些冒险无法通过转发来清除。我们可以对产生冒险的指令暂停一个周期。称为“**加载互锁（Load Interlock）**”

- 避免控制冒险：控制冒险只会出现在`ret`指令和跳转指令预测错方向时产生。解决方法是插入bubble（？）

  **异常处理**

异常可以由程序执行从内部产生，也可以由某个外部信号从外部产生。当前的ISA包含三种内部产生的异常：1. halt指令；2. 非法指令码和功能码组合的指令；3. 取值或数据读写访问非法地址。外部产生的异常包括：接收到一个网络接口受到新包的信号、点击鼠标的信号等等。

1. 当同时多条指令引起异常时，处理器应该向操作系统报告哪个异常？**基本原则：**由流水线中最深的指令引起的异常，优先级最高，因为指令在流水线中越深的阶段，表示该指令越早执行。
2. 在分支预测中，当预测分支中出现了异常，而后由于预测错误而取消该指令时，需要取消异常。

暂停和气泡是流水线中低级的机制，**暂停**能将指令阻塞在某个阶段，往流水线中插入**bubble**能使得流水线继续运行，但是不会改变当前阶段的寄存器、内存、条件码或程序状态。这两个状态决定了当时钟电平变高时，如何修改流水线寄存器。
