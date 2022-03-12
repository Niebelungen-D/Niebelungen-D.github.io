# eBPF-Basic-Learning


# eBPF

# What is eBPF ？

eBPF 全称是 extended Berkeley Packet Filter ，起源于 BPF ( Berkeley Packet Filter )。顾名思义，它向linux内核提供了对数据包的过滤。

早期的网络监控器等都是作为用户级进程运行的。为了分析只在内核空间运行的数据，它们必须将这些数据从内核空间复制到用户空间的内存中去，并进行上下文切换。这与直接在内核空间分析这些数据相比，导致了巨大的性能开销。

BPF 就是解决这一问题的一种在内核空间执行高效安全的程序的机制。

BPF 在数据包过滤上引入了两大革新：

- 一个新的虚拟机 (VM) 设计，可以有效地工作在基于寄存器结构的 CPU 之上；
- 应用程序使用缓存只复制与过滤数据包相关的数据，不会复制数据包的所有信息，最大程度地减少BPF 处理的数据，提高处理效率；

发展到今天，BPF 升级为 eBPF 。它演进成为了一套通用执行引擎，提供可基于系统或程序事件高效安全执行特定代码的通用能力，通用能力的使用者不再局限于内核开发者。原来的 BPF 被称为 cBPF （classic BPF）已被舍弃。

下面是 eBPF 的大致原理图：

![https://ebpf.io/static/loader-7eec5ccd8f6fbaf055256da4910acd5a.png](https://ebpf.io/static/loader-7eec5ccd8f6fbaf055256da4910acd5a.png)

用户可以通过创建内核探针（kprobe）或用户探针（uprobe）在几乎任何地方附加eBPF程序。

在我刚开始阅读 eBPF 的相关资料时，就在想，这不就是一个数据过滤吗。但是现在想想吧，你可以在几乎内核的任何地方加入自己的代码。向内核加入用户输入，这本身就是一个大胆创新的想法，而加入自己的程序这是多么令人激动！

![https://ebpf.io/static/hook_overview-99c69bbff092c35b9c83f00a80fed240.png](https://ebpf.io/static/hook_overview-99c69bbff092c35b9c83f00a80fed240.png)

# How does it work ？

正如原理图中展示的那样，用户需要首先使用 eBPF 指令集编写相应的 eBPF 程序，然后将程序字节码和程序类型送入内核，程序类型决定了可以访问的内核区域（各种Helper Calls）。

## 验证

为了确保安全，内核首先对传入的程序进行验证。

第一轮检查程序是否为一个有向无环图DAG，第二轮检查，它会拒绝下面的程序：

- 指令个数大于`BPF_MAXINSNS`（4096）
- 有循环
- 有无法到达的指令（程序结构只能是一个函数不能是森林）
- 越界或畸形跳跃

每个**寄存器状态**都有一个**类型**，

- `NOT_INIT`：该寄存器还未写入数据
- `SCALAR_VALUE`：标量值，不可作为指针
- 指针类型

依据它们**指向的数据结构类型**，又可以分为：

1. `PTR_TO_CTX`：指向 **`bpf_context`** 的指针。
2. `CONST_PTR_TO_MAP`：指向 **`struct bpf_map`** 的指针。 是**常量**（const），因为不允许对这种类型指针进行算术操作。
3. `PTR_TO_MAP_VALUE`：指向 bpf **map 元素**的指针。
4. `PTR_TO_MAP_VALUE_OR_NULL`：指向 bpf map 元素的指针，可为 NULL。 **访问 map 的操作**会返回这种类型的指针。**禁止算术操作**。
5. `PTR_TO_STACK`：帧指针（Frame pointer）。
6. `PTR_TO_PACKET`：指向 **`skb->data`** 的指针。
7. `PTR_TO_PACKET_END`：指向 **`skb->data + headlen`** 的指针。禁止算术操作。
8. `PTR_TO_SOCKET`：指向 **`struct bpf_sock_ops`** 的指针，内部有引用计数。
9. `PTR_TO_SOCKET_OR_NULL`：指向 **`struct bpf_sock_ops`** 的指针，或 NULL。
   
    **socket lookup 操作**会返回这种类型。**有引用计数**， 因此程序在执行结束时，必须通过 socket release 函数释放引用。禁止算术操作。
    

这些指针都称为 base 指针

## JIT

通过验证后，它就会进入JIT编译阶段，利用Just-In-Time编译器，编译生成的是通用的字节码，它是完全可移植的，可以在x86和ARM等任意球CPU架构上加载这个字节码，这样我们能获得本地编译后的程序运行速度，而且是安全可靠的。

## Maps

maps 是 eBPF 的数据存储数据库，在程序中由用户通过相应的函数创建，它支持以下类型：

- Hash tables, Arrays
- LRU (Least Recently Used)
- Ring Buffer
- Stack Trace
- LPM (Longest Prefix match)
- ……

一个定义的例子：

```c
// SEC("maps") 表示将这个结构编译到一个新创建的名为 maps 的 .section
struct bpf_map_def SEC("maps") my_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(long),
    .max_entries = 256,
};

```

值得注意的是：

- BPF Map是可以被用户空间访问并操作的
- BPF Map是可以与BPF程序分离的，即当创建一个BPF Map的BPF程序运行结束后，该BPF Map还能存在，而不是随着程序一起消亡

## Helper Calls

在 eBPF 的程序中不能直接调用内核函数。因为内核版本不断更新，很多函数会发生变化，这可能导致 eBPF 的失效。为了避免这样，内核提供了 helper calls 的 API，无需了解其实现，只需使用即可。另一方面，这也拓展了 eBPF 的功能。

[bpf-helpers(7) - Linux manual page](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)

# 指令集

eBPF 的指令结构如下：

```c
struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};
```

在 eBPF 中有 11 个 64位寄存器 R0-R10 

|  R0   |  返回值寄存器  |
| :---: | :------------: |
| R1-R5 |    函数参数    |
| R6-R9 | 被调用函数保留 |
|  R10  | 只读栈帧寄存器 |

其栈的大小固定为512字节。当一个 eBPF 程序启动时，R1 中的地址指向 context 上下文（当前情况下为数据包缓冲区）

## opcode 结构

```c
+-------------------------+--------------------+
|       5 bits            |   3 bits           |
|       xxxxxx            | instruction class  |
+-------------------------+--------------------+
(MSB)                                      (LSB)
```

op字段的低3位，决定指令类型。

Code: include/uapi/linux/bpf.h

```c
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define BPF_JMP32	0x06	/* jmp mode in word width */
#define BPF_ALU64	0x07	/* alu mode in double word width */
```

- BPF_LD, BPF_LDX: 两个类都用于加载操作。BPF_LD用于加载双字。后者是从 cBPF 继承而来的，主要是为了保持 cBPF 到 BPF 的转换效率，因为它们优化了 JIT 代码。
- BPF_ST, BPF_STX: 两个类都用于存储操作，用于将数据从寄存器到存储器中。
- BPF_ALU, BPF_ALU64: 分别是32位和64位下的ALU操作。
- BPF_JMP和BPF_JMP32：跳转指令。JMP32的跳转范围是32位大小(一个 word)

### 加载和存储指令

此时：

```c
+--------+--------+-------------------+
| 3 bits | 2 bits |   3 bits          |
|  mode  |  size  | instruction class |
+--------+--------+-------------------+
(MSB)                             (LSB)
```

size决定了操作数据的大小

```c
BPF_W   0x00    /* word=4 byte */
BPF_H   0x08    /* half word */
BPF_B   0x10    /* byte */
BPF_DW  0x18    /* eBPF only, double word */
```

mode

```c
BPF_IMM     0x00  /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
BPF_ABS     0x20
BPF_IND     0x40
BPF_MEM     0x60
BPF_LEN     0x80  /* classic BPF only, reserved in eBPF */
BPF_MSH     0xa0  /* classic BPF only, reserved in eBPF */
BPF_ATOMIC  0xc0  /* eBPF only, atomic operations */
```

### 跳转与运算指令

此时：

```c
+----------------+--------+--------------------+
|   4 bits       |  1 bit |   3 bits           |
| operation code | source | instruction class  |
+----------------+--------+--------------------+
(MSB)                                      (LSB)
```

```c
#define BPF_SRC(code)   ((code) & 0x08)
BPF_K     0x00
BPF_X     0x08

BPF_SRC(code) == BPF_X - use 'src_reg' register as source operand
BPF_SRC(code) == BPF_K - use 32-bit immediate as source operand
```

可以使用以下宏定义快速的编写指令，Code: samples/bpf/bpf_insn.h：

```c
/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* eBPF instruction mini library */
#ifndef __BPF_INSN_H
#define __BPF_INSN_H

struct bpf_insn;

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD	1
#endif

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/*
 * Atomic operations:
 *
 *   BPF_ADD                  *(uint *) (dst_reg + off16) += src_reg
 *   BPF_AND                  *(uint *) (dst_reg + off16) &= src_reg
 *   BPF_OR                   *(uint *) (dst_reg + off16) |= src_reg
 *   BPF_XOR                  *(uint *) (dst_reg + off16) ^= src_reg
 *   BPF_ADD | BPF_FETCH      src_reg = atomic_fetch_add(dst_reg + off16, src_reg);
 *   BPF_AND | BPF_FETCH      src_reg = atomic_fetch_and(dst_reg + off16, src_reg);
 *   BPF_OR | BPF_FETCH       src_reg = atomic_fetch_or(dst_reg + off16, src_reg);
 *   BPF_XOR | BPF_FETCH      src_reg = atomic_fetch_xor(dst_reg + off16, src_reg);
 *   BPF_XCHG                 src_reg = atomic_xchg(dst_reg + off16, src_reg)
 *   BPF_CMPXCHG              r0 = atomic_cmpxchg(dst_reg + off16, r0, src_reg)
 */

#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = OP })

/* Legacy alias */
#define BPF_STX_XADD(SIZE, DST, SRC, OFF) BPF_ATOMIC_OP(SIZE, BPF_ADD, DST, SRC, OFF)

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_REG(OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

#endif
```

# Security

虽然内核对用户输入做了很多的防护，但是依然没有阻止 eBPF 作为新的内核攻击面。

## OOB

用户与内核唯一的屏障是 verify ，如果绕过那么就可以实现注入了。 eBPF 会对读取对应类型的内核缓冲区 context 和 map，这里涉及到，程序读取的值不能马上确定，而程序又要对数据进行其他的运算，如何保证得到的数据等不超界？

eBPF 寄存器结构：

```c
struct bpf_reg_state {
	/* Ordering of fields matters.  See states_equal() */
	enum bpf_reg_type type;
	union {
		/* valid when type == PTR_TO_PACKET */
		u16 range;

		/* valid when type == CONST_PTR_TO_MAP | PTR_TO_MAP_VALUE |
		 *   PTR_TO_MAP_VALUE_OR_NULL
		 */
		struct bpf_map *map_ptr;

		/* Max size from any of the above. */
		unsigned long raw;
	};
	s32 off;
	u32 id;
	u32 ref_obj_id;

	struct tnum var_off;
	s64 smin_value; /* minimum possible (s64)value */
	s64 smax_value; /* maximum possible (s64)value */
	u64 umin_value; /* minimum possible (u64)value */
	u64 umax_value; /* maximum possible (u64)value */

	struct bpf_reg_state *parent;
	u32 frameno;
	s32 subreg_def;
	enum bpf_reg_liveness live;
	bool precise;
};

struct tnum {
	u64 value;
	u64 mask;
};
```

- `umin_value`和 `umax_value`：当解释器将寄存器的值解释为无符号整数时的最小值和最大值
- `smin_value` 和 `smax_value`：当解释器将寄存器的值解释为有符号整数时的最小值和最大值
- `var_off`: 用来描述无法确定的值，既然有待定的值，一个位的状态就变成了三种，‘0’、‘1’和未知。如果一个数的某位是确定的，那么其在value中的值就是它的真值，对应mask中的位为0，如果某位无法确定，那么mask中对应的位为1。

例如： `var_off→value = 0b010, value->mask = 0b100`，那么这个值就可能为0b010或0b110。

上述这五个数据可以相互更新，例如如果 `umax_value` 小于 `2^63`，则 `smin_value` 会被设置为 0（因为不会有负数出现），如果 `var_off` 指示寄存器只有最低 3 位可能为 `1,`则 `umax_value` 为 7。

# Reference

[Linux超能力BPF技术介绍及学习分享（附PPT）](https://davidlovezoe.club/wordpress/archives/1122)

[What is eBPF? An Introduction and Deep Dive into the eBPF Technology](https://ebpf.io/what-is-ebpf)

[[译] Linux Socket Filtering (LSF, aka BPF)（KernelDoc，2021）](https://arthurchiao.art/blog/linux-socket-filtering-aka-bpf-zh/#6-bpf-kernel-internalsebpf)

