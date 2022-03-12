# CSAPP Archlab


# CSAPP-Archlab

<!--more-->

## part A

使用Y86-64指令集实现`example.c`中的函数

```c
/* 
 * Architecture Lab: Part A 
 * 
 * High level specs for the functions that the students will rewrite
 * in Y86-64 assembly language
 */

/* $begin examples */
/* linked list element */
typedef struct ELE {
    long val;
    struct ELE *next;
} *list_ptr;

/* sum_list - Sum the elements of a linked list */
long sum_list(list_ptr ls)
{
    long val = 0;
    while (ls) {
	val += ls->val;
	ls = ls->next;
    }
    return val;
}

/* rsum_list - Recursive version of sum_list */
long rsum_list(list_ptr ls)
{
    if (!ls)
	return 0;
    else {
	long val = ls->val;
	long rest = rsum_list(ls->next);
	return val + rest;
    }
}

/* copy_block - Copy src to dest and return xor checksum of src */
long copy_block(long *src, long *dest, long len)
{
    long result = 0;
    while (len > 0) {
	long val = *src++;
	*dest++ = val;
	result ^= val;
	len--;
    }
    return result;
}
/* $end examples */
```

### sum_list

```assembly
  .pos 0
  irmovq stack,%rsp
  call main
  halt

#link list
.align 8
ele1:
  .quad 0x00a
  .quad ele2
ele2:
  .quad 0x0b0
  .quad ele3
ele3:
  .quad 0xc00
  .quad 0 
  
main:
  irmovq ele1,%rdi
  call sum_list
  ret
  
sum_list:
  pushq %r10
  irmovq $0x0,%rax
  jmp test
sum:
  mrmovq (%rdi),%r10
  addq %r10,%rax			#val+=ls.val
  mrmovq 8(%rdi),%rdi		#ls=ls.next  
test:
  andq %rdi,%rdi
  jne sum
  popq %r10
  ret

 .pos 0x200
stack:
```

思路其实很简单，对着c代码写就可，这里使用了`while`循环的优化。为了保存原来寄存器的值要先将其入栈。

```shell
niebelungen@ubuntu:~/Desktop/archlab-handout/sim/misc$ ./yis sum.yo
Stopped in 28 steps at PC = 0x13.  Status 'HLT', CC Z=1 S=0 O=0
Changes to registers:
%rax:	0x0000000000000000	0x0000000000000cba
%rsp:	0x0000000000000000	0x0000000000000200

Changes to memory:
0x01f0:	0x0000000000000000	0x000000000000005b
0x01f8:	0x0000000000000000	0x0000000000000013
```

`rax`中的结果是正确的。

### rsum_list

```assembly
  .pos 0
  irmovq stack,%rsp
  call main
  halt

#link list
.align 8
ele1:
  .quad 0x00a
  .quad ele2
ele2:
  .quad 0x0b0
  .quad ele3
ele3:
  .quad 0xc00
  .quad 0 
  
main:
  irmovq ele1,%rdi
  call rsum_list
  ret
  
rsum_list:
  pushq %r10
  xor %rax,%rax 		#irmovq $0x0,%rax
  andq %rdi,%rdi
  je end
  mrmovq (%rdi),%r10  
  mrmovq 8(%rdi),%rdi
  call rsum_list
  addq %r10,%rax
end:
  popq %r10
  ret
 .pos 0x200
stack:
```
使用递归的方式完成求和，那么`rdi`和`rax`的值都是变化的，这里要想到通过多余的寄存器保存当前的值，便于通过`addq`进行相加。

```shell
niebelungen@ubuntu:~/Desktop/archlab-handout/sim/misc$ ./yis rsum.yo
Stopped in 42 steps at PC = 0x13.  Status 'HLT', CC Z=0 S=0 O=0
Changes to registers:
%rax:	0x0000000000000000	0x0000000000000cba
%rsp:	0x0000000000000000	0x0000000000000200

Changes to memory:
0x01b8:	0x0000000000000000	0x0000000000000c00
0x01c0:	0x0000000000000000	0x0000000000000088
0x01c8:	0x0000000000000000	0x00000000000000b0
0x01d0:	0x0000000000000000	0x0000000000000088
0x01d8:	0x0000000000000000	0x000000000000000a
0x01e0:	0x0000000000000000	0x0000000000000088
0x01f0:	0x0000000000000000	0x000000000000005b
0x01f8:	0x0000000000000000	0x0000000000000013
```

### copy_block

```assembly
  .pos 0
  irmovq stack,%rsp
  call main
  halt

  .align 8
# Source block
src:
  .quad 0x00a
  .quad 0x0b0
  .quad 0xc00
# Destination block
dest:
  .quad 0x111
  .quad 0x222
  .quad 0x333
  
main:
  irmovq $0x3,%rdx
  irmovq dest,%rsi
  irmovq src,%rdi
  call copy_block
  ret
  
copy_block:
  pushq %r8
  pushq %r9
  pushq %r10
  irmovq $0x8,%r8
  irmovq $0x1,%r9
  xorq %rax,%rax
  jmp test
copy:
  mrmovq (%rdi),%r10
  rmmovq %r10,(%rsi)
  xorq %r10,%rax
  addq %r8,%rdi
  addq %r8,%rsi
  subq %r9,%rdx
test:
  andq %rdx,%rdx
  jne copy
  popq %r10
  popq %r9
  popq %r8
  ret
  
 .pos 0x200
stack:
```


```shell
niebelungen@ubuntu:~/Desktop/archlab-handout/sim/misc$ ./yis copy_block.yo
Stopped in 45 steps at PC = 0x13.  Status 'HLT', CC Z=1 S=0 O=0
Changes to registers:
%rax:	0x0000000000000000	0x0000000000000cba
%rsp:	0x0000000000000000	0x0000000000000200
%rsi:	0x0000000000000000	0x0000000000000048
%rdi:	0x0000000000000000	0x0000000000000030

Changes to memory:
0x0030:	0x0000000000000111	0x000000000000000a
0x0038:	0x0000000000000222	0x00000000000000b0
0x0040:	0x0000000000000333	0x0000000000000c00
0x01f0:	0x0000000000000000	0x000000000000006f
0x01f8:	0x0000000000000000	0x0000000000000013
```

## part B

修改`seq-fun.hcl`使其支持`iaddq`

|    阶段    |                         iaddq V, rB                          |
| :--------: | :----------------------------------------------------------: |
|   Fetch    | `icode`: `ifun`&larr; $M_1[PC]$  <br/>`rA`: `rB`&larr; $M_1[PC+1]$ <br/>`valC` &larr; $M_s[PC+2]$  <br/>`valP` &larr; PC+10 |
|   Decode   |                  <br>`valB` &larr; $R[rB]$                   |
|  Execute   |            `valE` &larr; `valC`+`valB`<br>Set CC             |
|   Memory   |                                                              |
| Write Back |                     R[rB] &larr; `valE`                      |
| PC Update  |                       PC &larr; `valP`                       |

填好表格，对应阶段进行修改就可以了。

```shell
niebelungen@ubuntu:~/Desktop/archlab-handout/sim/seq$  (cd ../ptest; make SIM=../seq/ssim TFLAGS=-i)
./optest.pl -s ../seq/ssim -i
Simulating with ../seq/ssim
  All 58 ISA Checks Succeed
./jtest.pl -s ../seq/ssim -i
Simulating with ../seq/ssim
  All 96 ISA Checks Succeed
./ctest.pl -s ../seq/ssim -i
Simulating with ../seq/ssim
  All 22 ISA Checks Succeed
./htest.pl -s ../seq/ssim -i
Simulating with ../seq/ssim
  All 756 ISA Checks Succeed
```

## part C

修改`ncopy.ys`使得`ncopy`函数尽可能快。首先，可以在`pipe-full.hcl`文件中增加`iaddq`指令。

```assembly
	xorq %rax,%rax		# count = 0;
	andq %rdx,%rdx		# len <= 0?
	jle Done		# if so, goto Done:

Loop:	mrmovq (%rdi), %r10	# read val from src...
	rmmovq %r10, (%rsi)	# ...and store it to dst
	andq %r10, %r10		# val <= 0?
	jle Npos		# if so, goto Npos:
	iaddq $1, %rax		# count++
Npos:  iaddq $-1, %rdx		# len--
	iaddq $8, %rdi		# src++
	iaddq $8, %rsi		# dst++
	andq %rdx,%rdx		# len > 0?
	jg Loop			# if so, goto Loop:
```

之后进行循环展开，这里进行了四路循环展开，注意到，`mrmovq (%rdi), %r10`和`rmmovq %r10, (%rsi)`之间有数据关联，所以引入一个寄存器消除气泡。且在程序一开始`rax`必然为0，去除`xorq %rax,%rax`。

```assembly
	iaddq $-4,%rdx
	jl Last1
	
Loop:
	mrmovq (%rdi),%r10
	mrmovq 8(%rdi),%r11
	rmmovq %r10,(%rsi)
	andq %r10, %r10
	jle Npos1
	iaddq $1,%rax

Npos1:
 	mrmovq 16(%rdi),%r10
	rmmovq %r11,8(%rsi)
	andq %r11, %r11
	jle Npos2
	iaddq $1,%rax
	
Npos2:
 	mrmovq 24(%rdi),%r11
	rmmovq %r10,16(%rsi)
	andq %r10, %r10
	jle Npos3
	iaddq $1,%rax
	
Npos3:
	rmmovq %r11,24(%rsi)
	andq %r11, %r11
	jle Npos
	iaddq $1,%rax

Npos:
	iaddq $32,%rdi
	iaddq $32,%rsi
	iaddq $-4,%rdx
	jge Loop
	
Last1:
	iaddq $4,%rdx
	iaddq $-1,%rdx
	jl Done
 	mrmovq (%rdi),%r10
 	mrmovq 8(%rdi),%r11
	rmmovq %r10,(%rsi)
	andq %r10, %r10
	jle Last2
	iaddq $1,%rax
	
Last2:
	iaddq $-1,%rdx
	jl Done
 	mrmovq 16(%rdi),%r10
	rmmovq %r11,8(%rsi)
	andq %r11, %r11
	jle Last3
	iaddq $1,%rax
	
Last3:
	iaddq $-1,%rdx
	jl Done
	rmmovq %r10,16(%rsi)
	andq %r10, %r10
	jle Done
	iaddq $1,%rax
```

目前得分：48.5/60  ，再展开为八路

```assembly
	iaddq $-8,%rdx
	jl Last1
	
Loop:
	mrmovq (%rdi),%r10
	mrmovq 8(%rdi),%r11
	rmmovq %r10,(%rsi)
	andq %r10, %r10
	jle Npos1
	iaddq $1,%rax

Npos1:
 	mrmovq 16(%rdi),%r10
	rmmovq %r11,8(%rsi)
	andq %r11, %r11
	jle Npos2
	iaddq $1,%rax
	
Npos2:
 	mrmovq 24(%rdi),%r11
	rmmovq %r10,16(%rsi)
	andq %r10, %r10
	jle Npos3
	iaddq $1,%rax
	
Npos3:
 	mrmovq 32(%rdi),%r10
	rmmovq %r11,24(%rsi)
	andq %r11, %r11
	jle Npos4
	iaddq $1,%rax
	
Npos4:
 	mrmovq 40(%rdi),%r11
	rmmovq %r10,32(%rsi)
	andq %r10, %r10
	jle Npos5
	iaddq $1,%rax
	
Npos5:
 	mrmovq 48(%rdi),%r10
	rmmovq %r11,40(%rsi)
	andq %r11, %r11
	jle Npos6
	iaddq $1,%rax
	
Npos6:
 	mrmovq 56(%rdi),%r11
	rmmovq %r10,48(%rsi)
	andq %r10, %r10
	jle Npos7
	iaddq $1,%rax
	
Npos7:
	rmmovq %r11,56(%rsi)
	andq %r11, %r11
	jle Npos
	iaddq $1,%rax
	
Npos:
	iaddq $64,%rdi
	iaddq $64,%rsi
	iaddq $-8,%rdx
	jge Loop
	
Last1:
	iaddq $8,%rdx
	iaddq $-1,%rdx
	jl Done
 	mrmovq (%rdi),%r10
 	mrmovq 8(%rdi),%r11
	rmmovq %r10,(%rsi)
	andq %r10, %r10
	jle Last2
	iaddq $1,%rax
	
Last2:
	iaddq $-1,%rdx
	jl Done
 	mrmovq 16(%rdi),%r10
	rmmovq %r11,8(%rsi)
	andq %r11, %r11
	jle Last3
	iaddq $1,%rax
	
Last3:
	iaddq $-1,%rdx
	jl Done
 	mrmovq 24(%rdi),%r11
	rmmovq %r10,16(%rsi)
	andq %r10, %r10
	jle Last4
	iaddq $1,%rax
	
Last4:
	iaddq $-1,%rdx
	jl Done
 	mrmovq 32(%rdi),%r10
	rmmovq %r11,24(%rsi)
	andq %r11, %r11
	jle Last5
	iaddq $1,%rax
	
Last5:
	iaddq $-1,%rdx
	jl Done
 	mrmovq 40(%rdi),%r11
	rmmovq %r10,32(%rsi)
	andq %r10, %r10
	jle Last6
	iaddq $1,%rax
	
Last6:
	iaddq $-1,%rdx
	jl Done
 	mrmovq 48(%rdi),%r10
	rmmovq %r11,40(%rsi)
	andq %r11, %r11
	jle Last7
	iaddq $1,%rax
	
Last7:
	iaddq $-1,%rdx
	jl Done
	rmmovq %r10,48(%rsi)
	andq %r10, %r10
	jle Done
	iaddq $1,%rax
```

目前得分：50.1/60 ，目前我们的代码是817字节，展开为十路，超出字节限制。然后发现在，剩余部分处理时，我们多次重复执行了`iaddq $-1,%rdx`，`jl Done`所以接下来想办法简化剩余处理。首先，从确定长度入手，长度确定进行优化后，可以跳转到剩余长度的位置，简化处理。

```assembly
	iaddq $-9,%rdx
	jl Find
	
Loop:
	mrmovq (%rdi),%r10
	mrmovq 8(%rdi),%r11
	rmmovq %r10,(%rsi)
	andq %r10, %r10
	jle Npos1
	iaddq $1,%rax

Npos1:
 	mrmovq 16(%rdi),%r10
	rmmovq %r11,8(%rsi)
	andq %r11, %r11
	jle Npos2
	iaddq $1,%rax
	
Npos2:
 	mrmovq 24(%rdi),%r11
	rmmovq %r10,16(%rsi)
	andq %r10, %r10
	jle Npos3
	iaddq $1,%rax
	
Npos3:
 	mrmovq 32(%rdi),%r10
	rmmovq %r11,24(%rsi)
	andq %r11, %r11
	jle Npos4
	iaddq $1,%rax
	
Npos4:
 	mrmovq 40(%rdi),%r11
	rmmovq %r10,32(%rsi)
	andq %r10, %r10
	jle Npos5
	iaddq $1,%rax
	
Npos5:
 	mrmovq 48(%rdi),%r10
	rmmovq %r11,40(%rsi)
	andq %r11, %r11
	jle Npos6
	iaddq $1,%rax
	
Npos6:
 	mrmovq 56(%rdi),%r11
	rmmovq %r10,48(%rsi)
	andq %r10, %r10
	jle Npos7
	iaddq $1,%rax
	
Npos7:
 	mrmovq 64(%rdi),%r10
	rmmovq %r11,56(%rsi)
	andq %r11, %r11
	jle Npos8
	iaddq $1,%rax
	
Npos8:
	rmmovq %r10,64(%rsi)
	andq %r10, %r10
	jle Npos
	iaddq $1,%rax
	
Npos:
	iaddq $72,%rdi
	iaddq $72,%rsi
	iaddq $-9,%rdx
	jge Loop
	
Find:
	iaddq $6,%rdx 
	jl  Left
	jg Right
	jmp Last3
Left:
	iaddq $2,%rdx		
	je Last1
	iaddq $-1,%rdx
	je Last2
	jmp Done
RL:	
	iaddq $1,%rdx
	jl Last4
	jmp Last5			
Right:	
	iaddq $-3,%rdx
	jl RL
	jg RR
	jmp Last6	
RR:	
	iaddq $-1,%rdx
	je Last7

Last8:
	mrmovq 56(%rdi),%r10
	andq %r10,%r10
	rmmovq %r10,56(%rsi)	
	jl Last7
	iaddq $1,%rax
	
Last7:
	mrmovq 48(%rdi),%r10
	andq %r10,%r10
	rmmovq %r10,48(%rsi)
	jl Last6
	iaddq $1,%rax

Last6:
	mrmovq 40(%rdi),%r10
	andq %r10,%r10
	rmmovq %r10,40(%rsi)
	jl Last5
	iaddq $1,%rax
	
Last5:
	mrmovq 32(%rdi),%r10
	andq %r10,%r10
	rmmovq %r10,32(%rsi)
	jl Last4
	iaddq $1,%rax
	
Last4:
	mrmovq 24(%rdi),%r10
	andq %r10,%r10
	rmmovq %r10,24(%rsi)
	jl Last3
	iaddq $1,%rax
	
Last3:
	mrmovq 16(%rdi),%r10
	andq %r10,%r10
	rmmovq %r10,16(%rsi)
	jl Last2
	iaddq $1,%rax
	
Last2:
	mrmovq 8(%rdi),%r10
	andq %r10,%r10
	rmmovq %r10,8(%rsi)
	jl Last1
	iaddq $1,%rax
	
Last1:
	mrmovq (%rdi),%r10
	andq %r10,%r10
	rmmovq %r10,(%rsi)
	jl Done
	iaddq $1,%rax
```

当前分数：56.6/60，尽力了。。。

