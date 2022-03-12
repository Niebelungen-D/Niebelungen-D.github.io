# Assembly 1


# 汇编语言（1）

> 教程使用王爽老师的《汇编语言》（第三版），这里仅仅介绍了32位处理器，建议再阅读近几年的教程学习64位处理器的一些结构与指令。

>如果你有一些c或c++的语言基础，在学习汇编时会更加深刻的理解数组、内存等基本概念，其中也有很多规定对应了现在的计算机为什么那么设置。
>
>总之，建议认真学习。
<!-- more -->

## 1、基础知识

存储单元的概念，CPU对存储器的读写，地址总线，数据总线，控制总线

内存地址空间，RAM,ROM

## 2、寄存器

### 1、通用寄存器

AX,BX,CX,DX存放一般数据的16位寄存器，可分为八位寄存器使用-H,-L。

### 2、CPU给出物理地址

CPU将内存分段，基础地址（段地址×16）+偏移地址=物理地址

### 3、段寄存器

CS,DS,SS,ES段寄存器，CS为代码段寄存器，IP为指令指针寄存器

>1、从CS：IP指向的内存单元读取指令，读取的指令进入指令缓冲器：
>
>2、IP=IP+所读取指令的长度，从而指向下一条指令：
>
>3、执行指令。转到步骤1，重复这个过程。

### 4、几个汇编指令

```assembly
mov ax,dx	 ;dx中的值放入ax中，dx不变
mov ax,16	 ;ax中的值+16
mov al,dh	 ;dh中的值放入al中
add ax,dx	 ;ax=ax+dx
add ah,4 	 ;ah=ah+4
jmp 1000:3	 ;cs=1000,ip=3，jmp用来修改cs：ip的值
jmp bx		 ;ip=bx
```

### 5、实验1

查看、修改CPU中寄存器的内容：R命令

查看内存中的内容：D命令

修改内存中的内容：E命令

将内存中的内容解释为机器指令和对应的汇编指令：U命令

执行CS:IP指向的内存单元处的指令：T命令

以汇编指令的形式向内存中写入指令：A命令3

## 3、寄存器（内存访问）

字单元：存放一个字型数据（16位）的内存单元

### 1、DS寄存器：

通常用来存放要访问数据的段地址。

```assembly
mov bx,1000H		
mov ds,bx		；ds不支持直接送入数据，所以用bx做中转。
mov ax,[0]		；将1000：0内存单元的字型数据放入ax
；[···]表示一个内存单元，[]其中的值代表偏移地址
；[0]的段地址，系统自动访问ds
```

### 2、mov，add，sub

```assembly
sub ax,bx	;ax=ax-bx
```

|        操作        | mov  | add  | sub  |
| :----------------: | :--: | :--: | :--: |
|    寄存器，数据    |  1   |  1   |  1   |
|   寄存器，寄存器   |  1   |  1   |  1   |
|  寄存器，内存单元  |  1   |  1   |  1   |
|  内存单元，寄存器  |  1   |  1   |  1   |
|  段寄存器，寄存器  |  1   |  0   |  0   |
|  寄存器，段寄存器  |  1   |  0   |  0   |
| 内存单元，段寄存器 |  1   |  0   |  0   |

### 3、数据段

专门用来存储数据的一段内存空间

### 4、栈

```assembly
push ax		;入栈，将ax中的数据放入栈
pop ax		;出栈，将栈顶的数据取出到ax
```

段寄存器SS：存放栈顶的段地址，寄存器SP：存放栈顶的偏移地址。

任意时刻SS：SP指向栈顶元素。栈为空时，不存在栈顶元素。

> push ax：
>
> （1）：SP=SP-2，栈顶更新；
>
> （2）：将ax中的数据送入SS：SP指向的内存单元

> pop ax:
>
> （1）：将栈顶的数据取出到ax；SP=SP+2
>
> （2）：SP=SP+2，栈顶更新；

> pop，push可以对寄存器，段寄存器，内存单元进行操作。

**栈顶超界问题**

向上，向下溢出，造成对其他内存单元数据的覆盖，暴露。

## 4、第一个程序

### 1、一些基本概念

程序的执行过程：

> （1）编写汇编源程序，产生一个文本文件(.asm)。
>
> （2）对源程序进行编译连接，编译产生目标文件(.obj)，将目标文件进行连接，产生可执行文件（.exe）。
>
> （3）执行可执行文件中的程序。

### 2、伪指令

伪指令，由编译器执行，汇编指令被编译为机器码由CPU执行。

```assembly
assume cs:abc	;assume将名为abc的代码段与cs联系
abc segment		;段的开始

	mov ax,2
	add ax,ax
	add ax,ax

mov ax,4c00h	;这两句代表程序返回
int 21h			;int，Debug中用p命令执行

abc ends		;段的结束
end				;程序的结束
```

### 3、程序执行的跟踪

command.com运行后，将程序1.exe加载入内存，command设置CPU的CS:IP指向程序的第一条指令，之后command将CPU的控制权交给程序，程序运行完成后，返回到command。

CX寄存器存放了程序长度，DS=SA,CS:IP指向SA+10H:0

> 空闲内存区：SA:0
>
> PSP区：SA:0		256个字节
>
> 程序区：SA+10H:0

## 5、[bx]和loop指令

### 1、[bx]&一些基本概念

（1）[bx]代表一个内存单元，其段地址在ds中，偏移地址在bx中。

（2）loop代表循环

（3）“（）”来表示一个寄存器或一个内存单元中的内容

```text
（ax）（ds）	ax，ds中的值
（20000H）	20000处内存单元的值
（（ds）*16+2）		内存单元ds：2处的值
```

（4）约定符号idata表示常量

### 2、loop指令

```assembly
	mov cx,11	
s:	add ax,ax	；s为标号，代表一段地址
	loop s		；（cx）=（cx）-1，若（cx）不为0，跳转至s处执行，若为0，向下执行。
```

**在汇编源程序中，数据不能以字母开头。**

在调试时，可以用g命令跳到下一条语句，也可以用p命令。

### 3、Debug和编译器对指令的解释

对于[idata]Debug将其解释为ds：idata，而编译器将其解释为idata。

```assembly
;对于编译器
mov al,[0]		;(al)=0
mov al,ds:[0]	;(al)=((ds)*16+0)
mov al,[bx]		;(al)=((ds)*16+(bx))
mov al,ds:[bx]	;同上，cs，ds，ss，es称为段前缀
```

### 4、一段安全的空间

直接向内存空间中写入数据可能会对系统造成损害。

PC机提供了一段安全的空间0：200~0：2ff，供我们使用。

## 6、包含多个段的程序

```assembly
assume cs:code,ds:data,ss:stack

data segment
	dw 0123h,0456h,0789h,0abch,0defh,0cbah,0987h
	;dw“define word”，定义了八个字型数据
	;dw定义的数据在数据段的最开始,即ds：0、……、ds：e
data ends

stack segment
	dw 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0	;将这16个字的空间当作栈
stack ends

code segment
start:	mov ax,stack	
		mov ss,ax		;告诉CPU，stack段为栈空间
		mov sp,20h		;栈空时的栈顶
		mov ax,data		
		mov ds,ax		;data段位数据段
		mov bx,0		;bx存放偏移地址
		mov cx,8
s:		push [bx]
		add bx,2
		loop s
		mov bx,0
		mov cx,8
s0:		pop [bx]
		add bx,2
		loop s0
		
		mov ax,4c00h
		int 21h		
code ends
end start		;指明程序入口在start处
```

## 7、灵活定位内存地址

### 1、and和or

and：逻辑与，可以将操作对象的相应位设为0。

or：逻辑或，可以将操作对象的相应位设为1。

```assembly
and al,11011111B	;小写转大写
or  bl,00100000B	;大写转小写
db 'DoNg'			;定义字节数据
```

### 2、[bx+idata]与数组

用idata表示数组开始的位置，bx表示数组的偏移。

eg：[5+bx],[0+bx]分别表示从ds：5和ds：0开始的两个数组

[0+bx]=[bx+0]=0[bx]=[bx].0

### 3、SI和DI

SI,DI与bx功能相近，但不能分成两个八位寄存器。

```assembly
mov ax,[bx+si]
;也可以写成这种形式
mov ax,[bx][si]
;对于[bx+si+idata]有以下几种形式
mov ax,[bx+200+si]
mov ax,[200+bx+si]
mov ax,200[bx][si]
mov ax,[bx].200[si]
mov ax,[bx][si].200
```

### 4、二重循环与栈的应用

```assembly
;下列程序可以实现数据段的每个单词的前四个字母变为大写
assume cs:codesg,ss:stacksg,ds:datasg

datasg segment			;数据段
db '1. display      '
db '2. brows		'
db '3. replace		'
db '4. modify		'
datasg ends

stacksg segment			;栈段，注意栈顶sp
dw 0,0,0,0,0,0,0,0
stacksg ends

codesg segment
start:	mov ax,stacksg
		mov ss,ax
		mov sp,16
		mov ax,datasg
		mov ds,ax
		mov cx,4		;外循环次数
		mov bx,0		;用bx代表行
		
s0:		push cx			;外层循环数暂存入cx
		mov si,0		;si代表列
		mov cx,4		;内循环数
		
s:		mov al,ds:[bx+3+si]		;循环实现前四个字母变为大写
		and al,11011111B
		mov ds:[bx+3+si],al
		inc si					;移动列
		loop s		
		
		pop cx					;出栈，取出外循环cx
		add bx+16				;移动行
		loop s0
		
		mov ax,4c00H
		int 21H
codesg ends
end start
```
