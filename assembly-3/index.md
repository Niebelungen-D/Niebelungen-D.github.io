# Assembly 3


# 汇编语言（3）

## 13、int

<!-- more -->

```assembly
int n
;n为中断类型码
;可以用作一种特殊的函数调用方式。
```


```assembly
assume cs:code
code segment
start:
	mov ax,cs			;源程序位置
	mov ds,ax
	mov si,offset s0
		
	mov ax,0			;目标程序位置
	mov es,0
	mov di,200h
	
	moc cx,offset s0-offset s0end
	cld					;正向传输安装
	rep movsb

	mov ax,0			;更新向量表
	mov es,ax
	mov word ptr es:[7ch*4],200h
	mov word ptr es:[7ch*4+2],0

	mov ax,4c00h
	int 21h
	
;下面是中断程序的内容
	
s0:	mul ax
	iret

s0end:
	nop
	
code ends
end start
```

```assembly
assume cd:code
code segment
start:
	mov ax,cs			;源程序位置
	mov ds,ax
	mov si,offset s0
		
	mov ax,0			;目标程序位置
	mov es,0
	mov di,200h
	
	mov cx,offset lp-offset lpend
	cld					;正向传输安装
	rep movsb

	mov ax,0			;更新向量表
	mov es,ax
	mov word ptr es:[7ch*4],200h
	mov word ptr es:[7ch*4+2],0

	mov ax,4c00h
	int 21h
	
;下面是中断程序的内容	
lp:	push bp
	mov bp,sp
	dec cx		;外部cx代表循环次数，需要提供
	jcxz lpret
	add[bp+2],bx	;bx代表所循环程序的长度
					;ss:[bp+2]中为中断执行后的IP，加上长度就回到了程序开始
lpret:
	pop bp
	iret
	
lpend:
	nop
	
code ends
end start
```

## 14、端口

端口：计算机与外界交流的门户。

CPU可以直接读写3个地方的数据：CPU内部寄存器，内存单元，端口。

### 1、基本概念

不能使用mov、push、pop，使用in，out。

```assembly
in al,60h
out 21h,al
```

```assembly
shl		;逻辑左移
shr		;逻辑右移

mov	ax,36h
mov cl,3
shl ax,cl
shr ax,cl
;当移动位数大于1时，必须将移动位数放入cl
;移动1位时，CF会储存被移出的那一位
```

### 2、CMOS RAM芯片

CMOS RAM芯片储存了时间信息，由电池供电，保证时间正常计算。70h为地址端口，71h为数据端口。

数据以BCD码的方式存放，0~9的四位二进制码。

BCD码+30h=十进制数的ASCII码，所以取出数据的高8位和低8位都要加30h。

```assembly
mov ah,al		;al中位从芯片8号单元读出的数据
mov cl,4
shr ah,cl		;ah中位月份的十位数码值
and al,00001111b;al中位月份的个位数码值
```

## 15、外中断

### 1、基本概念

分为可屏蔽中断和不可屏蔽中断。

IF=1,则CPU执行完当前指令后，响应中断；IF=0，则不响应。

参照中断处理的过程，IF置0是为了防止其他中断的干扰。

sti，设置IF=1；cli，设置IF=0。

### 2、键盘处理

按下一个键时，会产生一个扫描码，称为通码，松开时产生的扫描码称为断码。扫描码的长度为一个字节，通码的第7位为0，断码的第七位为1，即：断码=通码+80h。扫描码送到60h端口。

键盘的输入到达60h端口时，相关芯片发送中断类型码9，CPU执行int 9中断例程处理键盘输入。

int 9中断例程，会产生与扫描码对应的字符码，放入BIOS键盘缓冲区，一个键盘输入用一个字单元存放，高位字节存放扫描码，低位字节存放字符码。

### 3、编写int 9中断

```assembly
assume cs:code
stack segment
	db 128 dup (0)
stack ends

data segment
	dw 0,0
data ends
code segment
start	mov ax,0b800h
		mov es,ax
		mov ah,'a'
s:		mov es:[160*12+40*2],ah
		call delay
		inc ah
		cmp ah,'z'
		jna s
		
		mov ax,4c00h
		int 21h
		
delay:	push ax
		push dx
		mov dx,1000h	;外层循环数 1000H
		mov ax,0		;内层循环数是1 0000h
s1:		sub ax,1
		sbb dx,0
		cmp ax,0
		jne s1
		cmp dx,0
		jne s1
		pop dx
		pop ax
		ret
		
code ends
end start
```

## 16、直接定址表

### 1、标号

```assembly
a: db 1,2,3,4,5,6,7,8
b: dw 0
;这里a，b进阶表示内存单元的地址,后面加有”：“的地址标号，只能在代码段使用
a db 1,2,3,4,5,6,7,8
b dw 0
;这里a，b同时描述内存地址和单元长度，称为数据标号；
;a，cs：0后的内存单元为字节单元，b，cs：8后的内存单元为字单元
mov ax,b	;mov ax,cs:[8]
mov b,2		;mov word ptr cs:[8],2
inc b		;inc word ptr cs:[8]
mov al,a[bx+si+3]	;mov al,cs:0[bx+si+3]

seg ;取得某一标号的段地址
```

### 2、直接定址表

通过位移建立数据之间的映射关系。依据数据，直接计算出所要找的元素的位置的表。

## 17、使用BIOS进行键盘输入和磁盘读写

int 9h中断将键盘的输入数据放入键盘缓冲区

int 16h将ah作为参数传递寄存器，从键盘读取一个输入，并将其从缓冲区删除。

1. 检测键盘缓冲区中是否有数据
2. 没有则继续第一步
3. 读取缓冲区第一个字单元的键盘输入
4. 将读取的扫描码送入ah，ASCII送入al；
5. 将已读取的键盘输入从缓冲区中删除。

### 1、字符串

使用栈处理字符串的输入，

1. 调用int 16h读取键盘输入；
2. 如果是字符，进入字符栈，显示字符栈中的所有字符；继续执行1；
3. 如果是退格键，从字符栈中弹出一个字符，显示字符栈中的所有字符；继续执行1；
4. 如果是Enter键，向字符栈中压入0，返回。


