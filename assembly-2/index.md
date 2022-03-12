# Assembly 2


# 汇编语言（2）

<!-- more -->

## 8、数据处理

### 1、bx，si，di，bp

reg（寄存器）：ax、bx、cx、dx、ah、al、bh、bl、ch、cl、dh、dl、sp、bp、si、di；

sreg（段寄存器）：ds、ss、cs、es（扩展段，辅助作用）；

只有这四个寄存器用在“[...]”中来进行内存单元的寻址。

下面这两种语法是错误的

```assembly
mov ax,[si+di]
mov sx,[bx+bp]
```

若在“[...]”中使用bp，而指令没有显性给出段地址时，段地址默认在ss中。

### 2、数据的长度

在没有寄存器名存在的情况下，用操作符X ptr指明内存单元的长度，X在汇编指令中可以为word或byte。

```assembly
mov word ptr ds:[0],1
inc word ptr ds:[0]
inc byte ptr ds:[0]
add byte ptr [bx],2
```

push,pop只对字进行操作。

### 3、结构体

```assembly
mov ax,seg
mov ds,ax
mov bx,60h
mov word ptr [bx+0ch],38		;一个数据段中紧挨着存放了不同的信息
mov word ptr [bx+0eh],70		;类似c语言的结构体
mov si,0
mov byte ptr [bx+10+si],'V'
inc si
mov byte ptr [bx+10+si],'A'
inc si
mov byte ptr [bx+10+si],'X'
```

### 4、div

被除数默认放在AX或AX和DX中，若除数为8位，则被除数位16位，在ax中存放；若除数为16位，被除数位32位，在DX和AX中存放，ax存放低16位。

```assembly
;格式
;div reg
;div 内存单元
div byte ptr ds:[0]
;(a1)=(ax)/((ds)*16+0)的商
;(ah)=(ax)/((ds)*16+0)的余数
div word ptr es:[0]
;(ax)=[(dx)*10000H+(ax)]/((es)*16+0)的商
;(bx)=[(dx)*10000H+(ax)]/((es)*16+0)的余数
```

## 9、转移指令

### 1、offset

```assembly
mov ax,offset start  ;取得标号的偏移地址
```

### 2、jmp

观察机器码，可以发现立即数（idata）会在机器码中有所体现。jmp指令机器码中以补码的形式体现。

```assembly
cs:0000		mov ax,0123h		;B8 23 01
cs:0003		jmp s				;EB 03，执行jmp后，ip+2变为05
cs:0005		add ax,1			;实际作用是jmp执行后向下跳3个字节
cs:0008	 s:	inc ax				;jmp将ip=ip+03=08,03为补码的十六进制
```

```assembly
jmp short s			;段内短转移，（ip）=（ip）+8位位移
jmp near ptr s		;段内近转移，（ip）=（ip）+16位位移
jmp far ptr s		;段间转移，直接修改cs：ip
jmp word ptr 内存地址单元	;段内近转移，（ip）=(内存地址单元)
jmp dword ptr 内存地址单元;段间转移
						;(cs)=(内存地址单元+2),(ip)=(内存地址单元)
```

### 3、jcxz

```assembly
jcxz 标号
;if((cx)==0)
;	jmp 标号
```

## 10、CALL和RET指令

### 1、ret和retf

```assembly
ret  ;等价于pop ip
;(ip)=((ss)*16+(sp))
;(sp)=(sp)+2

retf  ;等价于pop ip,pop cs
;(ip)=((ss)*16+(sp))
;(sp)=(sp)+2
;(cs)=((ss)*16+(sp))
;(sp)=(sp)+2
```

### 2、call

```assembly
call s
;(sp)=(sp)-2			push ip
;((ss)*16+(sp))=(ip)	
;(ip)=(ip)+16位位移	  jmp near ptr 标号
;16位位移=标号处地址-call指令的第一个字节的地址

call far ptr s
;(sp)=(sp)-2			push cs
;((ss)*16+(sp))=(cs)	push ip
;(sp)=(sp)-2
;((ss)*16+(sp))=(ip)	
;(cs)=标号所在的段地址		jmp far ptr 标号
;(ip)=标号在段中的偏移地址

call 16位reg
;(sp)=(sp)-2
;((ss)*16+(sp))=(cs)
;(ip)=(16位reg)

call word ptr 内存单元地址
;push ip
;jmp word ptr 内存单元地址

call dword ptr 内存单元地址
;push cs
;push ip
;jmp dword ptr 内存单元地址
```

### 4、mul

```assembly
mul reg
mul 内存单元

mul byte ptr ds:[0]
;(ax)=(al)*((ds)*16+0)
mul word ptr [bx+si+8]
;(ax)=(ax)*((ds)*16+(bx)+(si)+8)结果的低16位
;(dx)=(ax)*((ds)*16+(bx)+(si)+8)结果的高16位
```

### 5、实验

```assembly
assume cs:code
data segment 

data ends

stack segment
	dw 8 dup(0)
stack ends

code segment
start:	mov ax,stack
		mov ss,ax
		mov sp,10h
		mov ax,4240h
		mov dx,0fh
		mov cx,0ah
		call divdw
		
		mov ax,
		int 21h
		
divdw:	push ax			;保存低16位
		mov ax,dx		;ax此时位H
		mov dx,0
		div cx			;高16位除以除数
		mov bx,ax		;H/N的商，放入高位商的储存位置
		pop ax
		div cx			;低16位除以除数
		mov cs,dx
		mov dx,bx
		ret
		
code ends
end start
```

## 11、标志寄存器

flag寄存器有16位，其中储存的信息被称为程序状态字（PSW）。

> 作用：
>
> （1）用来储存相关指令的某些执行结果；
>
> （2）用来为CPU执行相关指令提供行为依据；
>
> （3）用来控制CPU的相关工作方式。

|  值  |  15  |  14  |  13  | 12   |  11  |  10  | 9    |  8   |  7   |  6   |  5   |  4   |  3   |  2   |  1   |  0   |
| :--: | :--: | :--: | :--: | ---- | :--: | :--: | ---- | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| flag |      |      |      |      |  OF  |  DF  | IF   |  TF  |  SF  |  ZF  |      |  AF  |      |  PF  |      |  CF  |
|  1   |      |      |      |      |  OV  |  DN  |      |      |  NG  |  ZR  |      |      |      |  PE  |      |  CY  |
|  0   |      |      |      |      |  NV  |  UP  |      |      |  PL  |  NZ  |      |      |      |  PO  |      |  NC  |

flag的1、3、5、12、3、14、15没有任何含义。其他有特殊含义。

### 1、ZF、PF、SF、CF、OF

ZF（零标志位）：指令执行后，结果为0，则ZF=1，否则为0。

PF（奇偶标志位）：指令执行后，结果为偶数，则PF=1，否则为0。

SF（符号标志位）：指令执行后，结果为负数，则SF=1，否则为0。

> 当我们将数据当作有符号数来运算时，SF标志位才有意义

CF（进位标志位）：在进行**无符号数运算**的时候，它记录了运算结果的最高有效位向更高位的进位值。

> 例如，两个八位数据：98H+98H，将产生进位，8位数无法保存，更高的位被记录在CF中。
>
> 借位时也会发生改变。

OF（溢出标志位）：在进行**有符号数运算**时，若运算结果超出机器所能表达的范围，将产生溢出。产生溢出的溢出放入OF。

### 2、adc、sbb、cmp

```assembly
adc ax,bx
;(ax)=(ax)+(bx)+CF

;例计算1EF000H+201000H
mov ax,001eh	;存低位
mov bx,0f000h	;存高位
add bx,1000h	;低位相加
adc ax,0020h	
```

```assembly
sbb ax,bx
;(ax)=(ax)-(bx)-CF

;例计算003E1000H-00202000H
mov bx,1000h	;存低位
mov ax,003eh	;存高位
sub bx,2000h	;低位相减
sbb ax,0020h
```

```assembly
cmp ax,bx
;(ax)-(bx)，用来影响flag各位的值。

;无符号数的比较
;(ax)=(bx),ZF=1;
;(ax)≠(bx),ZF=0;
;(ax)<(bx),CF=1;
;(ax)≥(bx),CF=0;
;(ax)>(bx),CF=0&&ZF=0;
;(ax)≤(bx),CF=1||ZF=1;

;有符号数的比较
;SF=1&&OF=0,(ax)<(bx)
;SF=1%%OF=1,(ax)>(bx)
;SF=0&&OF=1,(ax)<(bx)
;SF=0&&OF=0,(ax)≥(bx)
```

### 3、条件转移指令

jump,not,equal,below,above

| 指令 |     含义     |  检测的flag  |
| :--: | :----------: | :----------: |
|  je  |  等于则转移  |     ZF=1     |
| jne  | 不等于则转移 |     ZF=0     |
|  jb  |  低于则转移  |     CF=1     |
| jnb  | 不低于则转移 |     CF=0     |
|  ja  |  高于则转移  |  CF=0,ZF=0   |
| jna  | 不高于则转移 | CF=1 or ZF=1 |

### 4、DF和串传送指令

DF（方向标志位）

```assembly
movsb
;(1)((es)*16+(di))=((ds)*16+(si))
;(2)if df=0,(si)=(si)+1,(di)=(di)+1
;	if df=1,(si)=(si)-1,(di)=(di)-1

movsw
;(1)((es)*16+(di))=((ds)*16+(si))
;(2)if df=0,(si)=(si)+2,(di)=(di)+2
;	if df=1,(si)=(si)-2,(di)=(di)-2

rep movsb
;s:movsb
;  loop s

cld			;设置df=0，正向传送
std			;设置df=1
```

### 5、pushf和popf

pushf：将标志寄存器的值压栈。

popf：将栈中的数据弹出，送入标志寄存器。

## 12、内中断

> 产生中断信息的四种情况：
>
> （1）除法错误，如：div指令产生的除法溢出； 0号中断
>
> （2）单步执行；		1号中断
>
> （3）执行into指令；
>
> （4）执行int指令。

### 1、中断向量表

储存着中断处理程序的入口地址的列表，在内存0000：0000到0000：03FF的1024个单元存放，一个物理地址占四个字节，低位为ip，高位为cs。

### 2、中断处理过程

1. 取得中断类型码N；
2. pushf
3. TF=0，IF=0；
4. push cs
5. push ip
6. （ip）=(N *4)，(cs)=(N *4+2)
7. 开始运行中断处理程序（用iret返回）

### 3、编程处理0号中断

```assembly
assume cs:code

code segment
start: 	mov ax,0			;目标程序地址
		mov es,ax
		mov di,200H
		
		mov ax,cs			;源程序地址
		mov ds,ax
		mov si,offset do0
		
		mov cx,offset do0end-offset do	;传输代码的长度
		
		cld					;正向传输
		rep movsb			;传输
		
		mov ax,0			;设置中断向量表，指向我们规定的程序入口
		mov es,ax
		mov word ptr es:[0*4],200h
		mov word ptr es:[0*4+2],0
		
		mov ax,4c00h
		int 21h
		
do:		jmp short do0
		db 'overflow!'		;用来存放‘overflow！’
		
		
do0:	mov ax,cs			;字符串的地址
		mov ds,ax
		mov si,202h
		
		mov ax,0b800h		;字符串要显示的位置
		mov es.ax
		mov di,12*160+36*2
		
		mov cx,9
s:		mov al,[si]
		mov es:[di],al
		inc si
		add di,2
		loop s
		
		mov ax,4c00h
		int 21h
		
do0end:	nop

code ends
end start
```

### 4、单步中断

若TF=1，则会产生单步中断。

1. 取得中断类型码1；
2. 标志寄存器入栈，TF=0,IF=0；
3. CS,IP入栈
4. (IP)=(1 *4),(CS)=(1 *4+2)

在Debug中，t命令使TF=1，进入单步中断程序，TF又被设置为0，来防止单步中断循环发生。

在执行完向ss寄存器传送数据的指令后，CPU不会响应中断。因为ss：sp的设置要连续完成。

```assembly
mov ax,1000h
mov ss,ax
mov ax,0	;这一步直接被忽略
mov sp,0
```

