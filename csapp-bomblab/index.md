# CSAPP Bomblab


# CSAPP-Bmoblab

输入正确的字符串拆除六个炸弹，通过分析汇编代码+调试找出答案。意外地很好玩~~

<!-- more -->

## phase_1

```assembly
0000000000400ee0 <phase_1>:
  400ee0:	48 83 ec 08          	sub    $0x8,%rsp
  400ee4:	be 00 24 40 00       	mov    $0x402400,%esi
  400ee9:	e8 4a 04 00 00       	callq  401338 <strings_not_equal>
  400eee:	85 c0                	test   %eax,%eax
  400ef0:	74 05                	je     400ef7 <phase_1+0x17>
  400ef2:	e8 43 05 00 00       	callq  40143a <explode_bomb>
  400ef7:	48 83 c4 08          	add    $0x8,%rsp
  400efb:	c3                   	retq 
```

`read_line`的输入被当作第一个参数传入了`phase_1`，随后`0x4020400`作为第二个参数，进入了`strings_not_equal`，`test eax,eax`比较返回值，不相等就会`explode_bomb`。所以我们要输入的字符串就在`0x402400`处。

```shell
pwndbg> print (char *) 0x402400
$1 = 0x402400 "Border relations with Canada have never been better."
```

## phase_2

同样输入被当作第一个参数。

```assembly
0000000000400efc <phase_2>:
  400efc:	55                   	push   %rbp
  400efd:	53                   	push   %rbx
  400efe:	48 83 ec 28          	sub    $0x28,%rsp
  400f02:	48 89 e6             	mov    %rsp,%rsi
  400f05:	e8 52 05 00 00       	callq  40145c <read_six_numbers>
  400f0a:	83 3c 24 01          	cmpl   $0x1,(%rsp)
  400f0e:	74 20                	je     400f30 <phase_2+0x34>
  400f10:	e8 25 05 00 00       	callq  40143a <explode_bomb>
  400f15:	eb 19                	jmp    400f30 <phase_2+0x34>
  400f17:	8b 43 fc             	mov    -0x4(%rbx),%eax
  400f1a:	01 c0                	add    %eax,%eax
  400f1c:	39 03                	cmp    %eax,(%rbx)
  400f1e:	74 05                	je     400f25 <phase_2+0x29>
  400f20:	e8 15 05 00 00       	callq  40143a <explode_bomb>
  400f25:	48 83 c3 04          	add    $0x4,%rbx
  400f29:	48 39 eb             	cmp    %rbp,%rbx
  400f2c:	75 e9                	jne    400f17 <phase_2+0x1b>
  400f2e:	eb 0c                	jmp    400f3c <phase_2+0x40>
  400f30:	48 8d 5c 24 04       	lea    0x4(%rsp),%rbx
  400f35:	48 8d 6c 24 18       	lea    0x18(%rsp),%rbp
  400f3a:	eb db                	jmp    400f17 <phase_2+0x1b>
  400f3c:	48 83 c4 28          	add    $0x28,%rsp
  400f40:	5b                   	pop    %rbx
  400f41:	5d                   	pop    %rbp
  400f42:	c3                   	retq
```
将栈增长，传入rsi。
```assembly
000000000040145c <read_six_numbers>:
  40145c:	48 83 ec 18          	sub    $0x18,%rsp
  401460:	48 89 f2             	mov    %rsi,%rdx
  401463:	48 8d 4e 04          	lea    0x4(%rsi),%rcx
  401467:	48 8d 46 14          	lea    0x14(%rsi),%rax
  40146b:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  401470:	48 8d 46 10          	lea    0x10(%rsi),%rax
  401474:	48 89 04 24          	mov    %rax,(%rsp)
  401478:	4c 8d 4e 0c          	lea    0xc(%rsi),%r9
  40147c:	4c 8d 46 08          	lea    0x8(%rsi),%r8
  401480:	be c3 25 40 00       	mov    $0x4025c3,%esi
  401485:	b8 00 00 00 00       	mov    $0x0,%eax
  40148a:	e8 61 f7 ff ff       	callq  400bf0 <__isoc99_sscanf@plt>
  40148f:	83 f8 05             	cmp    $0x5,%eax
  401492:	7f 05                	jg     401499 <read_six_numbers+0x3d>
  401494:	e8 a1 ff ff ff       	callq  40143a <explode_bomb>
  401499:	48 83 c4 18          	add    $0x18,%rsp
  40149d:	c3                   	retq   
```

这里又将栈增长，将rsi即原来的栈顶地址作为第三个参数给了rdx，偏移+4作为第四个参数给了rcx，同理，第五个参数在r8，第六个参数在r9。如果寄存器不够传参，会将参数入栈。分析第5-8行，偏移+0x10的第七个参数，和+0x14的第八个参数入栈了。

之后调用了`sscanf：int sscanf(const char *str, const char *format, ...)`，第一个参数是我们的输入，即数据源。第二个参数是`0x4025c3`处的格式化字符串。`sscanf`是将数据源按照格式化字符串的格式，给后面的参数赋值。查看格式化字符串：

```shell
pwndbg> print (char *) 0x4025c3
$1 = 0x4025c3 "%d %d %d %d %d %d"
```

所以我们就是要输入六个数字，中间以空格分隔。最后清栈返回。

```assembly
 400f0a:	83 3c 24 01          	cmpl   $0x1,(%rsp)
 400f0e:	74 20                	je     400f30 <phase_2+0x34>
 400f10:	e8 25 05 00 00       	callq  40143a <explode_bomb>
```

这时rsp指向了第一个参数，`cmpl $0x1,(%rsp)`与1进行比较，相等则跳转：

```assembly
 400f30:	48 8d 5c 24 04       	lea    0x4(%rsp),%rbx
 400f35:	48 8d 6c 24 18       	lea    0x18(%rsp),%rbp
 400f3a:	eb db                	jmp    400f17 <phase_2+0x1b>
```

rsp上移4的地址，给了rbx，这时rbx指向第二个参数。rsp上移0x18的地址，给了rbp，这时rbp指向了最后一个参数的后面的地址。最后跳回：

```assembly
  400f17:	8b 43 fc             	mov    -0x4(%rbx),%eax
  400f1a:	01 c0                	add    %eax,%eax
  400f1c:	39 03                	cmp    %eax,(%rbx)
  400f1e:	74 05                	je     400f25 <phase_2+0x29>
  400f20:	e8 15 05 00 00       	callq  40143a <explode_bomb>
  400f25:	48 83 c3 04          	add    $0x4,%rbx
  400f29:	48 39 eb             	cmp    %rbp,%rbx
  400f2c:	75 e9                	jne    400f17 <phase_2+0x1b>
  400f2e:	eb 0c                	jmp    400f3c <phase_2+0x40>
```

第一个参数*2与第二个参数比较，不相等就爆炸，相等就会跳到第6行的位置。将rbx地址+4，并与rbp进行比较。这里rbx就又指向了第三个参数，然后跳回，重复上面的操作，知道比较完了所有的参数，rbp==rbx。所以，除了第一个参数为1，其余参数都是前面参数的二倍。则结果为：

```text
1 2 4 8 16 32
```

## phase_3

```assembly
0000000000400f43 <phase_3>:
  400f43:	48 83 ec 18          	sub    $0x18,%rsp
  400f47:	48 8d 4c 24 0c       	lea    0xc(%rsp),%rcx
  400f4c:	48 8d 54 24 08       	lea    0x8(%rsp),%rdx
  400f51:	be cf 25 40 00       	mov    $0x4025cf,%esi
  400f56:	b8 00 00 00 00       	mov    $0x0,%eax
  400f5b:	e8 90 fc ff ff       	callq  400bf0 <__isoc99_sscanf@plt>
  400f60:	83 f8 01             	cmp    $0x1,%eax
  400f63:	7f 05                	jg     400f6a <phase_3+0x27>
  400f65:	e8 d0 04 00 00       	callq  40143a <explode_bomb>
  400f6a:	83 7c 24 08 07       	cmpl   $0x7,0x8(%rsp)
  400f6f:	77 3c                	ja     400fad <phase_3+0x6a>
  400f71:	8b 44 24 08          	mov    0x8(%rsp),%eax
  400f75:	ff 24 c5 70 24 40 00 	jmpq   *0x402470(,%rax,8)
  400f7c:	b8 cf 00 00 00       	mov    $0xcf,%eax
  400f81:	eb 3b                	jmp    400fbe <phase_3+0x7b>
  400f83:	b8 c3 02 00 00       	mov    $0x2c3,%eax
  400f88:	eb 34                	jmp    400fbe <phase_3+0x7b>
  400f8a:	b8 00 01 00 00       	mov    $0x100,%eax
  400f8f:	eb 2d                	jmp    400fbe <phase_3+0x7b>
  400f91:	b8 85 01 00 00       	mov    $0x185,%eax
  400f96:	eb 26                	jmp    400fbe <phase_3+0x7b>
  400f98:	b8 ce 00 00 00       	mov    $0xce,%eax
  400f9d:	eb 1f                	jmp    400fbe <phase_3+0x7b>
  400f9f:	b8 aa 02 00 00       	mov    $0x2aa,%eax
  400fa4:	eb 18                	jmp    400fbe <phase_3+0x7b>
  400fa6:	b8 47 01 00 00       	mov    $0x147,%eax
  400fab:	eb 11                	jmp    400fbe <phase_3+0x7b>
  400fad:	e8 88 04 00 00       	callq  40143a <explode_bomb>
  400fb2:	b8 00 00 00 00       	mov    $0x0,%eax
  400fb7:	eb 05                	jmp    400fbe <phase_3+0x7b>
  400fb9:	b8 37 01 00 00       	mov    $0x137,%eax
  400fbe:	3b 44 24 0c          	cmp    0xc(%rsp),%eax
  400fc2:	74 05                	je     400fc9 <phase_3+0x86>
  400fc4:	e8 71 04 00 00       	callq  40143a <explode_bomb>
  400fc9:	48 83 c4 18          	add    $0x18,%rsp
  400fcd:	c3                   	retq 
```

这里同样调用了`sscanf`，查看格式化字符串：

```shell
pwndbg> print (char *) 0x4025cf
$1 = 0x4025cf "%d %d"
```

最后输入的第一个参数放入了rsp+8，第二个参数放入rsp+0xc。返回后eax与1进行比较，判断是否输入了两个数，否则爆炸。然后第一个参数与7比较，判断第一个参数是否超过了7，否则爆炸。

之后将第一个参数放入eax，并跳转到`0x402470+8*rax`处。我们看看`0x402470`有存放的地址是什么：

```shell
pwndbg> x/16x 0x402470
0x402470:	0x00400f7c	0x00000000	0x00400fb9	0x00000000
0x402480:	0x00400f83	0x00000000	0x00400f8a	0x00000000
0x402490:	0x00400f91	0x00000000	0x00400f98	0x00000000
0x4024a0:	0x00400f9f	0x00000000	0x00400fa6	0x00000000
```

每个地址都对应了`mov $xxx,%eax`，即根据第一个参数跳转到不同的地址，给eax赋值，最后到`0x400be`比较第二个参数与eax。所以只要输入的第一个参数与第二个参数是对应的就可以。答案以下其一：

```text
0	207
1	311
2	707
3	256
4	389
5	206
6	682
7	327
```

## phase_4

```assembly
000000000040100c <phase_4>:
  40100c:	48 83 ec 18          	sub    $0x18,%rsp
  401010:	48 8d 4c 24 0c       	lea    0xc(%rsp),%rcx
  401015:	48 8d 54 24 08       	lea    0x8(%rsp),%rdx
  40101a:	be cf 25 40 00       	mov    $0x4025cf,%esi
  40101f:	b8 00 00 00 00       	mov    $0x0,%eax
  401024:	e8 c7 fb ff ff       	callq  400bf0 <__isoc99_sscanf@plt>
  401029:	83 f8 02             	cmp    $0x2,%eax
  40102c:	75 07                	jne    401035 <phase_4+0x29>
  40102e:	83 7c 24 08 0e       	cmpl   $0xe,0x8(%rsp)
  401033:	76 05                	jbe    40103a <phase_4+0x2e>
  401035:	e8 00 04 00 00       	callq  40143a <explode_bomb>
  40103a:	ba 0e 00 00 00       	mov    $0xe,%edx
  40103f:	be 00 00 00 00       	mov    $0x0,%esi
  401044:	8b 7c 24 08          	mov    0x8(%rsp),%edi
  401048:	e8 81 ff ff ff       	callq  400fce <func4>
  40104d:	85 c0                	test   %eax,%eax
  40104f:	75 07                	jne    401058 <phase_4+0x4c>
  401051:	83 7c 24 0c 00       	cmpl   $0x0,0xc(%rsp)
  401056:	74 05                	je     40105d <phase_4+0x51>
  401058:	e8 dd 03 00 00       	callq  40143a <explode_bomb>
  40105d:	48 83 c4 18          	add    $0x18,%rsp
  401061:	c3                   	retq   
```

又一个`sscanf`，跟第三关格式化字符串的地址一样。

返回后比较eax与2，判断参数是否输入了两个，否则跳转到炸弹处。然后判断第一个参数是否小于等于14，否则爆炸。之后调用`func4`,第一个参数为我们输入的第一个参数，第二个参数为0，第三个为14。

```assembly
0000000000400fce <func4>:
  400fce:	48 83 ec 08          	sub    $0x8,%rsp
  400fd2:	89 d0                	mov    %edx,%eax
  400fd4:	29 f0                	sub    %esi,%eax
  400fd6:	89 c1                	mov    %eax,%ecx
  400fd8:	c1 e9 1f             	shr    $0x1f,%ecx
  400fdb:	01 c8                	add    %ecx,%eax
  400fdd:	d1 f8                	sar    %eax
  400fdf:	8d 0c 30             	lea    (%rax,%rsi,1),%ecx
  400fe2:	39 f9                	cmp    %edi,%ecx
  400fe4:	7e 0c                	jle    400ff2 <func4+0x24>
  400fe6:	8d 51 ff             	lea    -0x1(%rcx),%edx
  400fe9:	e8 e0 ff ff ff       	callq  400fce <func4>
  400fee:	01 c0                	add    %eax,%eax
  400ff0:	eb 15                	jmp    401007 <func4+0x39>
  400ff2:	b8 00 00 00 00       	mov    $0x0,%eax
  400ff7:	39 f9                	cmp    %edi,%ecx
  400ff9:	7d 0c                	jge    401007 <func4+0x39>
  400ffb:	8d 71 01             	lea    0x1(%rcx),%esi
  400ffe:	e8 cb ff ff ff       	callq  400fce <func4>
  401003:	8d 44 00 01          	lea    0x1(%rax,%rax,1),%eax
  401007:	48 83 c4 08          	add    $0x8,%rsp
  40100b:	c3                   	retq 
```

第三个参数放入eax后减去第二个参数，最后放入了ecx。然后逻辑左移31位，再加上原来的数，最后算术右移一位，放入eax。然后ecx=rax+rsi，假设`func4(int a,int b,int c)`，那么上述指令相当于`(c-b)/2+b`。本题来说就是7。

也就是7被放入了ecx。然后比较第一个参数a与7的大小，判断是否7小于等于a。

若是，eax被赋值为0，再次比较a与7，这里这两个参数都没有改变所以必然会跳转，最后退出，返回值为0。

> 从这个分支继续分析，返回之后`test eax,eax`，因为eax=0，所以ZF=1，不会跳转，然后比较我们输入的第二个参数与0，相等就会退出，否则爆炸。
>
> 所以7 0是一个答案。

若否，7-1被赋值给了edx，再次调用了`func4`。

> 经过上面的分析只要让func4最后的返回值为0就可以。所以我们分析一下，若a<7时，输入何值才能使条件成立。
>
> `(c-b)/2+b-1`，即6作为第三个参数，其余参数没有发生变化。此时6/2=3，即a=3，使条件成立。第二层返回到第一层，0*2=0，返回，条件成立。
>
> 否则，继续调用，此时3-1=2作为第三个参数。2/2=1，a=1，条件成立。
>
> 否则，a=0，条件成立。

答案为以下其一：

```text
7 0
3 0
1 0
0 0
```

## phase_5

```assembly
0000000000401062 <phase_5>:
  401062:	53                   	push   %rbx
  401063:	48 83 ec 20          	sub    $0x20,%rsp
  401067:	48 89 fb             	mov    %rdi,%rbx
  40106a:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  401071:	00 00 
  401073:	48 89 44 24 18       	mov    %rax,0x18(%rsp)
  401078:	31 c0                	xor    %eax,%eax
  40107a:	e8 9c 02 00 00       	callq  40131b <string_length>
  40107f:	83 f8 06             	cmp    $0x6,%eax
  401082:	74 4e                	je     4010d2 <phase_5+0x70>
  401084:	e8 b1 03 00 00       	callq  40143a <explode_bomb>
  401089:	eb 47                	jmp    4010d2 <phase_5+0x70>
  40108b:	0f b6 0c 03          	movzbl (%rbx,%rax,1),%ecx
  40108f:	88 0c 24             	mov    %cl,(%rsp)
  401092:	48 8b 14 24          	mov    (%rsp),%rdx
  401096:	83 e2 0f             	and    $0xf,%edx
  401099:	0f b6 92 b0 24 40 00 	movzbl 0x4024b0(%rdx),%edx
  4010a0:	88 54 04 10          	mov    %dl,0x10(%rsp,%rax,1)
  4010a4:	48 83 c0 01          	add    $0x1,%rax
  4010a8:	48 83 f8 06          	cmp    $0x6,%rax
  4010ac:	75 dd                	jne    40108b <phase_5+0x29>
  4010ae:	c6 44 24 16 00       	movb   $0x0,0x16(%rsp)
  4010b3:	be 5e 24 40 00       	mov    $0x40245e,%esi
  4010b8:	48 8d 7c 24 10       	lea    0x10(%rsp),%rdi
  4010bd:	e8 76 02 00 00       	callq  401338 <strings_not_equal>
  4010c2:	85 c0                	test   %eax,%eax
  4010c4:	74 13                	je     4010d9 <phase_5+0x77>
  4010c6:	e8 6f 03 00 00       	callq  40143a <explode_bomb>
  4010cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4010d0:	eb 07                	jmp    4010d9 <phase_5+0x77>
  4010d2:	b8 00 00 00 00       	mov    $0x0,%eax
  4010d7:	eb b2                	jmp    40108b <phase_5+0x29>
  4010d9:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
  4010de:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
  4010e5:	00 00 
  4010e7:	74 05                	je     4010ee <phase_5+0x8c>
  4010e9:	e8 42 fa ff ff       	callq  400b30 <__stack_chk_fail@plt>
  4010ee:	48 83 c4 20          	add    $0x20,%rsp
  4010f2:	5b                   	pop    %rbx
  4010f3:	c3                   	retq   
```

竟然有canary~

rbx保存入栈，栈增长0x20，输入的字符串存入rbx，放canary，eax清零，调用`string_length`。最后返回字符串的长度，并与6进行比较，不相等就爆炸。所以要输入一个长度为6的字符串。

然后将eax赋值为0，然后字符串的最低字节放入ecx中，然后入栈，最后放入rdx，再与上0xf。最后取低四位放入了edx。

之后将这低四位加上`0x4024b0`的和的最低字节，放入edx,最后又将其放入栈中，canary之下。rax+1，与6进行比较，不相等就重复上面的操作。直到向栈中放入了6个字符，最后用’\x00‘进行截断。

然后调用`strings_not_equal`比较存入字符串，与`0x40245e`处的字符串。相等则退出，不相等就爆炸。查看`0x40245e`处的字符串：

```shell
pwndbg> x /s 0x40245e
0x40245e:	"flyers"
```

查看`0x4024b0`处字符串：

```shell
pwndbg> x /s 0x4024b0
0x4024b0 <array.3449>:	"maduiersnfotvbylSo you think you can stop the bomb with ctrl-c, do you?"
```

这里其实只要`maduiersnfotvby`，因为四位二进制数的范围为0-15。计算一下6个偏移：

```text
9 f e 5 6 7
```

所以只要低四位对应上面这些都可以，参考答案：

```shell
ionefg/IONEFG
```

## phase_6

```assembly
00000000004010f4 <phase_6>:
  4010f4:	41 56                	push   %r14
  4010f6:	41 55                	push   %r13
  4010f8:	41 54                	push   %r12
  4010fa:	55                   	push   %rbp
  4010fb:	53                   	push   %rbx
  4010fc:	48 83 ec 50          	sub    $0x50,%rsp
  401100:	49 89 e5             	mov    %rsp,%r13
  401103:	48 89 e6             	mov    %rsp,%rsi
  401106:	e8 51 03 00 00       	callq  40145c <read_six_numbers>
```

调用了`read_six_numbers`，根据之前的分析我们要输入六个数字。

```assembly
  40110b:	49 89 e6             	mov    %rsp,%r14
  40110e:	41 bc 00 00 00 00    	mov    $0x0,%r12d
  401114:	4c 89 ed             	mov    %r13,%rbp
  401117:	41 8b 45 00          	mov    0x0(%r13),%eax
  40111b:	83 e8 01             	sub    $0x1,%eax
  40111e:	83 f8 05             	cmp    $0x5,%eax
  401121:	76 05                	jbe    401128 <phase_6+0x34>      	;0x401128
  401123:	e8 12 03 00 00       	callq  40143a <explode_bomb>
  401128:	41 83 c4 01          	add    $0x1,%r12d
  40112c:	41 83 fc 06          	cmp    $0x6,%r12d
  401130:	74 21                	je     401153 <phase_6+0x5f>		;0x401153
  401132:	44 89 e3             	mov    %r12d,%ebx
  401135:	48 63 c3             	movslq %ebx,%rax
  401138:	8b 04 84             	mov    (%rsp,%rax,4),%eax
  40113b:	39 45 00             	cmp    %eax,0x0(%rbp)
  40113e:	75 05                	jne    401145 <phase_6+0x51>		;0x401145
  401140:	e8 f5 02 00 00       	callq  40143a <explode_bomb>
  401145:	83 c3 01             	add    $0x1,%ebx
  401148:	83 fb 05             	cmp    $0x5,%ebx
  40114b:	7e e8                	jle    401135 <phase_6+0x41>		;0x401135
  40114d:	49 83 c5 04          	add    $0x4,%r13
  401151:	eb c1                	jmp    401114 <phase_6+0x20>		;0x401114
```
这里r13指向了我们输入的数字。第一个数字-1与5进行比较，大于5就爆炸，所以我们输入的第一个数要小于等于6。

然后r12d+1，与6进行比较，第一次比较r12d为0。无论怎样，我们先考虑不相等的情况。

将r12d当作索引放入了rax，之后比较rsp+4*rax与rbp，即第一个参数与第二个参数，相等就会爆炸。然后，判断ebx即原来的r12d中的值+1后是否小于等于5。

如果小于就会跳回，ebx放入rax作为索引。这里ebx已经被加了1。所以可以分析出这是一个for循环用来判断，第一个数与之后的数是否相等。

之后r13+4指向了我们的第二个数，然后又比较了第二个数与6的大小。然后，把第二个参数单作第一个数，进行上述操作。

所以，通过上面的分析，我们输入的**六个数要小于等于6，且两两不相等**。

```assembly
  401153:	48 8d 74 24 18       	lea    0x18(%rsp),%rsi
  401158:	4c 89 f0             	mov    %r14,%rax
  40115b:	b9 07 00 00 00       	mov    $0x7,%ecx
  401160:	89 ca                	mov    %ecx,%edx
  401162:	2b 10                	sub    (%rax),%edx
  401164:	89 10                	mov    %edx,(%rax)
  401166:	48 83 c0 04          	add    $0x4,%rax
  40116a:	48 39 f0             	cmp    %rsi,%rax
  40116d:	75 f1                	jne    401160 <phase_6+0x6c>		;0x401160
```
`lea 0x18(%rsp),%rsi`将数组末尾地址给了rsi。将r14中的数组首址放入rax中，最后实现：7-参数。然后判断，是否到了数组尾部。所以这段实现了7-num[i]。

```assembly
  40116f:	be 00 00 00 00       	mov    $0x0,%esi
  401174:	eb 21                	jmp    401197 <phase_6+0xa3>		;0x401197
  401176:	48 8b 52 08          	mov    0x8(%rdx),%rdx
  40117a:	83 c0 01             	add    $0x1,%eax
  40117d:	39 c8                	cmp    %ecx,%eax
  40117f:	75 f5                	jne    401176 <phase_6+0x82>		;0x401176
  401181:	eb 05                	jmp    401188 <phase_6+0x94>		;0x401188
  401183:	ba d0 32 60 00       	mov    $0x6032d0,%edx
  401188:	48 89 54 74 20       	mov    %rdx,0x20(%rsp,%rsi,2)
  40118d:	48 83 c6 04          	add    $0x4,%rsi
  401191:	48 83 fe 18          	cmp    $0x18,%rsi
  401195:	74 14                	je     4011ab <phase_6+0xb7>		;0x4011ab
  401197:	8b 0c 34             	mov    (%rsp,%rsi,1),%ecx
  40119a:	83 f9 01             	cmp    $0x1,%ecx
  40119d:	7e e4                	jle    401183 <phase_6+0x8f>		;0x401183
  40119f:	b8 01 00 00 00       	mov    $0x1,%eax
  4011a4:	ba d0 32 60 00       	mov    $0x6032d0,%edx
  4011a9:	eb cb                	jmp    401176 <phase_6+0x82>		;0x401176
```

esi赋值为0，rsp+rsi指向的值，即我们的数组元素，放入ecx，并与1进行比较。小于等于1则跳转回去，将`0x6032d0`处的内容放入`rsp+rsi*2+0x20`的位置。否则，eax赋值为1，`0x6032d0`放入edx，跳转到，`0x6032d0+8`放入rdx，eax+1并于当前数组值进行比较，不相等就eax++，`0x6032d0+8`再加8。直到与当前数组元素相等，将偏移后的地址指向的内容放入`rsp+rsi*2+0x20`。然后索引值rsi+4并与0x18比较，判断是否到了数组尾部。否则将下一个元素放入ecx，并与1比较。

这里不太清晰我们看一下`0x6032d0`有什么：

```shell
pwndbg> x/24x 0x6032d0
0x6032d0 <node1>:	0x0000014c	0x00000001	0x006032e0	0x00000000
0x6032e0 <node2>:	0x000000a8	0x00000002	0x006032f0	0x00000000
0x6032f0 <node3>:	0x0000039c	0x00000003	0x00603300	0x00000000
0x603300 <node4>:	0x000002b3	0x00000004	0x00603310	0x00000000
0x603310 <node5>:	0x000001dd	0x00000005	0x00603320	0x00000000
0x603320 <node6>:	0x000001bb	0x00000006	0x00000000	0x00000000
```

可以发现这是一个链表，每个节点的结构如下：

```c
struct node{
    int value;
    int index;
    node *next;
}
```

我们刚刚做的就是将节点地址放入了栈中。

继续分析下一段：


  ```assembly
  4011ab:	48 8b 5c 24 20       	mov    0x20(%rsp),%rbx
  4011b0:	48 8d 44 24 28       	lea    0x28(%rsp),%rax
  4011b5:	48 8d 74 24 50       	lea    0x50(%rsp),%rsi
  4011ba:	48 89 d9             	mov    %rbx,%rcx
  4011bd:	48 8b 10             	mov    (%rax),%rdx
  4011c0:	48 89 51 08          	mov    %rdx,0x8(%rcx)
  4011c4:	48 83 c0 08          	add    $0x8,%rax
  4011c8:	48 39 f0             	cmp    %rsi,%rax
  4011cb:	74 05                	je     4011d2 <phase_6+0xde>		;0x4011d2
  4011cd:	48 89 d1             	mov    %rdx,%rcx
  4011d0:	eb eb                	jmp    4011bd <phase_6+0xc9>		;0x4011bd
  4011d2:	48 c7 42 08 00 00 00 	movq   $0x0,0x8(%rdx)
  4011d9:	00 
  ```
rbx分别指向数组首址，rax指向第二个节点，rsi指向末尾节点。rcx指向首址，然后第二个元素地址，放入rdx，然后放入首址偏移+8的位置。然后rax+8，指向下一个节点，并判断是否到达末尾。然后第二个元素地址放入rcx，重复上述操作，最后rdx中放入了末尾节点的地址。

上述操作相当于，将链表顺序链接起来，最后的节点指向NULL。


  ```assembly
  4011da:	bd 05 00 00 00       	mov    $0x5,%ebp
  4011df:	48 8b 43 08          	mov    0x8(%rbx),%rax
  4011e3:	8b 00                	mov    (%rax),%eax
  4011e5:	39 03                	cmp    %eax,(%rbx)
  4011e7:	7d 05                	jge    4011ee <phase_6+0xfa>		;0x4011ee
  4011e9:	e8 4c 02 00 00       	callq  40143a <explode_bomb>
  4011ee:	48 8b 5b 08          	mov    0x8(%rbx),%rbx
  4011f2:	83 ed 01             	sub    $0x1,%ebp
  4011f5:	75 e8                	jne    4011df <phase_6+0xeb>		;0x4011df
  4011f7:	48 83 c4 50          	add    $0x50,%rsp
  4011fb:	5b                   	pop    %rbx
  4011fc:	5d                   	pop    %rbp
  4011fd:	41 5c                	pop    %r12
  4011ff:	41 5d                	pop    %r13
  401201:	41 5e                	pop    %r14
  401203:	c3                   	retq 
  ```

ebp被赋值为5，作为计数。然后取下一个节点的值放入eax，并于当前节点进行比较，如果下一个节点的值大于当前值，就爆炸。所以要满足链表的值的递减顺序。

倒推一下，查看链表，顺序应该为：

```text
3 4 5 6 1 2
```

因为之前有个7-参数的操作，所以我们的答案为：

```text
4 3 2 1 6 5
```

## secret_phase

这里还有一个彩蛋！先来找一下进入条件：

```assembly
00000000004015c4 <phase_defused>:
  4015c4:	48 83 ec 78          	sub    $0x78,%rsp
  4015c8:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  4015cf:	00 00 
  4015d1:	48 89 44 24 68       	mov    %rax,0x68(%rsp)
  4015d6:	31 c0                	xor    %eax,%eax
  4015d8:	83 3d 81 21 20 00 06 	cmpl   $0x6,0x202181(%rip)        # 603760 <num_input_strings>
  4015df:	75 5e                	jne    40163f <phase_defused+0x7b>
  4015e1:	4c 8d 44 24 10       	lea    0x10(%rsp),%r8
  4015e6:	48 8d 4c 24 0c       	lea    0xc(%rsp),%rcx
  4015eb:	48 8d 54 24 08       	lea    0x8(%rsp),%rdx
  4015f0:	be 19 26 40 00       	mov    $0x402619,%esi
  4015f5:	bf 70 38 60 00       	mov    $0x603870,%edi
  4015fa:	e8 f1 f5 ff ff       	callq  400bf0 <__isoc99_sscanf@plt>
  4015ff:	83 f8 03             	cmp    $0x3,%eax
  401602:	75 31                	jne    401635 <phase_defused+0x71>
  401604:	be 22 26 40 00       	mov    $0x402622,%esi
  401609:	48 8d 7c 24 10       	lea    0x10(%rsp),%rdi
  40160e:	e8 25 fd ff ff       	callq  401338 <strings_not_equal>
  401613:	85 c0                	test   %eax,%eax
  401615:	75 1e                	jne    401635 <phase_defused+0x71>
  401617:	bf f8 24 40 00       	mov    $0x4024f8,%edi
  40161c:	e8 ef f4 ff ff       	callq  400b10 <puts@plt>
  401621:	bf 20 25 40 00       	mov    $0x402520,%edi
  401626:	e8 e5 f4 ff ff       	callq  400b10 <puts@plt>
  40162b:	b8 00 00 00 00       	mov    $0x0,%eax
  401630:	e8 0d fc ff ff       	callq  401242 <secret_phase>
  401635:	bf 58 25 40 00       	mov    $0x402558,%edi
  40163a:	e8 d1 f4 ff ff       	callq  400b10 <puts@plt>
  40163f:	48 8b 44 24 68       	mov    0x68(%rsp),%rax
  401644:	64 48 33 04 25 28 00 	xor    %fs:0x28,%rax
  40164b:	00 00 
  40164d:	74 05                	je     401654 <phase_defused+0x90>
  40164f:	e8 dc f4 ff ff       	callq  400b30 <__stack_chk_fail@plt>
  401654:	48 83 c4 78          	add    $0x78,%rsp
  401658:	c3                   	retq 
```

要想进入必须满足，0x603759 处的值为6，调试发现，我们每闯过一关，这里的值都会+1。所以必须通过前六关才可以。然后传入了，五个参数。我们看看`$0x402619`和`0x603870`处是什么：

```shell
pwndbg> x /2s 0x402619
0x402619:	"%d %d %s"
0x402622:	"DrEvil"
pwndbg> x 0x603870
0x603870 <input_strings+240>:	"7 0"
```

是我们第四关的答案，所以第二个条件就是在第四关中，之后又调用了`strings_not_equal`将我们输入的第三个参数与`DrEvil`进行比较，如果相等就可以进入。所以，为了进入我们要在第四关答案基础上添加`  DrEvil`，别忘了空格。

```assembly
0000000000401242 <secret_phase>:
  401242:	53                   	push   %rbx
  401243:	e8 56 02 00 00       	callq  40149e <read_line>
  401248:	ba 0a 00 00 00       	mov    $0xa,%edx
  40124d:	be 00 00 00 00       	mov    $0x0,%esi
  401252:	48 89 c7             	mov    %rax,%rdi
  401255:	e8 76 f9 ff ff       	callq  400bd0 <strtol@plt>
  40125a:	48 89 c3             	mov    %rax,%rbx
  40125d:	8d 40 ff             	lea    -0x1(%rax),%eax
  401260:	3d e8 03 00 00       	cmp    $0x3e8,%eax
  401265:	76 05                	jbe    40126c <secret_phase+0x2a>
  401267:	e8 ce 01 00 00       	callq  40143a <explode_bomb>
  40126c:	89 de                	mov    %ebx,%esi
  40126e:	bf f0 30 60 00       	mov    $0x6030f0,%edi
  401273:	e8 8c ff ff ff       	callq  401204 <fun7>
```

在`secret_phase`中，首先会调用一个`strtol`函数将输入的内容转换成10进制数，说明我们的输入要是一个数字。然后将返回值与999进行比较，如果大于999就会爆炸。然后将输入的数字作为第二个参数，`0x6030f0`作为第一个参数调用`fun7`。

查看`0x6030f0`：

```shell
pwndbg> x /120w 0x6030f0
0x6030f0 <n1>:		0x00000024	0x00000000	0x00603110	0x00000000
0x603100 <n1+16>:	0x00603130	0x00000000	0x00000000	0x00000000
0x603110 <n21>:		0x00000008	0x00000000	0x00603190	0x00000000
0x603120 <n21+16>:	0x00603150	0x00000000	0x00000000	0x00000000
0x603130 <n22>:		0x00000032	0x00000000	0x00603170	0x00000000
0x603140 <n22+16>:	0x006031b0	0x00000000	0x00000000	0x00000000
0x603150 <n32>:		0x00000016	0x00000000	0x00603270	0x00000000
0x603160 <n32+16>:	0x00603230	0x00000000	0x00000000	0x00000000
0x603170 <n33>:		0x0000002d	0x00000000	0x006031d0	0x00000000
0x603180 <n33+16>:	0x00603290	0x00000000	0x00000000	0x00000000
0x603190 <n31>:		0x00000006	0x00000000	0x006031f0	0x00000000
0x6031a0 <n31+16>:	0x00603250	0x00000000	0x00000000	0x00000000
0x6031b0 <n34>:		0x0000006b	0x00000000	0x00603210	0x00000000
0x6031c0 <n34+16>:	0x006032b0	0x00000000	0x00000000	0x00000000
0x6031d0 <n45>:		0x00000028	0x00000000	0x00000000	0x00000000
0x6031e0 <n45+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x6031f0 <n41>:		0x00000001	0x00000000	0x00000000	0x00000000
0x603200 <n41+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603210 <n47>:		0x00000063	0x00000000	0x00000000	0x00000000
0x603220 <n47+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603230 <n44>:		0x00000023	0x00000000	0x00000000	0x00000000
0x603240 <n44+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603250 <n42>:		0x00000007	0x00000000	0x00000000	0x00000000
0x603260 <n42+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603270 <n43>:		0x00000014	0x00000000	0x00000000	0x00000000
0x603280 <n43+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x603290 <n46>:		0x0000002f	0x00000000	0x00000000	0x00000000
0x6032a0 <n46+16>:	0x00000000	0x00000000	0x00000000	0x00000000
0x6032b0 <n48>:		0x000003e9	0x00000000	0x00000000	0x00000000
0x6032c0 <n48+16>:	0x00000000	0x00000000	0x00000000	0x00000000
```

分析发现这是一颗树，节点结构如下：

```c
struct node{
    long value;
    node *lchild,*rchild;
}
```

还原整棵二叉树：

![](https://imgbed.niebelungen-d.top/images/2021/02/02/Snipaste_2021-02-02_16-33-57.png)

是一颗排序二叉树。

```assembly
0000000000401204 <fun7>:
  401204:	48 83 ec 08          	sub    $0x8,%rsp
  401208:	48 85 ff             	test   %rdi,%rdi
  40120b:	74 2b                	je     401238 <fun7+0x34>
  40120d:	8b 17                	mov    (%rdi),%edx
  40120f:	39 f2                	cmp    %esi,%edx
  401211:	7e 0d                	jle    401220 <fun7+0x1c>
  401213:	48 8b 7f 08          	mov    0x8(%rdi),%rdi
  401217:	e8 e8 ff ff ff       	callq  401204 <fun7>
  40121c:	01 c0                	add    %eax,%eax
  40121e:	eb 1d                	jmp    40123d <fun7+0x39>
  401220:	b8 00 00 00 00       	mov    $0x0,%eax
  401225:	39 f2                	cmp    %esi,%edx
  401227:	74 14                	je     40123d <fun7+0x39>
  401229:	48 8b 7f 10          	mov    0x10(%rdi),%rdi
  40122d:	e8 d2 ff ff ff       	callq  401204 <fun7>
  401232:	8d 44 00 01          	lea    0x1(%rax,%rax,1),%eax
  401236:	eb 05                	jmp    40123d <fun7+0x39>
  401238:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  40123d:	48 83 c4 08          	add    $0x8,%rsp
  401241:	c3                   	retq
```

首先判断是否为空树，若是则返回-1。然后判断根节点的值是否小于等于我们输入的数。

若是，eax赋值为0，并判断根节点的值是否等于我们输入的数。相等则返回0。否则访问右子树，调用`fun7`。返回后，返回值*2+1，并回到`secret_phase`。

若否，访问左子树，调用`fun7`。返回后，返回值*2，并回到`secret_phase`。

上述操作就是在遍历二叉树，寻找与我们输入的数，并返回相应的值。

```assembly
  401278:	83 f8 02             	cmp    $0x2,%eax
  40127b:	74 05                	je     401282 <secret_phase+0x40>
  40127d:	e8 b8 01 00 00       	callq  40143a <explode_bomb>
  401282:	bf 38 24 40 00       	mov    $0x402438,%edi
  401287:	e8 84 f8 ff ff       	callq  400b10 <puts@plt>
  40128c:	e8 33 03 00 00       	callq  4015c4 <phase_defused>
  401291:	5b                   	pop    %rbx
  401292:	c3                   	retq
```

从`fun7`返回后，比较返回值与2，不相等就会爆炸。所以我们要找出令返回值为2的值。

我们的输入一定要在树中，不然就会返回负数。第二层的返回值只能是0或1，所以答案在三四层。

其次，我们输入的值一定是在某个右子树上，这样才会产生1。否则永远都是零。

若为7，返回4。22，返回2。20，返回2。35，返回4。47，返回4。

所以答案为：

```text
20/22
```

```bash
niebelungen@ubuntu:~/Desktop/bomb$ ./bomb
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
Border relations with Canada have never been better.
Phase 1 defused. How about the next one?
1 2 4 8 16 32
That's number 2.  Keep going!
0	207
Halfway there!
7 0 DrEvil
So you got that one.  Try this one.
ionefg
Good work!  On to the next...
4 3 2 1 6 5
Curses, you've found the secret phase!
But finding it and solving it are quite different...
22
Wow! You've defused the secret stage!
Congratulations! You've defused the bomb!
```


