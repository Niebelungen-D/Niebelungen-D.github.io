# uCore-lab-5


# 练习0

在`idt_init`中添加

```c
SETGATE(idt[T_SYSCALL], 0, GD_KTEXT, __vectors[T_SYSCALL], DPL_USER);
```

修改定时器中断：

```c
        ticks ++;
        if (ticks % TICK_NUM == 0) {
            assert(current != NULL);
            current->need_resched = 1;
            // print_ticks();
        }  
```

在`alloc_proc`中多出了PCB中的一些字段需要设置

```c
        proc->state = PROC_UNINIT;
        proc->pid = -1;
        proc->kstack = 0;
        proc->need_resched = 0;
        proc->parent = NULL;
        proc->mm = NULL;
        memset(&proc->context, 0, sizeof(struct context));
        proc->tf = NULL;
        proc->cr3 = boot_cr3;
        proc->flags = 0;
        memset(proc->name, 0, sizeof(proc->name));
        proc->wait_state = 0;
        proc->cptr = proc->yptr = proc->optr = NULL;
```

`do_fork`中的链表操作由`set_links`实现

```c
        proc->pid = get_pid();
        hash_proc(proc);
        // list_add(proc_list.prev, &proc->list_link);
        set_links(proc);
        // nr_process++;


```

这里我选择将进程加入到`proc_list`的链表尾部。因为我觉得这样的实现可以在一定程度上，让链表中的进程按照从旧到新的顺序排列。等待越久的进程优先级会越高，而从链表头可以更加方便的获得。实验中并没有对这部分的要求，但我同样通过了测试。

# 练习1

**加载应用程序并执行**
在`load_icode`设置正确的tf字段。

```c
    tf->tf_cs = USER_CS;
    tf->tf_ds = tf->tf_es = tf->tf_ss = USER_DS;
    tf->tf_esp = USTACKTOP;
    tf->tf_eip = elf->e_entry;
    tf->tf_eflags |= FL_IF; 
    ret = 0;
```

# 练习2

**父进程复制自己的内存空间给子进程**
补充`copy_range`的实现

```c
        uintptr_t src_kvaddr = page2kva(page);
        uintptr_t dst_kvaddr = page2kva(npage);
        memcpy(dst_kvaddr, src_kvaddr, PGSIZE);
        page_insert(to, npage, start, perm);
        assert(ret == 0);
```

# 练习3

## fork

fork的流程没有什么变化，不过PCB中多的数据结构和一些链表都通过`set_links`实现了

```c
/**
parent:           proc->parent  (proc is children)
children:         proc->cptr    (proc is parent)
older sibling:    proc->optr    (proc is younger sibling)
younger sibling:  proc->yptr    (proc is older sibling)
**/

// set_links - set the relation links of process
static void
set_links(struct proc_struct *proc) {
    list_add(proc_list.prev, &(proc->list_link));
    proc->yptr = NULL;
    if ((proc->optr = proc->parent->cptr) != NULL) {
        proc->optr->yptr = proc;
    }
    proc->parent->cptr = proc;
    nr_process ++;
}
```

根据注释

- parent：如果proc是某个进程的子进程，则该指针指向其父进程
- cptr：如果proc是某个子进程的父亲，则该指针指向其子进程
- optr：如果该进程说某个进程的多个子进程的一个，且是被较晚创建的那一个，那么该指针指向比它更早创建的兄弟
- yptr：如果该进程说某个进程的多个子进程的一个，且是被较早创建的那一个，那么该指针指向比它更晚创建的兄弟

## exec

```c
// do_execve - call exit_mmap(mm)&put_pgdir(mm) to reclaim memory space of current process
//           - call load_icode to setup new memory space accroding binary prog.
int
do_execve(const char *name, size_t len, unsigned char *binary, size_t size) {
    struct mm_struct *mm = current->mm;
    if (!user_mem_check(mm, (uintptr_t)name, len, 0)) {
        return -E_INVAL;
    }
    if (len > PROC_NAME_LEN) {
        len = PROC_NAME_LEN;
    }

    char local_name[PROC_NAME_LEN + 1];
    memset(local_name, 0, sizeof(local_name));
    memcpy(local_name, name, len);

    if (mm != NULL) {
        lcr3(boot_cr3);
        if (mm_count_dec(mm) == 0) {
            exit_mmap(mm);
            put_pgdir(mm);
            mm_destroy(mm);
        }
        current->mm = NULL;
    }
    int ret;
    if ((ret = load_icode(binary, size)) != 0) {
        goto execve_exit;
    }
    set_proc_name(current, local_name);
    return 0;

execve_exit:
    do_exit(ret);
    panic("already exit: %e.\n", ret);
}
```

首先，通过当前进程的`mm`字段，检查对应内存的权限等情况是否存在异常。接着，加载内核的cr3寄存器，回收相应的内存资源。内存使用引用计数法进程垃圾回收。然后，执行`load_icode`。

```c
/* load_icode - load the content of binary program(ELF format) as the new content of current process
 * @binary:  the memory addr of the content of binary program
 * @size:  the size of the content of binary program
 */
static int
load_icode(unsigned char *binary, size_t size) {
    if (current->mm != NULL) {
        panic("load_icode: current->mm must be empty.\n");
    }

    int ret = -E_NO_MEM;
    struct mm_struct *mm;
    //(1) create a new mm for current process
    if ((mm = mm_create()) == NULL) {
        goto bad_mm;
    }
    //(2) create a new PDT, and mm->pgdir= kernel virtual addr of PDT
    if (setup_pgdir(mm) != 0) {
        goto bad_pgdir_cleanup_mm;
    }
    //(3) copy TEXT/DATA section, build BSS parts in binary to memory space of process
    struct Page *page;
    //(3.1) get the file header of the bianry program (ELF format)
    struct elfhdr *elf = (struct elfhdr *)binary;
    //(3.2) get the entry of the program section headers of the bianry program (ELF format)
    struct proghdr *ph = (struct proghdr *)(binary + elf->e_phoff);
    //(3.3) This program is valid?
    if (elf->e_magic != ELF_MAGIC) {
        ret = -E_INVAL_ELF;
        goto bad_elf_cleanup_pgdir;
    }

    uint32_t vm_flags, perm;
    struct proghdr *ph_end = ph + elf->e_phnum;
    for (; ph < ph_end; ph ++) {
    //(3.4) find every program section headers
        if (ph->p_type != ELF_PT_LOAD) {
            continue ;
        }
        if (ph->p_filesz > ph->p_memsz) {
            ret = -E_INVAL_ELF;
            goto bad_cleanup_mmap;
        }
        if (ph->p_filesz == 0) {
            continue ;
        }
    //(3.5) call mm_map fun to setup the new vma ( ph->p_va, ph->p_memsz)
        vm_flags = 0, perm = PTE_U;
        if (ph->p_flags & ELF_PF_X) vm_flags |= VM_EXEC;
        if (ph->p_flags & ELF_PF_W) vm_flags |= VM_WRITE;
        if (ph->p_flags & ELF_PF_R) vm_flags |= VM_READ;
        if (vm_flags & VM_WRITE) perm |= PTE_W;
        if ((ret = mm_map(mm, ph->p_va, ph->p_memsz, vm_flags, NULL)) != 0) {
            goto bad_cleanup_mmap;
        }
        unsigned char *from = binary + ph->p_offset;
        size_t off, size;
        uintptr_t start = ph->p_va, end, la = ROUNDDOWN(start, PGSIZE);

        ret = -E_NO_MEM;

     //(3.6) alloc memory, and  copy the contents of every program section (from, from+end) to process's memory (la, la+end)
        end = ph->p_va + ph->p_filesz;
     //(3.6.1) copy TEXT/DATA section of bianry program
        while (start < end) {
            if ((page = pgdir_alloc_page(mm->pgdir, la, perm)) == NULL) {
                goto bad_cleanup_mmap;
            }
            off = start - la, size = PGSIZE - off, la += PGSIZE;
            if (end < la) {
                size -= la - end;
            }
            memcpy(page2kva(page) + off, from, size);
            start += size, from += size;
        }

      //(3.6.2) build BSS section of binary program
        end = ph->p_va + ph->p_memsz;
        if (start < la) {
            /* ph->p_memsz == ph->p_filesz */
            if (start == end) {
                continue ;
            }
            off = start + PGSIZE - la, size = PGSIZE - off;
            if (end < la) {
                size -= la - end;
            }
            memset(page2kva(page) + off, 0, size);
            start += size;
            assert((end < la && start == end) || (end >= la && start == la));
        }
        while (start < end) {
            if ((page = pgdir_alloc_page(mm->pgdir, la, perm)) == NULL) {
                goto bad_cleanup_mmap;
            }
            off = start - la, size = PGSIZE - off, la += PGSIZE;
            if (end < la) {
                size -= la - end;
            }
            memset(page2kva(page) + off, 0, size);
            start += size;
        }
    }
    //(4) build user stack memory
    vm_flags = VM_READ | VM_WRITE | VM_STACK;
    if ((ret = mm_map(mm, USTACKTOP - USTACKSIZE, USTACKSIZE, vm_flags, NULL)) != 0) {
        goto bad_cleanup_mmap;
    }
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-PGSIZE , PTE_USER) != NULL);
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-2*PGSIZE , PTE_USER) != NULL);
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-3*PGSIZE , PTE_USER) != NULL);
    assert(pgdir_alloc_page(mm->pgdir, USTACKTOP-4*PGSIZE , PTE_USER) != NULL);
    
    //(5) set current process's mm, sr3, and set CR3 reg = physical addr of Page Directory
    mm_count_inc(mm);
    current->mm = mm;
    current->cr3 = PADDR(mm->pgdir);
    lcr3(PADDR(mm->pgdir));

    //(6) setup trapframe for user environment
    struct trapframe *tf = current->tf;
    memset(tf, 0, sizeof(struct trapframe));
    tf->tf_cs = USER_CS;
    tf->tf_ds = tf->tf_es = tf->tf_ss = USER_DS;
    tf->tf_esp = USTACKTOP;
    tf->tf_eip = elf->e_entry;
    tf->tf_eflags |= FL_IF; 

    ret = 0;
out:
    return ret;
bad_cleanup_mmap:
    exit_mmap(mm);
bad_elf_cleanup_pgdir:
    put_pgdir(mm);
bad_pgdir_cleanup_mm:
    mm_destroy(mm);
bad_mm:
    goto out;
}
```

`load_icode`做了加载新进程的主要工作。它为新进程申请内存空间，并读取ELF文件的节头表，根据其中的信息设置每个节点的属性，并将它们映射（mmap）到对应的位置。
然后，拷贝代码节和数据节的数据到对应的虚拟内存。之后，构建bss段和栈段。设置当前进程的mm和tf。

## exit

```c
// do_exit - called by sys_exit
//   1. call exit_mmap & put_pgdir & mm_destroy to free the almost all memory space of process
//   2. set process' state as PROC_ZOMBIE, then call wakeup_proc(parent) to ask parent reclaim itself.
//   3. call scheduler to switch to other process
int
do_exit(int error_code) {
    if (current == idleproc) {
        panic("idleproc exit.\n");
    }
    if (current == initproc) {
        panic("initproc exit.\n");
    }
    
    struct mm_struct *mm = current->mm;
    if (mm != NULL) {
        lcr3(boot_cr3);
        if (mm_count_dec(mm) == 0) {
            exit_mmap(mm);
            put_pgdir(mm);
            mm_destroy(mm);
        }
        current->mm = NULL;
    }
    current->state = PROC_ZOMBIE;
    current->exit_code = error_code;
    
    bool intr_flag;
    struct proc_struct *proc;
    local_intr_save(intr_flag);
    {
        proc = current->parent;
        if (proc->wait_state == WT_CHILD) {
            wakeup_proc(proc);
        }
        while (current->cptr != NULL) {
            proc = current->cptr;
            current->cptr = proc->optr;
    
            proc->yptr = NULL;
            if ((proc->optr = initproc->cptr) != NULL) {
                initproc->cptr->yptr = proc;
            }
            proc->parent = initproc;
            initproc->cptr = proc;
            if (proc->state == PROC_ZOMBIE) {
                if (initproc->wait_state == WT_CHILD) {
                    wakeup_proc(initproc);
                }
            }
        }
    }
    local_intr_restore(intr_flag);
    
    schedule();
    panic("do_exit will not return!! %d.\n", current->pid);
}
```

减少进程mm的指向内存的引用计数，如果必要需要释放其指向内存和mm结构，并清空页表项。设置当前进程的状态为`PROC_ZOMBIE`。
接着，还判断当前其父进程是否在等待子进程退出，如果是则要唤醒父进程。如果该进程还有子进程，则会被`initproc`领养。并且其哥哥进程变成了当前进程的子进程，由此在循环中`initproc`可以将该进程的所有子进程回收。

进程回收完毕之后，调用`schedule()`让cpu运行下一个进程。

## wait

```c
// do_wait - wait one OR any children with PROC_ZOMBIE state, and free memory space of kernel stack
//         - proc struct of this child.
// NOTE: only after do_wait function, all resources of the child proces are free.
int
do_wait(int pid, int *code_store) {
    struct mm_struct *mm = current->mm;
    if (code_store != NULL) {
        if (!user_mem_check(mm, (uintptr_t)code_store, sizeof(int), 1)) {
            return -E_INVAL;
        }
    }

    struct proc_struct *proc;
    bool intr_flag, haskid;
repeat:
    haskid = 0;
    if (pid != 0) {
        proc = find_proc(pid);
        if (proc != NULL && proc->parent == current) {
            haskid = 1;
            if (proc->state == PROC_ZOMBIE) {
                goto found;
            }
        }
    }
    else {
        proc = current->cptr;
        for (; proc != NULL; proc = proc->optr) {
            haskid = 1;
            if (proc->state == PROC_ZOMBIE) {
                goto found;
            }
        }
    }
    if (haskid) {
        current->state = PROC_SLEEPING;
        current->wait_state = WT_CHILD;
        schedule();
        if (current->flags & PF_EXITING) {
            do_exit(-E_KILLED);
        }
        goto repeat;
    }
    return -E_BAD_PROC;

found:
    if (proc == idleproc || proc == initproc) {
        panic("wait idleproc or initproc.\n");
    }
    if (code_store != NULL) {
        *code_store = proc->exit_code;
    }
    local_intr_save(intr_flag);
    {
        unhash_proc(proc);
        remove_links(proc);
    }
    local_intr_restore(intr_flag);
    put_kstack(proc);
    kfree(proc);
    return 0;
}
```

`wait`函数会等待某一子进程（指定PID进程，或者任一子进程）退出（即状态变为PROC_ZOMBIE），然后将对应的子进程从哈希表中解链，清空内核栈和PCB。如果没有子进程处于`PROC_ZOMBIE`状态，则当前进程会变为`PROC_SLEEPING`并执行`schedule`调度其他进程运行，直到子进程退出后，才被唤醒。

# Challenge: COW

## ucore的COW机制的实现思想

父进程和子进程之间共享（share）页面而不是复制（copy）页面。但只要页面被共享，它们就不能被修改，即是只读的。注意此共享是指父子进程共享一个表示内存空间的mm_struct结构的变量。当父进程或子进程试图写一个共享的页面，就产生一个页访问异常，这时内核就把这个页复制到一个新的页面中并标记为可写。注意，原来的页面仍然是写保护的。当其它进程试图写入时，ucore检查写进程是否是这个页面的唯一属主（通过判断page_ref 和 swap_page_count 即 mem_map 中相关 entry 保存的值的和是否为1。）如果是，它把这个页面标记为对这个进程是可写的。

在具体实现上，ucore调用dup_mmap函数，并进一步调用copy_range函数来具体完成对页表内容的复制，这样两个页表表示同一个虚拟地址空间（包括对应的物理地址空间），且还需修改两个页表中每一个页对应的页表项属性为只读，但。在这种情况下，两个进程有两个页表，但这两个页表只映射了一块只读的物理内存。同理，对于换出的页，也采用同样的办法来共享一个换出页。综上所述，我们可以总结出：如果一个页的PTE属性是只读的，但此页所属的VMA描述指出其虚地址空间是可写的，则这样的页是COW页。

当对这样的地址空间进行写操作的时候，会触发do_pgfault函数被调用。此函数如果发现是COW页，就会调用alloc_page函数新分配一个物理页，并调用memcpy函数把旧页的内容复制到新页中，并最后调用page_insert函数给当前产生缺页错的进程建立虚拟页地址到新物理页地址的映射关系（即改写PTE，并设置此页为可读写）。

这里还有一个特殊情况，如果产生访问异常的页已经被换出到硬盘上了，则需要把此页通过swap_in_page函数换入到内存中来，如果进一步发现换入的页是一个COW页，则把其属性设置为只读，然后异常处理结束返回。但这样重新执行产生异常的写操作，又会触发一次内存访问异常，则又要执行上一段描述的过程了。

Page结构的ref域用于跟踪共享相应页面的进程数目。只要进程释放一个页面或者在它上面执行写时复制，它的ref域就递减；只有当ref变为0时，这个页面才被释放。

## DO IT

在`copy_range`中通过判断share参数是否被指定，选择是share还是完全复制。

```c
int
copy_range(pde_t *to, pde_t *from, uintptr_t start, uintptr_t end, bool share) {
    assert(start % PGSIZE == 0 && end % PGSIZE == 0);
    assert(USER_ACCESS(start, end));
    // copy content by page unit.
    do {
        //call get_pte to find process A's pte according to the addr start
        pte_t *ptep = get_pte(from, start, 0), *nptep;
        if (ptep == NULL) {
            start = ROUNDDOWN(start + PTSIZE, PTSIZE);
            continue ;
        }
        //call get_pte to find process B's pte according to the addr start. If pte is NULL, just alloc a PT
        if (*ptep & PTE_P) {
            if ((nptep = get_pte(to, start, 1)) == NULL) {
                return -E_NO_MEM;
            }
        uint32_t perm = (*ptep & PTE_USER);
        //get page from ptep
        struct Page *page = pte2page(*ptep);
        int ret=0;
        if(share)	// 如果是共享的只需要将页表项复制即可。
        {
            ret = page_insert(to, page, start, perm &~ PTE_W);
            // page_insert(from, page, start, perm &~ PTE_W);
        }
        else {
        // alloc a page for process B
            struct Page *npage = alloc_page();
            assert(page!=NULL);
            assert(npage!=NULL);
            uintptr_t src_kvaddr = page2kva(page);
            uintptr_t dst_kvaddr = page2kva(npage);
            memcpy(dst_kvaddr, src_kvaddr, PGSIZE);
            ret = page_insert(to, npage, start, perm);
        }
        assert(ret == 0);
        start += PGSIZE;
    } while (start != 0 && start < end);
    return 0;
}
```

修改`do_pgfault`

```c
int
do_pgfault(struct mm_struct *mm, uint32_t error_code, uintptr_t addr) {
    int ret = -E_INVAL;
    //try to find a vma which include addr
    struct vma_struct *vma = find_vma(mm, addr);

    pgfault_num++;
    //If the addr is in the range of a mm's vma?
    if (vma == NULL || vma->vm_start > addr) {
        cprintf("not valid addr %x, and  can not find it in vma\n", addr);
        goto failed;
    }
    //check the error_code
    switch (error_code & 3) {
    default:
            /* error code flag : default is 3 ( W/R=1, P=1): write, present */
    case 2: /* error code flag : (W/R=1, P=0): write, not present */
        if (!(vma->vm_flags & VM_WRITE)) {
            cprintf("do_pgfault failed: error code flag = write AND not present, but the addr's vma cannot write\n");
            goto failed;
        }
        break;
    case 1: /* error code flag : (W/R=0, P=1): read, present */
        cprintf("do_pgfault failed: error code flag = read AND present\n");
        goto failed;
    case 0: /* error code flag : (W/R=0, P=0): read, not present */
        if (!(vma->vm_flags & (VM_READ | VM_EXEC))) {
            cprintf("do_pgfault failed: error code flag = read AND not present, but the addr's vma cannot read or exec\n");
            goto failed;
        }
    }
    /* IF (write an existed addr ) OR
     *    (write an non_existed addr && addr is writable) OR
     *    (read  an non_existed addr && addr is readable)
     * THEN
     *    continue process
     */
    uint32_t perm = PTE_U;
    if (vma->vm_flags & VM_WRITE) {
        perm |= PTE_W;
    }
    addr = ROUNDDOWN(addr, PGSIZE);

    ret = -E_NO_MEM;

    pte_t *ptep=NULL;

#if 1
    //(1) try to find a pte, if pte's PT(Page Table) isn't existed, then create a PT.
    if((ptep = get_pte(mm->pgdir, addr, 1)) == NULL)              
    {
        cprintf("get_pte in do_pgfalut failed\n");
        goto failed;
    }
    if (*ptep == 0) {
        //(2) if the phy addr isn't exist, then alloc a page & map the phy addr with logical addr
        if(pgdir_alloc_page(mm->pgdir, addr, perm) == NULL) {                    
            cprintf("pgdir_alloc_page in do_pgfalut failed\n");
            goto failed;
        }        
    }
    else {
        struct Page *page = NULL;
        if(*ptep & PTE_P)	// 如果是COW的页
        {
            if(page_ref(page) > 1) 
            {
                struct Page *npage = alloc_page();
                page = pte2page(*ptep);
                assert(page!=NULL);
                assert(npage!=NULL);
                void *src_kvaddr = page2kva(page);
                void *dst_kvaddr = page2kva(npage);
                memcpy(dst_kvaddr, src_kvaddr, PGSIZE);
                // page_remove(mm->pgdir, addr);
                // page_ref_dec(page);
                ret = page_insert(mm->pgdir, npage, addr, perm&PTE_W);  
            }
            else
                ret = page_insert(mm->pgdir, page, addr, perm&PTE_W); 
          
        }
        else {
            if(swap_init_ok) {
                //(1）According to the mm AND addr, try to load the content of right disk page
                //    into the memory which page managed.
                if((ret = swap_in(mm, addr, &page)) != 0)
                {
                    cprintf("swap_in in do_pgfalut failed\n");
                    goto failed;
                }
                //(2) According to the mm, addr AND page, setup the map of phy addr <---> logical addr
                page_insert(mm->pgdir, page, addr, perm);
                //(3) make the page swappable.
                swap_map_swappable(mm, addr, page, 1);
                page->pra_vaddr = addr;
            }
            else {
                cprintf("no swap_init_ok but ptep is %x, failed\n", *ptep);
                goto failed;
            }
        }
   }
#endif
   ret = 0;
failed:
    return ret;
}
```

如果是COW的页，则要为当前进程创建一个页的拷贝，并替换这个进程的页表，设置权限为可读可写。在执行COW时，都会有一个页失去对共享页的引用，这个在我们进行页表的更新时就完成了。如果当前的页仅有一个引用，那么只需要更新页表重新设置权限即可，不需要仔申请新的页面了。

