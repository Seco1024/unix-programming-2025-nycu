#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <linux/sched.h> 
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PAGE_SZ           4096UL
#define NOP               0x90
#define TRAMPOLINE_OFFSET 512       

extern void syscall_hook(void);
typedef long (*sys_hook_t)(long, long, long, long, long, long, long);

static long real_syscall(long a1, long a2, long a3, long a4, long a5, long a6, long nr) {
    register long _r10 asm("r10") = a4;
    register long _r8  asm("r8")  = a5;
    register long _r9  asm("r9")  = a6;
    long ret;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(nr), "D"(a1), "S"(a2), "d"(a3),
                   "r"(_r10), "r"(_r8), "r"(_r9)
                 : "rcx", "r11", "memory");
    return ret;
}

static sys_hook_t the_hook = real_syscall;


long c_hook_bridge(long rdi_arg1, long rsi_arg2, long rdx_arg3, long r10_arg4, long r8_arg5, long r9_arg6, long nr, long retptr) {
if (nr == SYS_clone) {
    unsigned long flags = (unsigned long)rdi_arg1;
    if ((flags & CLONE_VM) && rsi_arg2) {
        *(uint64_t *)(rsi_arg2 + 8) = (uint64_t)retptr;   
    }
}

else if (nr == SYS_clone3) {
    struct clone_args {
        uint64_t flags, pidfd, child_tid, parent_tid,
                 exit_signal, stack, stack_size;     
    };
    struct clone_args *ca = (struct clone_args *)(uintptr_t)rdi_arg1;
    if ((ca->flags & CLONE_VM) && ca->stack && ca->stack_size >= 16) {
        *(uint64_t *)(ca->stack + ca->stack_size + 8) = (uint64_t)retptr;
    }
}
    return the_hook(rdi_arg1, rsi_arg2, rdx_arg3, r10_arg4, r8_arg5, r9_arg6, nr);
}

static void load_user_hook(void) {
    const char *lib = getenv("LIBZPHOOK");
    if (!lib || !*lib) {
        return;
    }

    void *h = dlmopen(LM_ID_NEWLM, lib, RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        fprintf(stderr, "dlmopen %s failed: %s\n", lib, dlerror());
        return;
    }

    typedef void (*init_t)(const sys_hook_t real_syscall_ptr, sys_hook_t *hook_ptr_to_update);
    init_t init = (init_t)dlsym(h, "__hook_init");
    if (!init) {
         fprintf(stderr, "__hook_init not found in %s: %s\n", lib, dlerror()); 
        return;
    }

    init(real_syscall, &the_hook);
}


static bool skip_path(const char *p)
{
    bool should_skip = (p && (strstr(p, "libzpoline.so") ||
                              strstr(p, "logger.so") ||
                              strstr(p, "[vdso]") ||
                              (strstr(p, "[vsyscall]") && strchr(p, '/') == NULL) ||
                              strstr(p, "[stack]")));
                              
    return should_skip;
}

static void patch_region(uint8_t *code_start_addr, size_t region_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;


    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return;
    }

    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON); // Ignore error, proceed if possible

    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
         cs_close(&handle);
         return;
    }

    count = cs_disasm(handle, code_start_addr, region_size, (uint64_t)code_start_addr, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            if (insn[i].id == X86_INS_SYSCALL) {
                if (insn[i].size == 2) {
                    uint8_t *patch_location = (uint8_t *)insn[i].address;
                    patch_location[0] = 0xFF; 
                    patch_location[1] = 0xD0; 

                } 
            }
        }
        cs_free(insn, count);
    }
    cs_close(&handle);
}


static void scan_and_patch(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("[zpoline] fopen /proc/self/maps failed");
        _exit(1);
    }
    char line[512];
    int region_count = 0;
    int processed_region_count = 0;

    while (fgets(line, sizeof line, fp)) {
        unsigned long region_start, region_end;
        char permissions[5] = {0};
        char path[400] = {0};

        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %[^\n]",
                   &region_start, &region_end, permissions, path) < 3) {
             if (sscanf(line, "%lx-%lx %4s", &region_start, &region_end, permissions) != 3) continue;
             path[0] = '\0';
        }

        region_count++;
        if (!strchr(permissions, 'x') || !strchr(permissions, 'r') || skip_path(path)) {
            continue;
        }
        processed_region_count++;

        uintptr_t segment_start = region_start;
        size_t segment_length = region_end - region_start;
        uintptr_t page_start = segment_start & ~(PAGE_SZ - 1);
        size_t page_length = ((segment_start - page_start + segment_length + PAGE_SZ - 1) / PAGE_SZ) * PAGE_SZ;
        bool needs_rw = !strchr(permissions, 'w');

        if (needs_rw) {
            if (mprotect((void *)page_start, page_length, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                continue;
            }
        }

        patch_region((uint8_t *)segment_start, segment_length);

        if (needs_rw) {
            if (mprotect((void *)page_start, page_length, PROT_READ | PROT_EXEC) != 0) {
               perror("[zpoline] mprotect RX restore failed"); // Keep essential errors
            }
        }
    }
    fclose(fp);
}

static void build_trampoline(void)
{
    uint8_t *base = mmap((void *)0, PAGE_SZ,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap VA 0 failed"); 
        _exit(1);
    }

    memset(base, NOP, TRAMPOLINE_OFFSET);
    uint8_t trampoline_code[] = {
        0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00, /* sub $0x80,%rsp */
        0x49, 0xBB,                               /* movabs $imm64,%r11 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* <addr> */
        0x41, 0xFF, 0xD3,                         /* call *%r11 */
        0x48, 0x81, 0xC4, 0x80, 0x00, 0x00, 0x00, /* add $0x80,%rsp */
        0xC3                                      /* ret */
    };
    memcpy(base + TRAMPOLINE_OFFSET, trampoline_code, sizeof(trampoline_code));
    uint64_t hook_fn_addr = (uint64_t)syscall_hook;
    memcpy(base + TRAMPOLINE_OFFSET + 9, &hook_fn_addr, sizeof(hook_fn_addr));

    if (mprotect(base, PAGE_SZ, PROT_READ | PROT_EXEC) != 0) {
        perror("[zpoline] mprotect VA 0 RO failed"); 
    }
}

__attribute__((constructor))
static void zpoline_init(void)
{
    build_trampoline();
    scan_and_patch();
    load_user_hook();
}