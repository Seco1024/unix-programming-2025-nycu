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

#define PAGE_SIZE 4096
#define PAGE_SZ 4096UL
#define TRAMPOLINE_OFFSET 512
#define NOPS 0x90

extern void syscall_hook(void);
int64_t handler(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

static int64_t trigger_syscall(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8,  int64_t r9, int64_t rax) {
    int64_t ret_val;
    register int64_t _r10 asm("r10") = r10;
    register int64_t _r8 asm("r8") = r8;
    register int64_t _r9 asm("r9") = r9;

    errno = 0; 
    asm volatile (
        "syscall"
        : "=a" (ret_val)  /* Output: rax -> ret_val ('a' constraint) */
        : "a" (rax),  /* Input: sys_rax -> rax ('a' constraint) */
        "D" (rdi),  /* Input: sys_rdi -> rdi ('D' constraint) */
        "S" (rsi),  /* Input: sys_rsi -> rsi ('S' constraint) */
        "d" (rdx),  /* Input: sys_rdx -> rdx ('d' constraint) */
        "r" (_r10),     /* Input: _r10 -> r10 ('r' generic, hint helps) */
        "r" (_r8),      /* Input: _r8  -> r8  ('r' generic, hint helps) */
        "r" (_r9)       /* Input: _r9  -> r9  ('r' generic, hint helps) */
        : "rcx", "r11", "memory" 
    );
    int syscall_errno = errno; 

    if (ret_val < 0 && ret_val > -4096) { 
        errno = -ret_val;
    } else {
        if (ret_val >= 0) errno = 0;
        else errno = syscall_errno;
    }

    return ret_val; 
}

__attribute__((visibility("default")))
int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx, int64_t r8,  int64_t r9,  int64_t rax) {
    int64_t out_rsi = rsi;
    if (rax == 1 && rdi == 1 && rsi && rdx > 0) {
        size_t len = (size_t)rdx;
        char *tmp = malloc(len);
        memcpy(tmp, (void*)rsi, len);
        for (size_t i = 0; i < len; i++) {
            switch (tmp[i]) {
                case '0': tmp[i] = 'o'; break;
                case '1': tmp[i] = 'i'; break;
                case '2': tmp[i] = 'z'; break;
                case '3': tmp[i] = 'e'; break;
                case '4': tmp[i] = 'a'; break;
                case '5': tmp[i] = 's'; break;
                case '6': tmp[i] = 'g'; break;
                case '7': tmp[i] = 't'; break;
                default:  break;
            }
        }
        out_rsi = (int64_t)tmp;
    }
    return trigger_syscall(rdi, out_rsi, rdx, rcx, r8, r9, rax);
}

static void rewrite_region(uint8_t *base, size_t len) {
    const uint8_t hook_op[2] = { 0xFF, 0xD0 };
    for (size_t off = 0; off + 1 < len; off++) {
        if (base[off] == 0x0F && base[off+1] == 0x05) {
            memcpy(base + off, hook_op, 2);
            off++;  
        }
    }
}

static void rewrite_code(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) { 
        perror("maps"); 
        exit(1); 
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        char perm[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perm) != 3) 
            continue;
        if (!strchr(perm, 'x') || strstr(line, "[vdso]") || strstr(line," [vsyscall]") || strstr(line, "[stack]")  || strstr(line, "libzpoline.so.2"))
            continue;

        size_t pagesz = PAGE_SIZE;
        uintptr_t page_start = (uintptr_t)start & ~(pagesz - 1);
        uintptr_t page_end   = ((uintptr_t)end + pagesz - 1) & ~(pagesz - 1);
        size_t   prot_len    = page_end - page_start;

        if (mprotect((void*)page_start, prot_len, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) {
            perror("mprotect RW failed");
            return;
        }
    }
    fclose(fp);

    FILE *fp2 = fopen("/proc/self/maps", "r");
    if (!fp2) { 
        perror("maps"); 
        exit(1); 
    }

    char line2[256];
    while (fgets(line2, sizeof(line2), fp2)) {
        unsigned long start, end;
        char perm[5];
        if (sscanf(line2, "%lx-%lx %4s", &start, &end, perm) != 3) 
            continue;
        if (!strchr(perm, 'x') || strstr(line2, "[vdso]") || strstr(line2," [vsyscall]") || strstr(line2, "[stack]")  || strstr(line2, "libzpoline.so.2"))
            continue;
        rewrite_region((uint8_t*)start, end - start);
    }
    fclose(fp2);
}

void trampoline_setup(uint8_t *base)
{
    /* sub $0x80,%rsp */
    uint8_t trampoline[] = {
        0x48, 0x81, 0xEC ,0x80, 0x00, 0x00, 0x00,          // sub $0x80,%rsp
        0x49, 0xBB,                                        // movabs imm64, %r11
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x41, 0xFF, 0xD3,                                  // call *%r11
        0x48,0x81,0xC4,0x80,0x00,0x00,0x00,                // add $0x80,%rsp
        0xC3                                               // ret
    };
    memcpy(base + TRAMPOLINE_OFFSET, trampoline, sizeof(trampoline));
    uint64_t h_fn = (uint64_t)syscall_hook;
    memcpy(base + TRAMPOLINE_OFFSET + 9, &h_fn, 8);  
}

static bool skip_path(const char *p)
{
    bool should_skip = (p && (strstr(p, "libzpoline.so.2") ||
                              strstr(p, "logger.so") ||
                              strstr(p, "[vdso]") ||
                              strstr(p, "[vsyscall]") ||
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

__attribute__((constructor))
static void zpoline_setup(void) {
    void *base = mmap((void *)0x0, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, 
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (base == MAP_FAILED) {
        perror("[zpoline] mmap failed");
        _exit(1);
    }
    memset(base, NOPS, TRAMPOLINE_OFFSET);
    trampoline_setup((uint8_t *)base);
    mprotect(base, PAGE_SIZE, PROT_READ | PROT_EXEC);
    // rewrite_code();
    scan_and_patch();
}