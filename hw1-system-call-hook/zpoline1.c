#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include "print_blob.h"

#define PAGE_SIZE 4096
#define NUM_SYSCALL 512
#define NOPS 0x90

__attribute__((constructor))
static void zpoline_setup(void) {
    size_t page_size = PAGE_SIZE;
    void *base = mmap((void *)(0x0), page_size, PROT_READ | PROT_WRITE | PROT_EXEC, 
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (base == MAP_FAILED) {
        perror("[zpoline] mmap failed");
        _exit(1);
    }
    memset(base, NOPS, NUM_SYSCALL);
    memcpy((unsigned char *)base + NUM_SYSCALL, print_bin, print_bin_len);
    mprotect(base, page_size, PROT_READ | PROT_EXEC);
}