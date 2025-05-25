#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <limits.h>  
#include <signal.h>
#include <ctype.h>    
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/sysmacros.h> 
#include <capstone/capstone.h>

#define MAX_LINE 256
#define BYTE_COL_WIDTH 24
#define MAX_BP  128     

typedef struct {
    int id;
    unsigned long addr;
    unsigned char orig_byte;
    int active; 
} bp_t;

static char input[MAX_LINE];
static pid_t child_pid = -1;
static unsigned long base_addr = 0;
static unsigned long entry_offset = 0;
static unsigned long entry_point = 0;
static Elf64_Ehdr ehdr;
static int is_terminated = 0;
static bp_t bp_tbl[MAX_BP];
static int bp_cnt = 0;        
static bp_t *pending_bp = NULL;
static int in_syscall_phase = 0;
static long last_sys_nr = 0; 

enum cmd_id {
    CMD_LOAD,
    CMD_SI,
    CMD_CONT,
    CMD_INFO,
    CMD_BREAK,
    CMD_BREAKRVA,
    CMD_DELETE,
    CMD_PATCH,
    CMD_SYSCALL,
    CMD_UNKNOWN
};

void handle_command(void);
void cmd_load(char *path);
void cmd_si(void);
void cmd_cont(void);
void cmd_info_reg(void);
void cmd_info_break(void);
void cmd_break(const char *addr_str);
void cmd_breakrva(const char *off_str);
void cmd_delete(const char *id_str);
void cmd_patch(const char *addr_str, const char *hex);
void cmd_syscall(void);
unsigned long get_entry_offset(const char *path);
unsigned long get_base_address(pid_t pid, const char *exe_path);
enum cmd_id lookup_cmd(char *cmd);
void disassemble_at(pid_t pid, unsigned long addr, int count);
static int addr_is_executable(unsigned long addr);
static int parse_u64(const char *s, unsigned long *out);
static bp_t *find_bp_by_addr(unsigned long addr);
static int hexpair_to_byte(char hi, char lo, unsigned char *out);
static void enable_breakpoint(bp_t *bp);


enum cmd_id lookup_cmd(char *cmd) {
    if (!cmd) return CMD_UNKNOWN;
    if (strcmp(cmd, "load") == 0) return CMD_LOAD;
    if (strcmp(cmd, "si")   == 0) return CMD_SI;
    if (strcmp(cmd, "cont") == 0) return CMD_CONT;
    if (strcmp(cmd, "info") == 0) return CMD_INFO;
    if (strcmp(cmd, "break") == 0) return CMD_BREAK;
    if (strcmp(cmd, "breakrva") == 0) return CMD_BREAKRVA;
    if (strcmp(cmd, "delete") == 0) return CMD_DELETE;
    if (strcmp(cmd, "patch") == 0)   return CMD_PATCH; 
    if (strcmp(cmd, "syscall") == 0) return CMD_SYSCALL;
    return CMD_UNKNOWN;
}

void handle_command(void) {
    char raw[MAX_LINE];
    strncpy(raw, input, MAX_LINE);
    char *tok = strtok(input, " \t\n");
    enum cmd_id id = lookup_cmd(tok);
    switch (id) {
        case CMD_LOAD: {
            char *arg = strtok(NULL, " \t\n");
            cmd_load(arg);
            break;
        }
        case CMD_SI:
            cmd_si();
            break;
        case CMD_CONT:
            cmd_cont();
            break;
        case CMD_INFO: {
            char *sub = strtok(NULL, " \t\n");
            if (sub && strcmp(sub, "reg") == 0) cmd_info_reg();
            else if (sub && strcmp(sub, "break") == 0) cmd_info_break();
            else printf("** unknown command 'info %s'\n", sub ? sub : "");
            break;
        }
        case CMD_BREAK: {
            char *addr = strtok(NULL, " \t\n");
            if (addr) cmd_break(addr);
            else printf("** the target address is not valid.\n");
            break;
        }
        case CMD_BREAKRVA: {
            char *addr = strtok(NULL, " \t\n");
            if (addr) cmd_breakrva(addr);
            else printf("** the target address is not valid.\n");
            break;
        }
        case CMD_DELETE: {
            char *id = strtok(NULL, " \t\n");
            if (id) cmd_delete(id);
            else printf("** the target id is not valid.\n");
            break;
        }
        case CMD_PATCH: {                             
            char *addr = strtok(NULL, " \t\n");
            char *hex  = strtok(NULL, " \t\n");
            if (addr && hex) cmd_patch(addr, hex);
            else puts("** the target address is not valid.");
            break;
        }
        case CMD_SYSCALL:
            cmd_syscall();
            break;
        default:
            printf("** unknown command '%s'\n", raw);
    }
}

static int addr_is_executable(unsigned long addr) {
    char maps[64];  
    snprintf(maps, sizeof(maps), "/proc/%d/maps", child_pid);
    FILE *fp = fopen(maps, "r");  
    if (!fp) return 0;

    char line[256];
    while (fgets(line, sizeof line, fp)) {
        unsigned long start, end;
        unsigned long off, ino;
        char perms[5], dev[6];
        if (sscanf(line,"%lx-%lx %4s %lx %5s %lu", &start, &end, perms, &off, dev, &ino) == 6){
            if (strchr(perms,'x') && addr >= start && addr < end) { 
                fclose(fp); 
                return 1; 
            }
        }
    }
    fclose(fp);
    return 0;
}

static int parse_u64(const char *s, unsigned long *out) {
    if (!s || !*s) return 0;
    if (!strncmp(s, "0x", 2) || !strncmp(s, "0X", 2)) s += 2;

    char *end;
    unsigned long val = strtoul(s, &end, 16);      /* base 16 */
    if (*end) return 0;                            /* non-hex */

    *out = val;
    return 1;
}

static bp_t* find_bp_by_addr(unsigned long addr) { 
    for (int i = 0; i < bp_cnt; ++i) {
        if(bp_tbl[i].active && bp_tbl[i].addr == addr) 
            return &bp_tbl[i];
    }
    return NULL;
}

void restore_byte(bp_t *bp) {
    int idx  = bp->addr & 0x7;
    long word = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)(bp->addr - idx), NULL);   
    unsigned char *bytes = (unsigned char *)&word;
    bytes[idx] = bp->orig_byte;  
    ptrace(PTRACE_POKETEXT, child_pid, (void *)(bp->addr - idx), (void *)word);
}

void cmd_load(char *path) {
    if (!path) {
        printf("** please specify a program to load.\n");
        return;
    }
    if (access(path, F_OK) == -1) { 
        fprintf(stderr, "** error: program '%s' not found: ", path); 
        perror(NULL); 
        return; 
    }
    if (access(path, X_OK) == -1) { 
        fprintf(stderr, "** error: program '%s' not executable: ", path); 
        perror(NULL); 
        return; 
    }

    entry_offset = get_entry_offset(path);
    pid_t pid = fork();
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) { 
            perror("ptrace TRACEME"); 
            _exit(1); 
        }
        execl(path, path, NULL);
        perror("execl"); _exit(1);
    }
    child_pid = pid;
    int status;
    waitpid(pid, &status, 0);

    base_addr = get_base_address(pid, path);
    entry_point = base_addr + entry_offset;

    int idx = entry_point & 7;
    long word = ptrace(PTRACE_PEEKTEXT, pid, entry_point - idx, NULL);
    unsigned char orig = ((unsigned char *)&word)[idx];
    ((unsigned char *)&word)[idx] = 0xCC;

    ptrace(PTRACE_POKETEXT, pid, entry_point - idx, word);
    ptrace(PTRACE_CONT, pid, NULL, NULL);            
    int st; 
    waitpid(pid, &st, 0);                

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rip = entry_point;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ((unsigned char *)&word)[idx] = orig;
    ptrace(PTRACE_POKETEXT, pid, entry_point - idx, word);

    printf("** program '%s' loaded. entry point: 0x%lx.\n", path, entry_point);
    disassemble_at(pid, entry_point, 5);
}

void cmd_si(void) {
    if (child_pid < 0) {
        printf("** please load a program first.\n");
        return;
    }
    if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) { 
        perror("ptrace SINGLESTEP"); 
        return; 
    }
    int status;
    waitpid(child_pid, &status, 0);
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        printf("** the target program terminated.\n");
        is_terminated = 1;
    } 
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        unsigned long bp_addr = regs.rip;
        bp_t *bp = find_bp_by_addr(regs.rip);
        if (bp) {
            restore_byte(bp);
            regs.rip = bp_addr;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            printf("** hit a breakpoint at 0x%lx.\n", bp_addr);
            pending_bp = bp;  
        }
        disassemble_at(child_pid, regs.rip, 5);
    }
}

void cmd_cont(void) {
    if (child_pid < 0) {
        printf("** please load a program first.\n");
        return;
    }

    if (pending_bp) {
        if (pending_bp && pending_bp->active) {
            if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
                perror("ptrace SINGLESTEP"); 
                return;
            }
            int status;
            waitpid(child_pid, &status, 0);
            enable_breakpoint(pending_bp);
            pending_bp = NULL; 
        }        
    }

    if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) { 
        perror("ptrace CONT"); 
        return; 
    }

    int status;
    waitpid(child_pid, &status, 0);
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        printf("** the target program terminated.\n");
        is_terminated = 1;
    } 
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        unsigned long bp_addr = regs.rip - 1;
        bp_t *bp = find_bp_by_addr(bp_addr);
        if (bp) {
            restore_byte(bp);
            regs.rip = bp_addr;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

            printf("** hit a breakpoint at 0x%lx.\n", bp_addr);
            disassemble_at(child_pid, regs.rip, 5);
            pending_bp = bp;  
        }
    }
}

void cmd_info_reg(void) {
    if (child_pid < 0) {
        printf("** please load a program first.\n");
        return;
    }
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) < 0) { 
        perror("ptrace GETREGS"); 
        return; 
    }

    printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
}

void cmd_break(const char *addr_str) {
    if (child_pid < 0) {
        printf("** please load a program first.\n");
        return;
    }

    unsigned long addr;
    if (!parse_u64(addr_str, &addr)) {
        printf("** the target address is not valid.\n");
        return;
    }

    if (!addr_is_executable(addr)) {
        printf("** the target address is not valid.\n");
        return;
    }

    int byte_idx = addr & 0x7;     
    long word = ptrace(PTRACE_PEEKTEXT, child_pid, addr - byte_idx, NULL);
    if (word == -1 && errno) {
        perror("ptrace PEEKTEXT");
        return;
    }

    unsigned char *bytes = (unsigned char *)&word;
    unsigned char origin = bytes[byte_idx];  
    bytes[byte_idx] = 0xCC;             
    if (ptrace(PTRACE_POKETEXT, child_pid, addr - byte_idx, (void*)word) < 0) {
        perror("ptrace POKETEXT"); 
        return;
    }

    bp_t *bp = &bp_tbl[bp_cnt++];
    bp->id = bp_cnt - 1;
    bp->addr = addr;
    bp->orig_byte = origin;
    bp->active = 1;

    printf("** set a breakpoint at 0x%lx.\n", addr);
}

void cmd_breakrva(const char *off_str) {
    unsigned long off;
    if (!parse_u64(off_str, &off)) {
        puts("** the target address is not valid.");
        return;
    }

    unsigned long base = base_addr ? base_addr : 0x400000UL;
    unsigned long abs = base + off;
    char buf[32];
    snprintf(buf, sizeof buf, "%lx", abs); 
    cmd_break(buf);                    
}

void cmd_info_break(void) {
    int printed = 0;
    for (int i = 0; i < bp_cnt; i++) {
        if (!bp_tbl[i].active) continue;
        if (!printed) puts("Num     Address");
        printf("%-7d 0x%lx\n", bp_tbl[i].id, bp_tbl[i].addr);
        printed = 1;
    }
    if (!printed) puts("** no breakpoints.");
}

void cmd_delete(const char *id_str) {
    char *end; 
    long id = strtol(id_str, &end, 10);
    if (*end || id < 0 || id >= bp_cnt || !bp_tbl[id].active) {
        printf("** breakpoint %s does not exist.\n", id_str);
        return;
    }
    restore_byte(&bp_tbl[id]);  
    bp_tbl[id].active = 0;
    if (pending_bp == &bp_tbl[id])       
        pending_bp = NULL;
    printf("** delete breakpoint %ld.\n", id);
}

void cmd_patch(const char *addr_str, const char *hex) {
    if (child_pid < 0) {
        puts("** please load a program first.");
        return;
    }

    unsigned long addr;
    if (!parse_u64(addr_str, &addr)) {
        puts("** the target address is not valid."); 
        return;
    }

    size_t hlen = strlen(hex);
    if (!hlen || hlen > 2048 || (hlen & 1)) {
        puts("** the target address is not valid."); 
        return;
    }

    unsigned char bytes[1024];
    for (size_t i = 0; i < hlen; i += 2) {
        if (!hexpair_to_byte(hex[i], hex[i + 1], &bytes[i / 2])) {
            puts("** the target address is not valid."); 
            return;
        }
    }

    size_t n = hlen / 2;

    for (size_t o = 0; o < n; o++) {
        if (!addr_is_executable(addr + o)) {
            puts("** the target address is not valid."); 
            return;
        }
    }

    for (int i = 0; i < bp_cnt; i++) {
        if (!bp_tbl[i].active) continue;
        unsigned long bp_addr = bp_tbl[i].addr;
        if (bp_addr >= addr && bp_addr < addr + n)
            bp_tbl[i].orig_byte = bytes[bp_addr - addr];
    }

    size_t off = 0;
    while (off < n) {
        unsigned long cur = addr + off;
        int idx = cur & 0x7;                   
        long word = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)(cur - idx), NULL);
        if (word == -1 && errno) { 
            perror("PTRACE_PEEKTEXT"); 
            return; 
        }

        size_t span = sizeof(long) - idx;                 
        if (span > n - off) span = n - off;
        memcpy(((unsigned char *)&word) + idx, bytes + off, span);

        if (ptrace(PTRACE_POKETEXT, child_pid, (void *)(cur - idx), (void *)word) < 0) {
            perror("PTRACE_POKETEXT"); return;
        }
        off += span;
    }
    printf("** patch memory at 0x%lx.\n", addr);
} 

void cmd_syscall(void) {
    if (child_pid < 0) {
        puts("** please load a program first.");
        return;
    }

    if (pending_bp && pending_bp->active) {
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace SINGLESTEP");
            return;
        }
        int st;
        waitpid(child_pid, &st, 0);
        enable_breakpoint(pending_bp);
        pending_bp = NULL;
    }

    if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) < 0) {
        perror("ptrace SYSCALL");
        return;
    }

    int status;
    waitpid(child_pid, &status, 0);

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        puts("** the target program terminated.");
        is_terminated = 1;
        return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

    unsigned long bp_addr = regs.rip - 1;        
    bp_t *bp = find_bp_by_addr(bp_addr);

    if (bp) {
        restore_byte(bp);
        regs.rip = bp_addr;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        printf("** hit a breakpoint at 0x%lx.\n", bp_addr);
        disassemble_at(child_pid, regs.rip, 5);
        pending_bp = bp;
        in_syscall_phase = 0;        
        return;
    }

    unsigned long sc_addr = regs.rip - 2;   

    if (!in_syscall_phase) {                   
        last_sys_nr = regs.orig_rax;  
        in_syscall_phase = 1;         

        printf("** enter a syscall(%ld) at 0x%lx.\n", last_sys_nr, sc_addr);
        disassemble_at(child_pid, sc_addr, 5); 
    } else {                            
        long ret = regs.rax;            
        in_syscall_phase = 0;                 

        printf("** leave a syscall(%ld) = %ld at 0x%lx.\n", last_sys_nr, ret, sc_addr);
        disassemble_at(child_pid, sc_addr, 5);
    }
}

unsigned long get_entry_offset(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { 
        perror("open"); 
        return 0; 
    }
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) { 
        perror("read ELF header"); 
        close(fd); 
        return 0; 
    }
    close(fd);
    return ehdr.e_entry;
}

unsigned long get_base_address(pid_t pid, const char *exe_path) {
    char real_exe[PATH_MAX];
    if (!realpath(exe_path, real_exe)) {
        perror("realpath"); return 0;
    }
    struct stat st;   // getting device no. and i-node
    if (stat(real_exe, &st) < 0) { 
        perror("stat"); 
        return 0; 
    }

    // first try: traverse /proc/PID/maps
    char line[512];
    char maps[64]; 
    unsigned long cand_base = 0;

    snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
    FILE *fp = fopen(maps, "r"); 
    if (!fp) { 
        perror("maps"); 
        return 0; 
    }

    while (fgets(line, sizeof line, fp)) {
        unsigned long start, end;
        unsigned long off, inode;
        char perms[5], dev[12], path[PATH_MAX] = "";
        int n = sscanf(line, "%lx-%lx %4s %lx %11s %lu %s", &start, &end, perms, &off, dev, &inode, path);
        if (n < 7 || !strchr(perms, 'x')) continue;

        if (strcmp(path, real_exe) == 0) {
            cand_base = start - off; 
            break;
        }
    }
    fclose(fp);

    // second try: i-node + dev comparison (for patchelf) 
    if (cand_base == 0) {
        fp = fopen(maps, "r");
        while (fgets(line, sizeof line, fp)) {
            unsigned long start, end;
            unsigned long off, inode;
            char perms[5], dev[12];
            if (sscanf(line, "%lx-%lx %4s %lx %11s %lu", &start, &end, perms, &off, dev, &inode) != 6) continue;
            if (!strchr(perms, 'x')) continue;

            unsigned maj, min;
            if (sscanf(dev, "%x:%x", &maj, &min) != 2) continue;
            if (inode == st.st_ino && maj == major(st.st_dev) && min == minor(st.st_dev)) {
                cand_base = start - off;
                break;
            }
        }
        fclose(fp);
    }

    if (ehdr.e_type != ET_DYN) cand_base = 0;
    return cand_base;
}

void disassemble_at(pid_t pid, unsigned long addr, int count) {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

    unsigned long cur = addr;  
    int done = 0;  

    while (done < count) {
        if (!addr_is_executable(cur)) {
            puts("** the address is out of the range of the executable region.");
            break;
        }

        unsigned char buf[16] = {0};
        int fetched = 0;

        for (; fetched < 16; ++fetched) {
            unsigned long baddr = cur + fetched;
            if (!addr_is_executable(baddr)) break;                
            errno = 0;
            long word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(baddr & ~7UL), NULL);
            if (word == -1 && errno) break;         
            buf[fetched] = ((unsigned char *)&word)[baddr & 7];
        }

        if (fetched == 0) {
            puts("** the address is out of the range of the executable region.");
            break;
        }

        for (int k = 0; k < bp_cnt; ++k) {
            if (bp_tbl[k].active && 
                bp_tbl[k].addr >= cur && 
                bp_tbl[k].addr < cur + fetched)
                buf[bp_tbl[k].addr - cur] = bp_tbl[k].orig_byte;
        }

        cs_insn *insn;
        size_t n = cs_disasm(handle, buf, fetched, cur, 1, &insn);
        if (n == 0) {
            puts("** the address is out of the range of the executable region.");
            break;
        }

        printf("    %lx:\t", insn[0].address);

        int hexlen = 0;
        for (size_t b = 0; b < insn[0].size; ++b) {
            printf("%02x ", insn[0].bytes[b]);
            hexlen += 3;
        }
        for (int pad = BYTE_COL_WIDTH - hexlen; pad > 0; --pad)
            putchar(' ');

        printf("%-8s %s\n", insn[0].mnemonic, insn[0].op_str);
        cur  += insn[0].size;
        done += 1;
        cs_free(insn, n);
    }
    cs_close(&handle);
}

static void enable_breakpoint(bp_t *bp) {
    if (!bp || !bp->active)       
        return;
    int idx  = bp->addr & 0x7;
    long word = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)(bp->addr - idx), NULL);
    unsigned char *bytes = (unsigned char *)&word;
    bytes[idx] = 0xCC;                             
    ptrace(PTRACE_POKETEXT, child_pid, (void *)(bp->addr - idx), (void *)word);
}

static int hexpair_to_byte(char hi, char lo, unsigned char *out) {
    int h = isdigit(hi) ? hi - '0' : tolower(hi) - 'a' + 10;
    int l = isdigit(lo) ? lo - '0' : tolower(lo) - 'a' + 10;
    if (h < 0 || h > 15 || l < 0 || l > 15) return 0;
    *out = (h << 4) | l;
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc > 1) cmd_load(argv[1]);
    printf("(sdb) ");
    while (fgets(input, sizeof(input), stdin)) {
        handle_command();
        if (is_terminated)
            break;
        printf("(sdb) ");
    }
    return 0;
}