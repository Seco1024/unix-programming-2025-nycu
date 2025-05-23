#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <elf.h>
#include <signal.h>
#include <capstone/capstone.h>

#define MAX_LINE 256
#define BYTE_COL_WIDTH 24
#define MAX_BP  128     

typedef struct {
    int id;
    unsigned long addr;
    unsigned char    orig_byte;
    int              active; 
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

enum cmd_id {
    CMD_LOAD,
    CMD_SI,
    CMD_CONT,
    CMD_INFO,
    CMD_BREAK,
    CMD_BREAKRVA,
    CMD_DELETE,
    CMD_PATCH,
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
unsigned long get_entry_offset(const char *path);
unsigned long get_base_address(pid_t pid);
enum cmd_id lookup_cmd(char *cmd);
void disassemble_at(pid_t pid, unsigned long addr, int count);
static int addr_is_executable(unsigned long addr);
static int parse_u64(const char *s, unsigned long *out);
static bp_t *find_bp_by_addr(unsigned long addr);
static int hexpair_to_byte(char hi, char lo, unsigned char *out);
static void enable_breakpoint(bp_t *bp);

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
        default:
            printf("** unknown command '%s'\n", raw);
    }
}

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
    return CMD_UNKNOWN;
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

static int parse_u64(const char *s, unsigned long *out)
{
    if (!s || !*s) return 0;
    if (!strncmp(s, "0x", 2) || !strncmp(s, "0X", 2))
        s += 2;

    char *end;
    unsigned long val = strtoul(s, &end, 16);   /* 固定 base 16 */
    if (*end) return 0;                         /* 出現非十六進位字元 */

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

    base_addr = get_base_address(pid);
    entry_point = base_addr + entry_offset;
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

void cmd_breakrva(const char *off_str)
{
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
    for (size_t i = 0; i < hlen; i += 2)
        if (!hexpair_to_byte(hex[i], hex[i + 1], &bytes[i / 2])) {
            puts("** the target address is not valid."); 
            return;
        }
    size_t n = hlen / 2;

    for (size_t o = 0; o < n; o++)
        if (!addr_is_executable(addr + o)) {
            puts("** the target address is not valid."); return;
        }

    for (int i = 0; i < bp_cnt; i++) {
        if (!bp_tbl[i].active) 
            continue;
        unsigned long bp_addr = bp_tbl[i].addr;
        if (bp_addr >= addr && bp_addr < addr + n)
            bp_tbl[i].orig_byte = bytes[bp_addr - addr];
    }

    size_t off = 0;
    while (off < n) {
        unsigned long cur  = addr + off;
        int idx = cur & 0x7;                   
        long word = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)(cur - idx), NULL);
        if (word == -1 && errno) { 
            perror("PTRACE_PEEKTEXT"); 
            return; 
        }

        size_t span = sizeof(long) - idx;                 
        if (span > n - off) 
            span = n - off;
        memcpy(((unsigned char *)&word) + idx, bytes + off, span);

        if (ptrace(PTRACE_POKETEXT, child_pid, (void *)(cur - idx), (void *)word) < 0) {
            perror("PTRACE_POKETEXT"); return;
        }
        off += span;
    }
    printf("** patch memory at 0x%lx.\n", addr);
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

unsigned long get_base_address(pid_t pid) {
    char maps_path[64]; 
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r"); if (!f) { 
        perror("fopen maps"); 
        return 0; 
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end, offset, inode;
        char perms[5], dev[6];
        if (sscanf(line, "%lx-%lx %4s %lx %5s %lu", &start, &end, perms, &offset, dev, &inode) == 6) {
            if (strchr(perms, 'x') && offset == 0) { 
                fclose(f); 
                return (ehdr.e_type == ET_DYN) ? start : 0; 
            }
        }
    }
    fclose(f);
    return 0;
}

void disassemble_at(pid_t pid, unsigned long addr, int count) {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) 
        return;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

    unsigned char buf[16];
    size_t offset = 0;

    for (int i = 0; i < count; i++) {
        long data = ptrace(PTRACE_PEEKTEXT, pid, addr + offset, NULL);
        if (data == -1 && errno) { 
            perror("ptrace PEEKTEXT"); 
            break; 
        }

        memcpy(buf, &data, sizeof(data));

        // Replace int3 breakpoint with origin text
        unsigned long word_start = addr + offset;
        for (int j = 0; j < bp_cnt; j++) {
            if (!bp_tbl[j].active) continue;
            unsigned long bp_addr = bp_tbl[j].addr;
            if (bp_addr >= word_start && bp_addr < word_start + sizeof(long)) {
                size_t idx = bp_addr - word_start;     
                buf[idx] = bp_tbl[j].orig_byte;       
            }
        }

        cs_insn *insn;
        size_t insn_count = cs_disasm(handle, buf, sizeof(buf), addr + offset, 1, &insn);
        if (!insn_count) break;

        printf("    %lx:\t", insn[0].address);
        int byte_len = 0;
        for (int b = 0; b < insn[0].size; b++) {
            printf("%02x ", insn[0].bytes[b]); byte_len += 3;
        }
        int pad = BYTE_COL_WIDTH - byte_len; if (pad < 1) pad = 1;
        while (pad--) putchar(' ');
        printf("%-8s %s\n", insn[0].mnemonic, insn[0].op_str);

        offset += insn[0].size;
        cs_free(insn, insn_count);
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