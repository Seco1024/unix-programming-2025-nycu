#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t, int64_t);

static syscall_hook_fn_t real_syscall = NULL;   


static void escape_bytes(char *dst, size_t dst_sz,
                         const unsigned char *src, size_t n)
{
    size_t out = 0;
    for (size_t i = 0; i < n && out + 4 < dst_sz; ++i) {
        unsigned c = src[i];
        if (c == '\n')      { dst[out++] = '\\'; dst[out++] = 'n';  }
        else if (c == '\r') { dst[out++] = '\\'; dst[out++] = 'r';  }
        else if (c == '\t') { dst[out++] = '\\'; dst[out++] = 't';  }
        else if (c == '\"' || c == '\\') {
            dst[out++] = '\\'; dst[out++] = (char)c;
        }
        else if (c >= 0x20 && c <= 0x7e) { dst[out++] = (char)c; }
        else {
            snprintf(dst + out, 5, "\\x%02x", c);
            out += 4;
        }
    }
    dst[out] = '\0';
}

static void format_sockaddr(char *out, size_t sz,
                            const struct sockaddr *sa, socklen_t len)
{
    if (!sa || len == 0) {
        snprintf(out, sz, "-");
        return;
    }

    if (sa->sa_family == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)sa;
        size_t maxpath = len - offsetof(struct sockaddr_un, sun_path);
        size_t pathlen = strnlen(un->sun_path, maxpath);
        if (pathlen > 0) {
            snprintf(out, sz, "UNIX:%.*s", (int)pathlen, un->sun_path);
        }
        else {
            snprintf(out, sz, "UNIX:(null)");
        }
        return;
    }
    else if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
        snprintf(out, sz, "%s:%u", ip, ntohs(in6->sin6_port));
    }
    else if (sa->sa_family == AF_UNIX && len >= sizeof(struct sockaddr_un)) {
        const struct sockaddr_un *un = (const struct sockaddr_un *)sa;
        snprintf(out, sz, "UNIX:%s", *un->sun_path ? un->sun_path : "(null)");
    }
    else snprintf(out, sz, "-");
}


static int64_t hook(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8,  int64_t r9, int64_t rax)
{

    switch (rax) {
    case SYS_execve: {
        const char *file = (const char *)rdi;
        fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n",
                file ? file : "(null)", (void *)rsi, (void *)rdx);
        return real_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    }

    case SYS_openat: {
        int          dirfd = (int)rdi;
        const char  *path  = (const char *)rsi;
        int          flags = (int)rdx;
        mode_t       mode  = (mode_t)r10;

        int64_t ret =
            real_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

        fprintf(stderr,
                "[logger] openat(%s, \"%s\", 0x%x, %#o) = %ld\n",
                (dirfd == AT_FDCWD ? "AT_FDCWD" : ({ char b[32]; snprintf(b,32,"%d",dirfd); b; })),
                path ? path : "(null)", flags, mode, ret);
        return ret;
    }

    case SYS_read: {
        int    fd    = (int)rdi;
        void  *buf   = (void *)rsi;
        size_t count = (size_t)rdx;

        int64_t ret = real_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

        size_t to_dump = (ret > 0) ? (ret < 32 ? (size_t)ret : 32) : 0;
        char escaped[32 * 4 + 1];
        if (to_dump)
            escape_bytes(escaped, sizeof(escaped), buf, to_dump);
        else
            escaped[0] = '\0';

        fprintf(stderr,
                "[logger] read(%d, \"%s\"%s, %zu) = %ld\n",
                fd, escaped, (ret > 32 ? "..." : ""), count, ret);
        return ret;
    }

    case SYS_write: {
        int    fd    = (int)rdi;
        const void *buf   = (const void *)rsi;
        size_t count = (size_t)rdx;

        size_t to_dump = (count < 32 ? count : 32);
        char   escaped[32 * 4 + 1];
        if (to_dump)
            escape_bytes(escaped, sizeof(escaped), buf, to_dump);
        else
            escaped[0] = '\0';

        int64_t ret = real_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

        fprintf(stderr,
                "[logger] write(%d, \"%s\"%s, %zu) = %ld\n",
                fd, escaped, (count > 32 ? "..." : ""), count, ret);
        return ret;
    }

    case SYS_connect: {
        int                     fd      = (int)rdi;
        const struct sockaddr  *sa      = (const struct sockaddr *)rsi;
        socklen_t               addrlen = (socklen_t)rdx;

        int64_t ret = real_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

        char addrbuf[128];
        format_sockaddr(addrbuf, sizeof(addrbuf), sa, addrlen);

        fprintf(stderr,
                "[logger] connect(%d, \"%s\", %u) = %ld\n",
                fd, addrbuf, (unsigned)addrlen, ret);
        return ret;
    }

    default:
        return real_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    }
}


void __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall)
{
    real_syscall   = trigger_syscall;
    *hooked_syscall = hook;
}
