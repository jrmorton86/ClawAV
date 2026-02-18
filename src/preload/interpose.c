/*
 * libclawtower.so — LD_PRELOAD syscall interception for ClawAV
 *
 * Intercepts execve, open, openat, connect and checks against a cached
 * JSON policy loaded once at library init.  Denied calls return -1/EACCES.
 *
 * Build: gcc -shared -fPIC -o libclawtower.so src/preload/interpose.c -ldl
 */

#define _GNU_SOURCE

/* Suppress -Wnonnull-compare: we interpose libc functions whose headers mark
   params as __attribute__((nonnull)), but callers CAN pass NULL in practice
   (e.g. buggy programs, fuzz inputs).  Our null checks are intentional
   defense-in-depth and must not be optimized away. */
#pragma GCC diagnostic ignored "-Wnonnull-compare"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ── Policy config ─────────────────────────────────────────────────────── */

#define POLICY_PATH      "/etc/clawav/preload-policy.json"
#define MAX_RULES        64
#define MAX_RULE_LEN     256
#define MAX_LOG_PATH     256

static int   g_enabled = 0;
static char  g_log_file[MAX_LOG_PATH] = "/var/log/clawav/preload.log";

static char  g_deny_exec[MAX_RULES][MAX_RULE_LEN];
static int   g_deny_exec_count = 0;

static char  g_deny_paths_write[MAX_RULES][MAX_RULE_LEN];
static int   g_deny_paths_write_count = 0;

static char  g_deny_connect[MAX_RULES][MAX_RULE_LEN];
static int   g_deny_connect_count = 0;

/* ── Real libc function pointers ───────────────────────────────────────── */

typedef int  (*real_execve_t)(const char *, char *const[], char *const[]);
typedef int  (*real_open_t)(const char *, int, ...);
typedef int  (*real_openat_t)(int, const char *, int, ...);
typedef int  (*real_connect_t)(int, const struct sockaddr *, socklen_t);

static real_execve_t   real_execve   = NULL;
static real_open_t     real_open     = NULL;
static real_openat_t   real_openat   = NULL;
static real_connect_t  real_connect  = NULL;

/* ── Logging ───────────────────────────────────────────────────────────── */

static void claw_log(const char *action, const char *detail) {
    /* Open/append/close each time — simple, no fd leak, low frequency for denied ops */
    FILE *f = fopen(g_log_file, "a");
    if (!f) return;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s %s\n",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            action, detail);
    fclose(f);
}

/* ── Minimal JSON parser (static buffers only) ─────────────────────────── */

/* Extract a JSON string array into dest[][MAX_RULE_LEN], return count */
static int parse_string_array(const char *json, const char *key, char dest[][MAX_RULE_LEN], int max) {
    char search[MAX_RULE_LEN];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *pos = strstr(json, search);
    if (!pos) return 0;

    pos = strchr(pos, '[');
    if (!pos) return 0;
    pos++; /* skip '[' */

    int count = 0;
    while (count < max) {
        const char *q1 = strchr(pos, '"');
        if (!q1 || *q1 == ']') break;
        /* check if we hit ']' before next '"' */
        const char *bracket = strchr(pos, ']');
        if (bracket && bracket < q1) break;

        q1++; /* start of string content */
        const char *q2 = strchr(q1, '"');
        if (!q2) break;

        size_t len = (size_t)(q2 - q1);
        if (len >= MAX_RULE_LEN) len = MAX_RULE_LEN - 1;
        memcpy(dest[count], q1, len);
        dest[count][len] = '\0';
        count++;
        pos = q2 + 1;
    }
    return count;
}

/* Extract a simple JSON string value */
static int parse_string_value(const char *json, const char *key, char *dest, int max) {
    char search[MAX_RULE_LEN];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *pos = strstr(json, search);
    if (!pos) return 0;

    pos = strchr(pos + strlen(search), ':');
    if (!pos) return 0;
    pos++;

    const char *q1 = strchr(pos, '"');
    if (!q1) return 0;
    q1++;
    const char *q2 = strchr(q1, '"');
    if (!q2) return 0;

    size_t len = (size_t)(q2 - q1);
    if ((int)len >= max) len = max - 1;
    memcpy(dest, q1, len);
    dest[len] = '\0';
    return 1;
}

static int parse_bool_value(const char *json, const char *key) {
    char search[MAX_RULE_LEN];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *pos = strstr(json, search);
    if (!pos) return 0;

    pos = strchr(pos + strlen(search), ':');
    if (!pos) return 0;

    /* skip whitespace */
    while (*pos == ':' || *pos == ' ' || *pos == '\t') pos++;
    return (strncmp(pos, "true", 4) == 0) ? 1 : 0;
}

/* ── Constructor: load policy once ─────────────────────────────────────── */

__attribute__((constructor))
static void clawtower_init(void) {
    /* Resolve real functions */
    real_execve  = (real_execve_t)dlsym(RTLD_NEXT, "execve");
    real_open    = (real_open_t)dlsym(RTLD_NEXT, "open");
    real_openat  = (real_openat_t)dlsym(RTLD_NEXT, "openat");
    real_connect = (real_connect_t)dlsym(RTLD_NEXT, "connect");

    /* Read policy file */
    FILE *f = fopen(POLICY_PATH, "r");
    if (!f) {
        /* No policy = passthrough mode */
        g_enabled = 0;
        return;
    }

    /* Read entire file (policy should be small) */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0 || sz > 65536) {
        fclose(f);
        return;
    }
    fseek(f, 0, SEEK_SET);

    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return; }

    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    buf[rd] = '\0';

    /* Parse fields */
    g_enabled = parse_bool_value(buf, "enabled");
    parse_string_value(buf, "log_file", g_log_file, MAX_LOG_PATH);
    g_deny_exec_count = parse_string_array(buf, "deny_exec", g_deny_exec, MAX_RULES);
    g_deny_paths_write_count = parse_string_array(buf, "deny_paths_write", g_deny_paths_write, MAX_RULES);
    g_deny_connect_count = parse_string_array(buf, "deny_connect", g_deny_connect, MAX_RULES);

    free(buf);
}

/* ── Interposed functions ──────────────────────────────────────────────── */

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (g_enabled && pathname) {
        /* Build a simple command string for matching */
        /* Check if the binary basename + first arg matches any deny_exec pattern */
        const char *base = strrchr(pathname, '/');
        base = base ? base + 1 : pathname;

        for (int i = 0; i < g_deny_exec_count; i++) {
            /* Pattern like "bash -c": check basename matches first word, argv[1] matches rest */
            char pat[MAX_RULE_LEN];
            strncpy(pat, g_deny_exec[i], MAX_RULE_LEN - 1);
            pat[MAX_RULE_LEN - 1] = '\0';

            char *space = strchr(pat, ' ');
            if (space) {
                *space = '\0';
                const char *arg_pat = space + 1;
                if (strcmp(base, pat) == 0 && argv && argv[0] && argv[1] &&
                    strcmp(argv[1], arg_pat) == 0) {
                    char detail[512];
                    snprintf(detail, sizeof(detail), "exec: %s %s", pathname,
                             argv[1] ? argv[1] : "");
                    claw_log("DENIED", detail);
                    errno = EACCES;
                    return -1;
                }
            } else {
                /* Simple basename match */
                if (strcmp(base, pat) == 0) {
                    char detail[512];
                    snprintf(detail, sizeof(detail), "exec: %s", pathname);
                    claw_log("DENIED", detail);
                    errno = EACCES;
                    return -1;
                }
            }
        }
    }

    return real_execve(pathname, argv, envp);
}

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    if (g_enabled && pathname && (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))) {
        for (int i = 0; i < g_deny_paths_write_count; i++) {
            /* Prefix match: deny if path starts with the deny pattern */
            size_t dlen = strlen(g_deny_paths_write[i]);
            if (strncmp(pathname, g_deny_paths_write[i], dlen) == 0) {
                /* Exact match or path continues with '/' */
                if (pathname[dlen] == '\0' || pathname[dlen] == '/') {
                    char detail[512];
                    snprintf(detail, sizeof(detail), "open(write): %s", pathname);
                    claw_log("DENIED", detail);
                    errno = EACCES;
                    return -1;
                }
            }
        }
    }

    return real_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    if (g_enabled && pathname && (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))) {
        const char *check_path = pathname;
        char resolved[PATH_MAX];

        if (pathname[0] != '/') {
            /* Relative path — resolve to absolute for policy checking */
            char dir_buf[PATH_MAX];
            int resolved_ok = 0;

            if (dirfd == AT_FDCWD) {
                if (getcwd(dir_buf, sizeof(dir_buf)) != NULL) {
                    snprintf(resolved, PATH_MAX, "%s/%s", dir_buf, pathname);
                    check_path = resolved;
                    resolved_ok = 1;
                }
            } else {
                /* Real fd — read /proc/self/fd/{dirfd} to get directory path */
                char proc_path[64];
                snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dirfd);
                ssize_t len = readlink(proc_path, dir_buf, PATH_MAX - 1);
                if (len > 0) {
                    dir_buf[len] = '\0';
                    snprintf(resolved, PATH_MAX, "%s/%s", dir_buf, pathname);
                    check_path = resolved;
                    resolved_ok = 1;
                }
            }

            if (!resolved_ok) {
                /* Fail-closed: cannot resolve path, deny access */
                char detail[512];
                snprintf(detail, sizeof(detail), "openat(write): DENIED unresolvable relative path: %s", pathname);
                claw_log("DENIED", detail);
                errno = EACCES;
                return -1;
            }
        }

        for (int i = 0; i < g_deny_paths_write_count; i++) {
            size_t dlen = strlen(g_deny_paths_write[i]);
            if (strncmp(check_path, g_deny_paths_write[i], dlen) == 0) {
                if (check_path[dlen] == '\0' || check_path[dlen] == '/') {
                    char detail[512];
                    snprintf(detail, sizeof(detail), "openat(write): %s", check_path);
                    claw_log("DENIED", detail);
                    errno = EACCES;
                    return -1;
                }
            }
        }
    }

    return real_openat(dirfd, pathname, flags, mode);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (g_enabled && g_deny_connect_count > 0 && addr) {
        char addrstr[128] = {0};

        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)addr;
            snprintf(addrstr, sizeof(addrstr), "%s:%d",
                     inet_ntoa(in->sin_addr), ntohs(in->sin_port));
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
            char ip6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &in6->sin6_addr, ip6, sizeof(ip6));
            snprintf(addrstr, sizeof(addrstr), "[%s]:%d", ip6, ntohs(in6->sin6_port));
        }

        if (addrstr[0]) {
            for (int i = 0; i < g_deny_connect_count; i++) {
                if (strstr(addrstr, g_deny_connect[i])) {
                    char detail[512];
                    snprintf(detail, sizeof(detail), "connect: %s", addrstr);
                    claw_log("DENIED", detail);
                    errno = EACCES;
                    return -1;
                }
            }
        }
    }

    return real_connect(sockfd, addr, addrlen);
}
