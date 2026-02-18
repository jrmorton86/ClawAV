/*
 * libclawtower.so v2 — Predictive Behavioral LD_PRELOAD Engine
 *
 * Replaces the static deny-list approach with:
 *   - Ring buffer behavioral tracking
 *   - Threat scoring with decay
 *   - Sequence pattern matching (attack detection)
 *   - Sensitive fd tracking
 *   - Shannon entropy detection on socket writes
 *   - Frequency anomaly detection (openat bursts)
 *   - Shared memory event bus to sentinel
 *   - Hot-reload policy via shared memory version flag
 *
 * Build: gcc -shared -fPIC -o libclawtower.so src/preload/interpose_v2.c -ldl -lpthread -lm
 * No heap allocation. All static buffers.
 *
 * (c) 2026 ClawTower / ClawTower
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>

/* aarch64 doesn't have some legacy syscall numbers */
#ifndef __NR_open
#define __NR_open 0x1000
#endif
#ifndef __NR_dup2
#define __NR_dup2 0x1001
#endif

/* ══════════════════════════════════════════════════════════════════════════
 * Constants & Categories
 * ══════════════════════════════════════════════════════════════════════════ */

#define RING_SIZE             256
#define SENSITIVE_FD_MAX      128
#define SENSITIVE_PATH_MAX    64
#define SHM_EVENT_QUEUE_SIZE  1024
#define POLICY_CHECK_INTERVAL 1000
#define FREQ_WINDOW_NS        1000000000ULL  /* 1 second */
#define FREQ_THRESHOLD        50
#define ENTROPY_THRESHOLD     7.0
#define SCORE_DECAY_PER_SEC   50
#define MAX_PATH_LEN          256

/* Threat levels */
#define THREAT_NORMAL    0
#define THREAT_ELEVATED  1
#define THREAT_CRITICAL  2
#define THREAT_LOCKDOWN  3

/* Categories */
#define CAT_NONE              0
#define CAT_READ_SENSITIVE    1
#define CAT_READ_AUTH         2
#define CAT_NET_CONNECT       3
#define CAT_NET_WRITE         4
#define CAT_EXEC              5
#define CAT_EXEC_NETWORK_TOOL 6
#define CAT_EXEC_SHELL        7
#define CAT_EXEC_SUDO         8
#define CAT_MMAP_RW           9
#define CAT_MPROTECT_EXEC    10
#define CAT_DLOPEN            11
#define CAT_DLSYM             12
#define CAT_WRITE_PERSISTENCE 13
#define CAT_CHMOD_EXEC        14
#define CAT_READ_PRIVESC      15
#define CAT_WRITE_SHLIB       16
#define CAT_FD_DUP            17
#define CAT_OPEN_SENSITIVE    18
#define CAT_OPEN_WRITE_ETC    19
#define CAT_ENTROPY_WRITE     20
#define CAT_FREQ_BURST        21
#define CAT_OPEN_GENERAL      22

/* Actions from pattern match */
#define ACTION_BOOST     0
#define ACTION_CRITICAL  1
#define ACTION_LOCKDOWN  2

/* Shared memory commands */
#define CMD_NONE            0
#define CMD_LOCKDOWN        1
#define CMD_RELEASE         2
#define CMD_RELOAD_POLICY   3
#define CMD_FORCE_THREAT    4

#define SHM_NAME "/clawtower_shm"
#define SHM_MAGIC 0x434C4157  /* "CLAW" */

/* ══════════════════════════════════════════════════════════════════════════
 * Data Structures
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t syscall_nr;
    uint32_t flags;
    uint64_t timestamp_ns;
    uint64_t path_hash;
    uint16_t threat_score;
    uint16_t category;
} syscall_event_t;

typedef struct {
    syscall_event_t events[RING_SIZE];
    _Atomic uint32_t head;
    uint32_t total_count;
    uint16_t threat_level;     /* accumulated score */
    uint16_t alert_state;      /* THREAT_NORMAL..THREAT_LOCKDOWN */
    uint64_t last_decay_ns;    /* last time we applied decay */
} __attribute__((aligned(64))) ring_buffer_t;

/* Sensitive fd tracking */
typedef struct {
    int      fd;
    uint16_t category;    /* CAT_READ_SENSITIVE or CAT_READ_AUTH */
    uint16_t base_score;
    uint64_t path_hash;
} sensitive_fd_entry_t;

/* Socket fd tracking */
typedef struct {
    int fd;
    int active;
} socket_fd_entry_t;

/* Attack pattern */
typedef struct {
    uint16_t steps[8];
    uint16_t max_window_ms;
    uint16_t threat_boost;
    uint8_t  step_count;
    uint8_t  action;
} attack_pattern_t;

/* Shared memory layout */
typedef struct {
    uint32_t magic;
    uint32_t version;

    /* libclawtower → sentinel */
    syscall_event_t event_queue[SHM_EVENT_QUEUE_SIZE];
    _Atomic uint32_t event_head;
    _Atomic uint32_t event_tail;

    /* sentinel → libclawtower */
    _Atomic uint32_t command;
    _Atomic uint32_t policy_version;
    _Atomic uint16_t forced_threat_level;

    /* stats */
    _Atomic uint64_t total_syscalls;
    _Atomic uint64_t total_denied;
    _Atomic uint64_t total_elevated;
} shared_state_t;

/* Frequency tracking for openat burst detection */
typedef struct {
    uint64_t timestamps[FREQ_THRESHOLD + 10];
    uint32_t head;
    uint32_t count;
} freq_tracker_t;

/* ══════════════════════════════════════════════════════════════════════════
 * Global State (all static, no heap)
 * ══════════════════════════════════════════════════════════════════════════ */

static ring_buffer_t g_ring __attribute__((aligned(64)));

static sensitive_fd_entry_t g_sensitive_fds[SENSITIVE_FD_MAX];
static int g_sensitive_fd_count = 0;

#define SOCKET_FD_MAX 64
static socket_fd_entry_t g_socket_fds[SOCKET_FD_MAX];

static shared_state_t *g_shm = NULL;
static uint32_t g_current_policy_version = 0;
static uint32_t g_syscall_counter = 0;

static freq_tracker_t g_openat_freq;

static int g_initialized = 0;

/* Sensitive path prefixes for read monitoring */
static const char *SENSITIVE_PATHS[] = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    NULL
};
static const uint16_t SENSITIVE_SCORES[] = { 200, 100, 200 };
static const uint16_t SENSITIVE_CATS[] = { CAT_READ_AUTH, CAT_READ_SENSITIVE, CAT_READ_PRIVESC };

/* Home-relative sensitive paths (checked with $HOME prefix) */
static const char *HOME_SENSITIVE[] = {
    "/.ssh/",
    "/.aws/",
    "/.openclaw/",
    NULL
};
static const uint16_t HOME_SCORES[] = { 300, 300, 150 };
static const uint16_t HOME_CATS[] = { CAT_READ_AUTH, CAT_READ_AUTH, CAT_READ_SENSITIVE };

static char g_home_dir[MAX_PATH_LEN] = "";

/* Network tool basenames */
static const char *NETWORK_TOOLS[] = { "curl", "wget", "nc", "ncat", "socat", NULL };
static const char *SHELL_TOOLS[] = { "sh", "bash", "dash", "zsh", "fish", NULL };

/* Attack patterns — from design doc §4.4 */
static const attack_pattern_t PATTERNS[] = {
    /* Data exfiltration: read sensitive → connect → write to socket */
    { .steps = {CAT_READ_SENSITIVE, CAT_NET_CONNECT, CAT_NET_WRITE},
      .step_count = 3, .max_window_ms = 10000,
      .threat_boost = 500, .action = ACTION_LOCKDOWN },

    /* Credential theft: read auth → exec network tool */
    { .steps = {CAT_READ_AUTH, CAT_EXEC_NETWORK_TOOL},
      .step_count = 2, .max_window_ms = 30000,
      .threat_boost = 600, .action = ACTION_LOCKDOWN },

    /* Reverse shell: connect → dup2 → exec shell */
    { .steps = {CAT_NET_CONNECT, CAT_FD_DUP, CAT_EXEC_SHELL},
      .step_count = 3, .max_window_ms = 5000,
      .threat_boost = 900, .action = ACTION_LOCKDOWN },

    /* Shellcode injection: mmap(RW) → mprotect(RX) */
    { .steps = {CAT_MMAP_RW, CAT_MPROTECT_EXEC},
      .step_count = 2, .max_window_ms = 1000,
      .threat_boost = 900, .action = ACTION_LOCKDOWN },

    /* Persistence: write cron/systemd → chmod +x */
    { .steps = {CAT_WRITE_PERSISTENCE, CAT_CHMOD_EXEC},
      .step_count = 2, .max_window_ms = 60000,
      .threat_boost = 700, .action = ACTION_CRITICAL },

    /* Privilege escalation: read sudoers → exec sudo */
    { .steps = {CAT_READ_PRIVESC, CAT_EXEC_SUDO},
      .step_count = 2, .max_window_ms = 30000,
      .threat_boost = 500, .action = ACTION_CRITICAL },

    /* Library injection: write .so → dlopen */
    { .steps = {CAT_WRITE_SHLIB, CAT_DLOPEN},
      .step_count = 2, .max_window_ms = 5000,
      .threat_boost = 800, .action = ACTION_LOCKDOWN },
};
#define PATTERN_COUNT (sizeof(PATTERNS) / sizeof(PATTERNS[0]))

/* ── Real libc function pointers ──────────────────────────────────────── */

typedef int       (*real_execve_t)(const char *, char *const[], char *const[]);
typedef int       (*real_open_t)(const char *, int, ...);
typedef int       (*real_openat_t)(int, const char *, int, ...);
typedef int       (*real_connect_t)(int, const struct sockaddr *, socklen_t);
typedef ssize_t   (*real_read_t)(int, void *, size_t);
typedef ssize_t   (*real_pread_t)(int, void *, size_t, off_t);
typedef ssize_t   (*real_readv_t)(int, const struct iovec *, int);
typedef ssize_t   (*real_write_t)(int, const void *, size_t);
typedef void     *(*real_mmap_t)(void *, size_t, int, int, int, off_t);
typedef int       (*real_mprotect_t)(void *, size_t, int);
typedef void     *(*real_dlopen_t)(const char *, int);
typedef void     *(*real_dlsym_t)(void *, const char *);
typedef int       (*real_close_t)(int);
typedef int       (*real_dup2_t)(int, int);
typedef int       (*real_socket_t)(int, int, int);

static real_execve_t   real_execve_fn   = NULL;
static real_open_t     real_open_fn     = NULL;
static real_openat_t   real_openat_fn   = NULL;
static real_connect_t  real_connect_fn  = NULL;
static real_read_t     real_read_fn     = NULL;
static real_pread_t    real_pread_fn    = NULL;
static real_readv_t    real_readv_fn    = NULL;
static real_write_t    real_write_fn    = NULL;
static real_mmap_t     real_mmap_fn     = NULL;
static real_mprotect_t real_mprotect_fn = NULL;
static real_dlopen_t   real_dlopen_fn   = NULL;
/* dlsym is intentionally NOT hooked — see comment in dlopen section */
static real_close_t    real_close_fn    = NULL;
static real_dup2_t     real_dup2_fn     = NULL;
static real_socket_t   real_socket_fn   = NULL;

/* Recursion guard (thread-local) */
static __thread int g_in_hook = 0;

/* Bootstrap: during init, dlsym may call our hooked functions.
 * We need raw syscall fallbacks for that period. */
#include <linux/unistd.h>

static inline int raw_open(const char *path, int flags, int mode) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, mode);
}

static inline ssize_t raw_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

static inline ssize_t raw_write(int fd, const void *buf, size_t count) {
    return syscall(__NR_write, fd, buf, count);
}

static inline int raw_close(int fd) {
    return (int)syscall(__NR_close, fd);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Utility Functions
 * ══════════════════════════════════════════════════════════════════════════ */

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* FNV-1a 64-bit hash */
static inline uint64_t fnv1a_hash(const char *str) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    if (!str) return hash;
    while (*str) {
        hash ^= (uint64_t)(unsigned char)*str++;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static inline const char *basename_of(const char *path) {
    if (!path) return "";
    const char *b = strrchr(path, '/');
    return b ? b + 1 : path;
}

static inline int str_in_list(const char *s, const char **list) {
    for (int i = 0; list[i]; i++) {
        if (strcmp(s, list[i]) == 0) return 1;
    }
    return 0;
}

static inline int str_starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Ring Buffer
 * ══════════════════════════════════════════════════════════════════════════ */

static void apply_decay(uint64_t now) {
    if (g_ring.last_decay_ns == 0) {
        g_ring.last_decay_ns = now;
        return;
    }
    uint64_t elapsed_ns = now - g_ring.last_decay_ns;
    if (elapsed_ns < 20000000ULL) return;  /* don't decay more than 50x/s */

    uint64_t decay = (elapsed_ns / 1000000000ULL) * SCORE_DECAY_PER_SEC;
    /* Also fractional decay */
    uint64_t frac_ns = elapsed_ns % 1000000000ULL;
    decay += (frac_ns * SCORE_DECAY_PER_SEC) / 1000000000ULL;

    if (decay > 0) {
        if (g_ring.threat_level > (uint16_t)decay)
            g_ring.threat_level -= (uint16_t)decay;
        else
            g_ring.threat_level = 0;
        g_ring.last_decay_ns = now;
    }
}

static inline uint16_t get_alert_state(uint16_t score) {
    if (score >= 900) return THREAT_LOCKDOWN;
    if (score >= 600) return THREAT_CRITICAL;
    if (score >= 300) return THREAT_ELEVATED;
    return THREAT_NORMAL;
}

static void ring_push(uint32_t syscall_nr, uint32_t flags, uint64_t ts,
                       uint64_t path_hash, uint16_t score, uint16_t category) {
    uint32_t idx = atomic_fetch_add(&g_ring.head, 1) % RING_SIZE;

    g_ring.events[idx].syscall_nr    = syscall_nr;
    g_ring.events[idx].flags         = flags;
    g_ring.events[idx].timestamp_ns  = ts;
    g_ring.events[idx].path_hash     = path_hash;
    g_ring.events[idx].threat_score  = score;
    g_ring.events[idx].category      = category;

    g_ring.total_count++;

    /* Apply decay then add score */
    apply_decay(ts);
    uint32_t new_level = (uint32_t)g_ring.threat_level + score;
    if (new_level > 1000) new_level = 1000;
    g_ring.threat_level = (uint16_t)new_level;
    g_ring.alert_state = get_alert_state(g_ring.threat_level);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Shared Memory Event Bus
 * ══════════════════════════════════════════════════════════════════════════ */

static void shm_init(void) {
    int fd = shm_open(SHM_NAME, O_RDWR, 0600);
    if (fd < 0) {
        /* Try to create */
        fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0600);
        if (fd < 0) return;
        if (ftruncate(fd, sizeof(shared_state_t)) < 0) {
            close(fd);
            return;
        }
    }

    g_shm = (shared_state_t *)mmap(NULL, sizeof(shared_state_t),
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (g_shm == MAP_FAILED) {
        g_shm = NULL;
        return;
    }

    if (g_shm->magic != SHM_MAGIC) {
        memset(g_shm, 0, sizeof(shared_state_t));
        g_shm->magic = SHM_MAGIC;
        g_shm->version = 1;
    }
}

static void shm_emit_event(const syscall_event_t *evt) {
    if (!g_shm) return;

    uint32_t head = atomic_load(&g_shm->event_head);
    uint32_t tail = atomic_load(&g_shm->event_tail);

    /* Check if full */
    uint32_t next = (head + 1) % SHM_EVENT_QUEUE_SIZE;
    if (next == tail) return;  /* queue full, drop */

    g_shm->event_queue[head] = *evt;
    atomic_store(&g_shm->event_head, next);
    atomic_fetch_add(&g_shm->total_syscalls, 1);
}

static void shm_check_commands(void) {
    if (!g_shm) return;

    uint32_t cmd = atomic_exchange(&g_shm->command, CMD_NONE);
    switch (cmd) {
    case CMD_LOCKDOWN:
        g_ring.threat_level = 1000;
        g_ring.alert_state = THREAT_LOCKDOWN;
        break;
    case CMD_RELEASE:
        g_ring.threat_level = 0;
        g_ring.alert_state = THREAT_NORMAL;
        break;
    case CMD_FORCE_THREAT: {
        uint16_t forced = atomic_load(&g_shm->forced_threat_level);
        g_ring.threat_level = forced;
        g_ring.alert_state = get_alert_state(forced);
        break;
    }
    case CMD_RELOAD_POLICY:
        /* Bump check — actual reload handled by policy_version */
        break;
    default:
        break;
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * Sensitive FD Tracking
 * ══════════════════════════════════════════════════════════════════════════ */

static void track_sensitive_fd(int fd, uint16_t category, uint16_t score, uint64_t ph) {
    if (g_sensitive_fd_count >= SENSITIVE_FD_MAX) return;
    /* Check not already tracked */
    for (int i = 0; i < g_sensitive_fd_count; i++) {
        if (g_sensitive_fds[i].fd == fd) {
            g_sensitive_fds[i].category = category;
            g_sensitive_fds[i].base_score = score;
            g_sensitive_fds[i].path_hash = ph;
            return;
        }
    }
    g_sensitive_fds[g_sensitive_fd_count].fd = fd;
    g_sensitive_fds[g_sensitive_fd_count].category = category;
    g_sensitive_fds[g_sensitive_fd_count].base_score = score;
    g_sensitive_fds[g_sensitive_fd_count].path_hash = ph;
    g_sensitive_fd_count++;
}

static sensitive_fd_entry_t *find_sensitive_fd(int fd) {
    for (int i = 0; i < g_sensitive_fd_count; i++) {
        if (g_sensitive_fds[i].fd == fd) return &g_sensitive_fds[i];
    }
    return NULL;
}

static void untrack_fd(int fd) {
    for (int i = 0; i < g_sensitive_fd_count; i++) {
        if (g_sensitive_fds[i].fd == fd) {
            g_sensitive_fds[i] = g_sensitive_fds[g_sensitive_fd_count - 1];
            g_sensitive_fd_count--;
            return;
        }
    }
    /* Also remove from socket tracking */
    for (int i = 0; i < SOCKET_FD_MAX; i++) {
        if (g_socket_fds[i].fd == fd && g_socket_fds[i].active) {
            g_socket_fds[i].active = 0;
            return;
        }
    }
}

static void track_socket_fd(int fd) {
    for (int i = 0; i < SOCKET_FD_MAX; i++) {
        if (!g_socket_fds[i].active) {
            g_socket_fds[i].fd = fd;
            g_socket_fds[i].active = 1;
            return;
        }
    }
}

static int is_socket_fd(int fd) {
    for (int i = 0; i < SOCKET_FD_MAX; i++) {
        if (g_socket_fds[i].active && g_socket_fds[i].fd == fd) return 1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Path Classification
 * ══════════════════════════════════════════════════════════════════════════ */

static int classify_path(const char *path, uint16_t *out_cat, uint16_t *out_score) {
    if (!path) return 0;

    /* Check absolute sensitive paths */
    for (int i = 0; SENSITIVE_PATHS[i]; i++) {
        if (str_starts_with(path, SENSITIVE_PATHS[i])) {
            *out_cat = SENSITIVE_CATS[i];
            *out_score = SENSITIVE_SCORES[i];
            return 1;
        }
    }

    /* Check home-relative paths */
    if (g_home_dir[0] && str_starts_with(path, g_home_dir)) {
        const char *rel = path + strlen(g_home_dir);
        for (int i = 0; HOME_SENSITIVE[i]; i++) {
            if (str_starts_with(rel, HOME_SENSITIVE[i])) {
                *out_cat = HOME_CATS[i];
                *out_score = HOME_SCORES[i];
                return 1;
            }
        }
    }

    return 0;
}

static int is_persistence_path(const char *path) {
    if (!path) return 0;
    return str_starts_with(path, "/etc/cron") ||
           str_starts_with(path, "/var/spool/cron") ||
           str_starts_with(path, "/etc/systemd/") ||
           (g_home_dir[0] && str_starts_with(path, g_home_dir) &&
            (strstr(path, ".bashrc") || strstr(path, ".profile") ||
             strstr(path, ".crontab") || strstr(path, "/.config/systemd/")));
}

static int is_shlib_path(const char *path) {
    if (!path) return 0;
    size_t len = strlen(path);
    return (len > 3 && strcmp(path + len - 3, ".so") == 0) ||
           (strstr(path, ".so.") != NULL);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Frequency Detection (openat burst)
 * ══════════════════════════════════════════════════════════════════════════ */

static int freq_check_openat(uint64_t now) {
    uint32_t idx = g_openat_freq.head % (FREQ_THRESHOLD + 10);
    g_openat_freq.timestamps[idx] = now;
    g_openat_freq.head++;
    if (g_openat_freq.count < FREQ_THRESHOLD + 10)
        g_openat_freq.count++;

    if (g_openat_freq.count < FREQ_THRESHOLD) return 0;

    /* Count how many timestamps are within the last 1s */
    int recent = 0;
    for (uint32_t i = 0; i < g_openat_freq.count && i < FREQ_THRESHOLD + 10; i++) {
        if (now - g_openat_freq.timestamps[i] <= FREQ_WINDOW_NS)
            recent++;
    }
    return recent >= FREQ_THRESHOLD;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Shannon Entropy
 * ══════════════════════════════════════════════════════════════════════════ */

static double compute_entropy(const void *buf, size_t len) {
    if (len == 0) return 0.0;
    uint32_t counts[256];
    memset(counts, 0, sizeof(counts));

    const unsigned char *p = (const unsigned char *)buf;
    for (size_t i = 0; i < len; i++)
        counts[p[i]]++;

    double entropy = 0.0;
    double dlen = (double)len;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double prob = (double)counts[i] / dlen;
        entropy -= prob * log2(prob);
    }
    return entropy;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Sequence Pattern Matching
 * ══════════════════════════════════════════════════════════════════════════ */

static void check_patterns(uint64_t now) {
    uint32_t head = atomic_load(&g_ring.head);

    for (size_t p = 0; p < PATTERN_COUNT; p++) {
        const attack_pattern_t *pat = &PATTERNS[p];
        uint64_t window_ns = (uint64_t)pat->max_window_ms * 1000000ULL;

        /* Scan backward through ring buffer looking for pattern steps in order */
        int step = pat->step_count - 1;  /* start from last step */

        for (int i = 0; i < RING_SIZE && step >= 0; i++) {
            uint32_t idx = (head - 1 - i + RING_SIZE * 2) % RING_SIZE;
            syscall_event_t *evt = &g_ring.events[idx];

            if (evt->timestamp_ns == 0) break;  /* empty slot */
            if (now - evt->timestamp_ns > window_ns) break;  /* too old */

            if (evt->category == pat->steps[step]) {
                step--;
            }
        }

        if (step < 0) {
            /* Pattern matched! Apply threat boost */
            uint32_t new_level = (uint32_t)g_ring.threat_level + pat->threat_boost;
            if (new_level > 1000) new_level = 1000;
            g_ring.threat_level = (uint16_t)new_level;
            g_ring.alert_state = get_alert_state(g_ring.threat_level);

            /* Emit pattern match event to shm */
            if (g_shm) {
                syscall_event_t match_evt = {
                    .syscall_nr = 0xFFFF,  /* sentinel: pattern match */
                    .flags = (uint32_t)p,
                    .timestamp_ns = now,
                    .path_hash = 0,
                    .threat_score = pat->threat_boost,
                    .category = pat->steps[0],
                };
                shm_emit_event(&match_evt);
            }
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * Hot-Reload Check
 * ══════════════════════════════════════════════════════════════════════════ */

static void maybe_reload_policy(void) {
    if (++g_syscall_counter % POLICY_CHECK_INTERVAL != 0) return;
    if (!g_shm) return;

    uint32_t ver = atomic_load(&g_shm->policy_version);
    if (ver != g_current_policy_version) {
        /* In v2, policy is the sensitive path tables + patterns.
         * For now, just acknowledge the version change.
         * Full disk reload would go here. */
        g_current_policy_version = ver;
    }

    /* Also check commands */
    shm_check_commands();
}

/* ══════════════════════════════════════════════════════════════════════════
 * Core event recording + enforcement
 * ══════════════════════════════════════════════════════════════════════════ */

static int should_block(void) {
    return g_ring.alert_state >= THREAT_LOCKDOWN;
}

static void maybe_throttle(void) {
    if (g_ring.alert_state == THREAT_CRITICAL) {
        /* Insert 50ms delay */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000000 };
        nanosleep(&ts, NULL);
    }
}

static void record_and_check(uint32_t nr, uint32_t flags, uint64_t path_hash,
                              uint16_t score, uint16_t category) {
    uint64_t ts = now_ns();
    ring_push(nr, flags, ts, path_hash, score, category);

    /* Pattern matching */
    check_patterns(ts);

    /* Emit to shared memory if elevated+ */
    if (g_ring.alert_state >= THREAT_ELEVATED && g_shm) {
        syscall_event_t evt = {
            .syscall_nr = nr,
            .flags = flags,
            .timestamp_ns = ts,
            .path_hash = path_hash,
            .threat_score = score,
            .category = category,
        };
        shm_emit_event(&evt);
        atomic_fetch_add(&g_shm->total_elevated, 1);
    }

    maybe_reload_policy();
    maybe_throttle();
}

/* ══════════════════════════════════════════════════════════════════════════
 * Interposed Functions
 * ══════════════════════════════════════════════════════════════════════════ */

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    if (!g_initialized || g_in_hook) {
        if (real_open_fn) return real_open_fn(pathname, flags, mode);
        return raw_open(pathname, flags, mode);
    }

    g_in_hook = 1;

    uint16_t cat = CAT_OPEN_GENERAL, score = 0;
    uint64_t ph = fnv1a_hash(pathname);

    /* Check if opening sensitive path */
    uint16_t s_cat, s_score;
    if (classify_path(pathname, &s_cat, &s_score)) {
        cat = CAT_OPEN_SENSITIVE;
        score = 0;  /* Score applied on read, not open */
    }

    /* Check write to /etc */
    if (pathname && (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))) {
        if (str_starts_with(pathname, "/etc/")) {
            cat = CAT_OPEN_WRITE_ETC;
            score = 400;
        }
        if (is_persistence_path(pathname)) {
            cat = CAT_WRITE_PERSISTENCE;
            score = 300;
        }
        if (is_shlib_path(pathname)) {
            cat = CAT_WRITE_SHLIB;
            score = 200;
        }
    }

    record_and_check(__NR_open, flags, ph, score, cat);

    if (should_block() && score > 0) {
        g_in_hook = 0;
        errno = EACCES;
        return -1;
    }

    int fd = real_open_fn(pathname, flags, mode);

    /* Track sensitive fds */
    if (fd >= 0 && classify_path(pathname, &s_cat, &s_score)) {
        track_sensitive_fd(fd, s_cat, s_score, ph);
    }

    g_in_hook = 0;
    return fd;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | __O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    if (!g_initialized || g_in_hook) {
        if (real_openat_fn) return real_openat_fn(dirfd, pathname, flags, mode);
        return (int)syscall(__NR_openat, dirfd, pathname, flags, mode);
    }

    g_in_hook = 1;

    uint64_t ts = now_ns();
    uint64_t ph = fnv1a_hash(pathname);
    uint16_t cat = CAT_OPEN_GENERAL, score = 0;

    /* Frequency detection */
    if (freq_check_openat(ts)) {
        cat = CAT_FREQ_BURST;
        score = 300;
        ring_push(__NR_openat, flags, ts, ph, score, cat);
        check_patterns(ts);
    }

    /* Classify path */
    uint16_t s_cat, s_score;
    int is_sensitive = classify_path(pathname, &s_cat, &s_score);

    if (pathname && (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))) {
        if (pathname[0] == '/' && str_starts_with(pathname, "/etc/")) {
            cat = CAT_OPEN_WRITE_ETC;
            score = 400;
        }
        if (is_persistence_path(pathname)) {
            cat = CAT_WRITE_PERSISTENCE;
            score = 300;
        }
        if (is_shlib_path(pathname)) {
            cat = CAT_WRITE_SHLIB;
            score = 200;
        }
    }

    record_and_check(__NR_openat, flags, ph, score, cat);

    if (should_block() && score > 0) {
        g_in_hook = 0;
        errno = EACCES;
        return -1;
    }

    int fd = real_openat_fn(dirfd, pathname, flags, mode);

    if (fd >= 0 && is_sensitive) {
        track_sensitive_fd(fd, s_cat, s_score, ph);
    }

    g_in_hook = 0;
    return fd;
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!g_initialized || g_in_hook) {
        if (real_read_fn) return real_read_fn(fd, buf, count);
        return raw_read(fd, buf, count);
    }

    g_in_hook = 1;

    sensitive_fd_entry_t *sfd = find_sensitive_fd(fd);
    if (sfd) {
        record_and_check(__NR_read, 0, sfd->path_hash, sfd->base_score, sfd->category);
        if (should_block()) {
            g_in_hook = 0;
            errno = EACCES;
            return -1;
        }
    }

    ssize_t ret = real_read_fn(fd, buf, count);
    g_in_hook = 0;
    return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
    if (!g_initialized || g_in_hook)
        return real_pread_fn(fd, buf, count, offset);

    g_in_hook = 1;

    sensitive_fd_entry_t *sfd = find_sensitive_fd(fd);
    if (sfd) {
        record_and_check(__NR_pread64, 0, sfd->path_hash, sfd->base_score, sfd->category);
        if (should_block()) {
            g_in_hook = 0;
            errno = EACCES;
            return -1;
        }
    }

    ssize_t ret = real_pread_fn(fd, buf, count, offset);
    g_in_hook = 0;
    return ret;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    if (!g_initialized || g_in_hook)
        return real_readv_fn(fd, iov, iovcnt);

    g_in_hook = 1;

    sensitive_fd_entry_t *sfd = find_sensitive_fd(fd);
    if (sfd) {
        record_and_check(__NR_readv, 0, sfd->path_hash, sfd->base_score, sfd->category);
        if (should_block()) {
            g_in_hook = 0;
            errno = EACCES;
            return -1;
        }
    }

    ssize_t ret = real_readv_fn(fd, iov, iovcnt);
    g_in_hook = 0;
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!g_initialized || g_in_hook) {
        if (real_write_fn) return real_write_fn(fd, buf, count);
        return raw_write(fd, buf, count);
    }

    g_in_hook = 1;

    /* Entropy check on socket writes when elevated+ */
    if (is_socket_fd(fd) && g_ring.alert_state >= THREAT_ELEVATED && count >= 64) {
        double ent = compute_entropy(buf, count > 4096 ? 4096 : count);
        if (ent > ENTROPY_THRESHOLD) {
            record_and_check(__NR_write, 0, 0, 250, CAT_ENTROPY_WRITE);
        } else {
            record_and_check(__NR_write, 0, 0, 0, CAT_NET_WRITE);
        }
        if (should_block()) {
            g_in_hook = 0;
            errno = EACCES;
            return -1;
        }
    } else if (is_socket_fd(fd)) {
        record_and_check(__NR_write, 0, 0, 0, CAT_NET_WRITE);
    }

    ssize_t ret = real_write_fn(fd, buf, count);
    g_in_hook = 0;
    return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!g_initialized || g_in_hook)
        return real_connect_fn(sockfd, addr, addrlen);

    g_in_hook = 1;

    uint16_t score = 150;
    /* Multiplier: if recent sensitive reads in buffer */
    uint32_t head = atomic_load(&g_ring.head);
    uint64_t now = now_ns();
    for (int i = 0; i < RING_SIZE; i++) {
        uint32_t idx = (head - 1 - i + RING_SIZE * 2) % RING_SIZE;
        syscall_event_t *evt = &g_ring.events[idx];
        if (evt->timestamp_ns == 0) break;
        if (now - evt->timestamp_ns > 5000000000ULL) break;  /* 5s window */
        if (evt->category == CAT_READ_SENSITIVE || evt->category == CAT_READ_AUTH) {
            score *= 2;
            break;
        }
    }

    record_and_check(__NR_connect, 0, 0, score, CAT_NET_CONNECT);

    /* Track as socket fd */
    track_socket_fd(sockfd);

    if (should_block()) {
        g_in_hook = 0;
        errno = EACCES;
        return -1;
    }

    int ret = real_connect_fn(sockfd, addr, addrlen);
    g_in_hook = 0;
    return ret;
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (!g_initialized || g_in_hook)
        return real_execve_fn(pathname, argv, envp);

    g_in_hook = 1;

    const char *base = basename_of(pathname);
    uint64_t ph = fnv1a_hash(pathname);
    uint16_t score = 200;
    uint16_t cat = CAT_EXEC;

    if (str_in_list(base, NETWORK_TOOLS)) {
        cat = CAT_EXEC_NETWORK_TOOL;
        if (g_ring.alert_state >= THREAT_ELEVATED) score *= 3;
    } else if (str_in_list(base, SHELL_TOOLS)) {
        cat = CAT_EXEC_SHELL;
    } else if (strcmp(base, "sudo") == 0) {
        cat = CAT_EXEC_SUDO;
    } else if (!str_starts_with(pathname, "/usr/bin/") &&
               !str_starts_with(pathname, "/usr/sbin/") &&
               !str_starts_with(pathname, "/bin/") &&
               !str_starts_with(pathname, "/sbin/")) {
        score = 300;  /* Unknown binary outside standard paths */
    }

    record_and_check(__NR_execve, 0, ph, score, cat);

    if (should_block()) {
        g_in_hook = 0;
        errno = EACCES;
        return -1;
    }

    g_in_hook = 0;
    return real_execve_fn(pathname, argv, envp);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (!g_initialized || g_in_hook) {
        if (real_mmap_fn) return real_mmap_fn(addr, length, prot, flags, fd, offset);
        /* Raw mmap syscall fallback */
        return (void *)syscall(__NR_mmap, addr, length, prot, flags, fd, offset);
    }

    g_in_hook = 1;

    if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        /* RWX mapping — immediate high threat */
        record_and_check(__NR_mmap, (uint32_t)prot, 0, 500, CAT_MPROTECT_EXEC);
    } else if ((prot & PROT_WRITE) && !(prot & PROT_EXEC)) {
        /* RW mapping — potential shellcode staging */
        record_and_check(__NR_mmap, (uint32_t)prot, 0, 0, CAT_MMAP_RW);
    }

    void *ret = real_mmap_fn(addr, length, prot, flags, fd, offset);
    g_in_hook = 0;
    return ret;
}

int mprotect(void *addr, size_t len, int prot) {
    if (!g_initialized || g_in_hook) {
        if (real_mprotect_fn) return real_mprotect_fn(addr, len, prot);
        return (int)syscall(__NR_mprotect, addr, len, prot);
    }

    g_in_hook = 1;

    if (prot & PROT_EXEC) {
        record_and_check(__NR_mprotect, (uint32_t)prot, 0, 500, CAT_MPROTECT_EXEC);
        if (should_block()) {
            g_in_hook = 0;
            errno = EACCES;
            return -1;
        }
    }

    int ret = real_mprotect_fn(addr, len, prot);
    g_in_hook = 0;
    return ret;
}

/* dlopen hook — dlsym is NOT hooked to avoid infinite recursion
 * (our dlsym would intercept all dlsym calls including our own resolution). */
void *dlopen(const char *filename, int flags) {
    if (!g_initialized || g_in_hook) {
        if (real_dlopen_fn) return real_dlopen_fn(filename, flags);
        return NULL;
    }

    g_in_hook = 1;

    uint64_t ph = fnv1a_hash(filename);
    uint16_t score = 400;
    record_and_check(0xD10, (uint32_t)flags, ph, score, CAT_DLOPEN);

    if (should_block()) {
        g_in_hook = 0;
        return NULL;
    }

    void *ret = real_dlopen_fn(filename, flags);
    g_in_hook = 0;
    return ret;
}

/* Note: dlsym is intentionally NOT hooked.
 * Hooking dlsym causes infinite recursion since we use dlsym(RTLD_NEXT, ...)
 * to resolve all our real function pointers. The cost of not hooking dlsym
 * is minimal — dlopen is the high-value interception point. */

int close(int fd) {
    if (g_initialized && !g_in_hook) {
        g_in_hook = 1;
        untrack_fd(fd);
        g_in_hook = 0;
    }
    if (real_close_fn) return real_close_fn(fd);
    return raw_close(fd);
}

int dup2(int oldfd, int newfd) {
    if (!g_initialized || g_in_hook)
        return real_dup2_fn(oldfd, newfd);

    g_in_hook = 1;
    record_and_check(__NR_dup2, 0, 0, 0, CAT_FD_DUP);
    int ret = real_dup2_fn(oldfd, newfd);
    g_in_hook = 0;
    return ret;
}

int socket(int domain, int type, int protocol) {
    if (!g_initialized || g_in_hook)
        return real_socket_fn(domain, type, protocol);

    g_in_hook = 1;
    int fd = real_socket_fn(domain, type, protocol);
    if (fd >= 0) {
        track_socket_fd(fd);
    }
    g_in_hook = 0;
    return fd;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Constructor / Destructor
 * ══════════════════════════════════════════════════════════════════════════ */

__attribute__((constructor))
static void clawtower_v2_init(void) {
    g_in_hook = 1;  /* Prevent hooks from firing during init */

    /* Resolve real functions via RTLD_NEXT — must happen before g_initialized */
    real_open_fn     = (real_open_t)dlsym(RTLD_NEXT, "open");
    real_openat_fn   = (real_openat_t)dlsym(RTLD_NEXT, "openat");
    real_read_fn     = (real_read_t)dlsym(RTLD_NEXT, "read");
    real_pread_fn    = (real_pread_t)dlsym(RTLD_NEXT, "pread");
    real_readv_fn    = (real_readv_t)dlsym(RTLD_NEXT, "readv");
    real_write_fn    = (real_write_t)dlsym(RTLD_NEXT, "write");
    real_connect_fn  = (real_connect_t)dlsym(RTLD_NEXT, "connect");
    real_execve_fn   = (real_execve_t)dlsym(RTLD_NEXT, "execve");
    real_mmap_fn     = (real_mmap_t)dlsym(RTLD_NEXT, "mmap");
    real_mprotect_fn = (real_mprotect_t)dlsym(RTLD_NEXT, "mprotect");
    real_dlopen_fn   = (real_dlopen_t)dlsym(RTLD_NEXT, "dlopen");
    real_close_fn    = (real_close_t)dlsym(RTLD_NEXT, "close");
    real_dup2_fn     = (real_dup2_t)dlsym(RTLD_NEXT, "dup2");
    real_socket_fn   = (real_socket_t)dlsym(RTLD_NEXT, "socket");

    /* Initialize ring buffer */
    memset(&g_ring, 0, sizeof(g_ring));
    memset(g_sensitive_fds, 0, sizeof(g_sensitive_fds));
    memset(g_socket_fds, 0, sizeof(g_socket_fds));
    memset(&g_openat_freq, 0, sizeof(g_openat_freq));

    /* Get home dir */
    const char *home = getenv("HOME");
    if (home) {
        strncpy(g_home_dir, home, MAX_PATH_LEN - 1);
        g_home_dir[MAX_PATH_LEN - 1] = '\0';
    }

    /* Init shared memory */
    shm_init();

    g_in_hook = 0;
    g_initialized = 1;
}

__attribute__((destructor))
static void clawtower_v2_fini(void) {
    g_initialized = 0;
    if (g_shm) {
        munmap(g_shm, sizeof(shared_state_t));
        g_shm = NULL;
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * Introspection API (for test program)
 * ══════════════════════════════════════════════════════════════════════════ */

/* Export ring buffer state for testing */
uint16_t clawtower_get_threat_level(void) { return g_ring.threat_level; }
uint16_t clawtower_get_alert_state(void) { return g_ring.alert_state; }
uint32_t clawtower_get_ring_count(void) { return g_ring.total_count; }
uint32_t clawtower_get_ring_head(void) { return atomic_load(&g_ring.head); }

syscall_event_t *clawtower_get_ring_event(uint32_t idx) {
    if (idx >= RING_SIZE) return NULL;
    return &g_ring.events[idx];
}

void clawtower_reset(void) {
    memset(&g_ring, 0, sizeof(g_ring));
    g_sensitive_fd_count = 0;
    memset(g_socket_fds, 0, sizeof(g_socket_fds));
    memset(&g_openat_freq, 0, sizeof(g_openat_freq));
}
