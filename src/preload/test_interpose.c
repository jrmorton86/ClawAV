/*
 * Test program for libclawtower.so v2
 *
 * Run: LD_PRELOAD=./libclawtower.so ./test_interpose
 *
 * Tests ring buffer, threat scoring, sensitive fd tracking,
 * pattern matching, and entropy detection.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

typedef struct {
    uint32_t syscall_nr;
    uint32_t flags;
    uint64_t timestamp_ns;
    uint64_t path_hash;
    uint16_t threat_score;
    uint16_t category;
} syscall_event_t;

/* Resolved at runtime from LD_PRELOAD'd library */
static uint16_t (*clawtower_get_threat_level)(void);
static uint16_t (*clawtower_get_alert_state)(void);
static uint32_t (*clawtower_get_ring_count)(void);
static uint32_t (*clawtower_get_ring_head)(void);
static void     (*clawtower_reset)(void);
static syscall_event_t *(*clawtower_get_ring_event)(uint32_t idx);

#define THREAT_NORMAL   0
#define THREAT_ELEVATED 1
#define THREAT_CRITICAL 2
#define THREAT_LOCKDOWN 3

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  TEST: %-50s ", name); } while(0)
#define PASS() do { printf("✅ PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("❌ FAIL: %s\n", msg); tests_failed++; } while(0)
#define CHECK(cond, msg) do { if (cond) { PASS(); } else { FAIL(msg); } } while(0)

/* ── Test 1: Ring buffer records events ──────────────────────────────── */
static void test_ring_buffer(void) {
    printf("\n═══ Ring Buffer Tests ═══\n");
    clawtower_reset();

    uint32_t before = clawtower_get_ring_count();

    /* Open a regular file — should record to ring buffer */
    int fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) close(fd);

    uint32_t after = clawtower_get_ring_count();
    TEST("open() records to ring buffer");
    CHECK(after > before, "ring count didn't increase after open()");

    /* Multiple opens should increase count */
    clawtower_reset();
    for (int i = 0; i < 10; i++) {
        fd = open("/dev/null", O_RDONLY);
        if (fd >= 0) close(fd);
    }
    TEST("multiple opens increase ring count");
    CHECK(clawtower_get_ring_count() >= 10, "expected >=10 events");
}

/* ── Test 2: Threat scoring on sensitive paths ───────────────────────── */
static void test_threat_scoring(void) {
    printf("\n═══ Threat Scoring Tests ═══\n");
    clawtower_reset();

    uint16_t before = clawtower_get_threat_level();

    /* Open /etc/passwd (sensitive) — should bump threat level */
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        char buf[64];
        read(fd, buf, sizeof(buf));  /* read on sensitive fd */
        close(fd);
    }

    uint16_t after = clawtower_get_threat_level();
    TEST("/etc/passwd read increases threat");
    CHECK(after > before, "threat level didn't increase after reading /etc/passwd");

    TEST("threat level reflects base score (~100)");
    CHECK(after >= 50, "expected threat >= 50 for /etc/passwd read");

    /* Check alert state */
    TEST("alert state correct for current level");
    uint16_t state = clawtower_get_alert_state();
    if (after < 300) {
        CHECK(state == THREAT_NORMAL, "expected NORMAL state");
    } else {
        CHECK(state >= THREAT_ELEVATED, "expected at least ELEVATED");
    }
}

/* ── Test 3: Sensitive fd tracking ───────────────────────────────────── */
static void test_sensitive_fd_tracking(void) {
    printf("\n═══ Sensitive FD Tracking Tests ═══\n");
    clawtower_reset();

    /* Open /etc/passwd, then read → should score the read */
    int fd = open("/etc/passwd", O_RDONLY);
    TEST("/etc/passwd opens successfully");
    CHECK(fd >= 0, "couldn't open /etc/passwd");

    if (fd >= 0) {
        uint16_t before_read = clawtower_get_threat_level();
        char buf[32];
        ssize_t n = read(fd, buf, sizeof(buf));
        uint16_t after_read = clawtower_get_threat_level();

        TEST("read on sensitive fd increases threat");
        CHECK(after_read > before_read, "threat didn't increase on sensitive read");

        close(fd);

        /* After close + new read on /dev/null, should NOT increase further */
        uint16_t before_null = clawtower_get_threat_level();
        fd = open("/dev/null", O_RDONLY);
        if (fd >= 0) {
            read(fd, buf, sizeof(buf));
            close(fd);
        }
        /* /dev/null is not sensitive so read shouldn't add score */
        TEST("/dev/null read doesn't add threat score");
        /* Allow small decay but shouldn't increase */
        CHECK(clawtower_get_threat_level() <= before_null + 1,
              "non-sensitive read shouldn't add score");
    }
}

/* ── Test 4: Ring buffer wraps correctly ─────────────────────────────── */
static void test_ring_wrap(void) {
    printf("\n═══ Ring Wrap Tests ═══\n");
    clawtower_reset();

    /* Generate >256 events to force ring wrap */
    for (int i = 0; i < 300; i++) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd >= 0) close(fd);
    }

    TEST("ring wraps without crash (>256 events)");
    CHECK(clawtower_get_ring_count() >= 300, "expected >=300 total events");

    /* Head should have wrapped */
    uint32_t head = clawtower_get_ring_head();
    TEST("head pointer wraps correctly");
    CHECK(head >= 300, "head should be >= 300 (raw, mod 256 for index)");

    /* Events should still be readable */
    syscall_event_t *evt = clawtower_get_ring_event(head % 256);
    TEST("wrapped events are readable");
    CHECK(evt != NULL, "event pointer should not be NULL");
}

/* ── Test 5: mprotect PROT_EXEC scoring ──────────────────────────────── */
static void test_mprotect_scoring(void) {
    printf("\n═══ mprotect Scoring Tests ═══\n");
    clawtower_reset();

    /* Allocate a page and mprotect it PROT_EXEC */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST("mmap RW succeeds");
    CHECK(page != MAP_FAILED, "mmap failed");

    if (page != MAP_FAILED) {
        uint16_t before = clawtower_get_threat_level();

        /* mprotect to PROT_EXEC — high threat! */
        int ret = mprotect(page, 4096, PROT_READ | PROT_EXEC);

        uint16_t after = clawtower_get_threat_level();
        TEST("mprotect PROT_EXEC increases threat significantly");
        CHECK(after > before + 100, "expected large threat increase for PROT_EXEC");

        munmap(page, 4096);
    }
}

/* ── Test 6: Pattern matching (shellcode injection) ──────────────────── */
static void test_pattern_shellcode(void) {
    printf("\n═══ Pattern Matching: Shellcode Injection ═══\n");
    clawtower_reset();

    /* Pattern: mmap(RW) → mprotect(RX) within 1s = shellcode injection */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        TEST("mmap for pattern test");
        FAIL("mmap failed");
        return;
    }

    uint16_t before = clawtower_get_threat_level();
    mprotect(page, 4096, PROT_READ | PROT_EXEC);
    uint16_t after = clawtower_get_threat_level();

    TEST("shellcode pattern (mmap RW → mprotect RX) detected");
    /* Should have both the mprotect base score AND pattern boost */
    CHECK(after >= 500, "expected threat >= 500 from shellcode pattern");

    munmap(page, 4096);
}

/* ── Test 7: connect() scoring with multiplier ───────────────────────── */
static void test_connect_scoring(void) {
    printf("\n═══ Connect Scoring Tests ═══\n");
    clawtower_reset();

    /* First read /etc/passwd, then connect — should get multiplied score */
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        char buf[32];
        read(fd, buf, sizeof(buf));
        close(fd);
    }

    uint16_t before_connect = clawtower_get_threat_level();

    /* Create a socket and try to connect to localhost:1 (will fail, but hook fires) */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(1);
        inet_aton("127.0.0.1", &addr.sin_addr);

        connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        /* Don't care about return — hook already fired */

        uint16_t after_connect = clawtower_get_threat_level();
        TEST("connect after sensitive read gets multiplied score");
        CHECK(after_connect > before_connect + 100,
              "expected significant increase from connect with prior read");

        close(sock);
    }
}

/* ── Test 8: Introspection API works ─────────────────────────────────── */
static void test_introspection(void) {
    printf("\n═══ Introspection API Tests ═══\n");
    clawtower_reset();

    TEST("reset clears threat level");
    CHECK(clawtower_get_threat_level() == 0, "threat not 0 after reset");

    TEST("reset clears ring count");
    CHECK(clawtower_get_ring_count() == 0, "ring count not 0 after reset");

    TEST("reset clears alert state");
    CHECK(clawtower_get_alert_state() == THREAT_NORMAL, "alert not NORMAL after reset");

    /* Get event from empty ring */
    syscall_event_t *evt = clawtower_get_ring_event(0);
    TEST("ring event at index 0 accessible");
    CHECK(evt != NULL, "event pointer should not be NULL");

    TEST("out of bounds index returns NULL");
    CHECK(clawtower_get_ring_event(999) == NULL, "expected NULL for OOB index");
}

/* ── Test 9: Threat level decay ──────────────────────────────────────── */
static void test_decay(void) {
    printf("\n═══ Threat Decay Tests ═══\n");
    clawtower_reset();

    /* Generate some threat */
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        char buf[32];
        read(fd, buf, sizeof(buf));
        close(fd);
    }

    uint16_t initial = clawtower_get_threat_level();
    TEST("initial threat after /etc/passwd read > 0");
    CHECK(initial > 0, "expected non-zero threat");

    /* Sleep to allow decay */
    if (initial > 0) {
        sleep(2);
        /* Trigger another event to apply decay */
        fd = open("/dev/null", O_RDONLY);
        if (fd >= 0) close(fd);

        uint16_t after_decay = clawtower_get_threat_level();
        TEST("threat decays after 2s of clean activity");
        CHECK(after_decay < initial, "expected threat to decay over time");
    }
}

/* ── Main ─────────────────────────────────────────────────────────────── */
int main(void) {
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   libclawtower.so v2 — Test Suite               ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    /* Resolve introspection API from LD_PRELOAD'd library */
    clawtower_get_threat_level = dlsym(RTLD_DEFAULT, "clawtower_get_threat_level");
    clawtower_get_alert_state  = dlsym(RTLD_DEFAULT, "clawtower_get_alert_state");
    clawtower_get_ring_count   = dlsym(RTLD_DEFAULT, "clawtower_get_ring_count");
    clawtower_get_ring_head    = dlsym(RTLD_DEFAULT, "clawtower_get_ring_head");
    clawtower_get_ring_event   = dlsym(RTLD_DEFAULT, "clawtower_get_ring_event");
    clawtower_reset            = dlsym(RTLD_DEFAULT, "clawtower_reset");

    if (!clawtower_get_threat_level || !clawtower_reset) {
        printf("\n⚠️  Not running with LD_PRELOAD! Run with:\n");
        printf("   LD_PRELOAD=./libclawtower.so ./test_interpose\n\n");
        return 1;
    }

    test_introspection();
    test_ring_buffer();
    test_ring_wrap();
    test_threat_scoring();
    test_sensitive_fd_tracking();
    test_mprotect_scoring();
    test_pattern_shellcode();
    test_connect_scoring();
    test_decay();

    printf("\n══════════════════════════════════════════════════\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("══════════════════════════════════════════════════\n");

    return tests_failed > 0 ? 1 : 0;
}
