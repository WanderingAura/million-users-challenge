// main.c: the unity build. Every other .c file is included here, in dependency order, so the whole server is one
// translation unit (one compile, whole-program inlining, simple PGO).
#include "base.h"
#include "linux.c"
#include "sha256.c"
#include "simd.c"
#include "timefmt.c"
#include "json.c"
#include "jwt.c"
#include "deflate.c"
#include "pg.c"
#include "http.c"

// ---- allocation guard: after startup, the serving threads must not allocate ----
#if defined(__GLIBC__) && !defined(NO_ALLOC_GUARD)
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);
static __thread int t_serving;  // set on core threads once their loop starts
static __thread int t_allow;    // set around rare paths that may allocate inside libc (reconnect, logging)
static int g_alloc_abort;
static volatile int g_alloc_violations;
static void alloc_violation(void)
{
    if (__atomic_fetch_add(&g_alloc_violations, 1, __ATOMIC_RELAXED) == 0) {
        static const char msg[] = "warning: heap allocation on a serving thread\n";
        ssize_t w = write(2, msg, sizeof(msg) - 1);
        (void)w;
    }
    if (g_alloc_abort) abort();
}
void *malloc(size_t n)
{
    if (t_serving && !t_allow) alloc_violation();
    return __libc_malloc(n);
}
void *calloc(size_t a, size_t b)
{
    if (t_serving && !t_allow) alloc_violation();
    return __libc_calloc(a, b);
}
void *realloc(void *p, size_t n)
{
    if (t_serving && !t_allow) alloc_violation();
    return __libc_realloc(p, n);
}
void free(void *p) { __libc_free(p); }
#define ALLOW_ALLOC_BEGIN() (t_allow++)
#define ALLOW_ALLOC_END() (t_allow--)
#define SERVING_BEGIN() (t_serving = 1)
#else
static int g_alloc_abort __attribute__((unused));
static volatile int g_alloc_violations;
#define ALLOW_ALLOC_BEGIN() ((void)0)
#define ALLOW_ALLOC_END() ((void)0)
#define SERVING_BEGIN() ((void)0)
#endif

// pg_connect calls getaddrinfo and friends, which allocate: allow it on that (reconnect-only) path.
internal int pg_connect_guarded(const DbConfig *c, ScramCache *s, char *err, umm cap)
{
    ALLOW_ALLOC_BEGIN();
    int fd = pg_connect(c, s, err, cap);
    ALLOW_ALLOC_END();
    return fd;
}
#define pg_connect pg_connect_guarded
#define fprintf(...) (ALLOW_ALLOC_BEGIN(), fprintf(__VA_ARGS__), ALLOW_ALLOC_END())
#include "loop.c"
#undef fprintf
#undef pg_connect

// ---- a synthetic corpus for the Huffman code (built from words and formats, never from the database) ----
global const char *corpus_words[] = {
    "the", "a", "an", "and", "but", "or", "so", "because", "while", "after", "before", "just", "really", "very",
    "is", "was", "it", "to", "of", "in", "on", "for", "with", "at", "by", "from", "my", "your", "our", "we", "you",
    "i", "they", "this", "that", "these", "those", "here", "there", "today", "tomorrow", "yesterday", "again",
    "server", "database", "request", "latency", "cache", "index", "query", "benchmark", "cpu", "memory", "disk",
    "network", "throughput", "users", "coffee", "morning", "weekend", "project", "deploy", "release", "bug",
    "feature", "test", "rewrite", "refactor", "commit", "branch", "merge", "review", "thinking", "building",
    "shipping", "learning", "reading", "writing", "debugging", "measuring", "watching", "waiting", "running",
    "fast", "slow", "small", "big", "cheap", "simple", "boring", "clever", "weird", "surprising", "honest",
    "careful", "lucky", "tired", "ready", "done", "broken", "finally", "never", "always", "sometimes", "usually",
    "something", "nothing", "everything", "anything", "someone", "linux", "kernel", "socket", "pool", "load",
    "says", "hi", "hello", "thanks", "good", "great", "new", "first", "last", "time", "day", "week", "year",
    "people", "work", "home", "city", "music", "book", "game", "team", "idea", "plan", "note", "update",
};
global const char *corpus_adj[] = {"quiet", "brave", "clever", "sunny", "rusty", "swift", "lazy", "mellow", "sharp",
                                    "wild", "cosmic", "tiny", "golden", "silver", "happy", "grumpy", "curious"};
global const char *corpus_noun[] = {"otter", "falcon", "badger", "comet", "river", "maple", "pixel", "walrus", "ember",
                                     "glacier", "lantern", "meadow", "nebula", "orchid", "pebble", "raven", "willow"};

typedef struct { u64 s; } Rng;
internal u32 rng_next(Rng *r)
{
    r->s ^= r->s << 13;
    r->s ^= r->s >> 7;
    r->s ^= r->s << 17;
    return (u32)(r->s >> 11);
}
internal u32 rng_range(Rng *r, u32 lo, u32 hi) { return lo + rng_next(r) % (hi - lo + 1); }

// Fills `rows` with plausible posts; text goes into `pool`.
internal void corpus_rows(Rng *r, PostRow *rows, int n, u8 *pool, s64 *id_base, s64 *ts_base)
{
    u8 *o = pool;
    for (int i = 0; i < n; i++) {
        PostRow *row = &rows[i];
        row->id = (*id_base)--;
        *ts_base -= (s64)rng_range(r, 1000, 120000) * 1000;
        row->ts = *ts_base;
        row->likes = rng_range(r, 0, 3) == 0 ? rng_range(r, 0, 300) : rng_range(r, 0, 20);
        row->body = o;
        int sentences = (int)rng_range(r, 1, 3);
        for (int s = 0; s < sentences; s++) {
            int words = (int)rng_range(r, 3, 14);
            for (int w = 0; w < words; w++) {
                const char *wd = corpus_words[rng_next(r) % ArrayCount(corpus_words)];
                umm l = strlen(wd);
                memcpy(o, wd, l);
                if (w == 0) *o = (u8)(*o >= 'a' && *o <= 'z' ? *o - 32 : *o);
                o += l;
                if (rng_range(r, 0, 12) == 0) *o++ = ',';
                if (w + 1 < words) *o++ = ' ';
            }
            const char *punct[] = {".", ".", "!", "?", "...", "."};
            const char *p = punct[rng_next(r) % 6];
            memcpy(o, p, strlen(p));
            o += strlen(p);
            if (s + 1 < sentences) *o++ = ' ';
        }
        if (rng_range(r, 0, 4) == 0) { // some bodies carry numbers and times
            o += sprintf((char *)o, " at %02u:%02u (%u, %u)", rng_range(r, 0, 23), rng_range(r, 0, 59),
                         rng_range(r, 1, 99999), rng_range(r, 1, 50));
        }
        row->body_len = (u32)(o - row->body);
        row->author = o;
        o += sprintf((char *)o, "%s_%s_%u", corpus_adj[rng_next(r) % ArrayCount(corpus_adj)],
                     corpus_noun[rng_next(r) % ArrayCount(corpus_noun)], rng_range(r, 1, 50000));
        row->author_len = (u32)(o - row->author);
    }
}

internal void huffman_init(void)
{
    deflate_static_init();
    static u32 lit_freq[NUM_LIT], dist_freq[NUM_DIST];
    static u8 out[65536], pool[65536];
    static Deflater dz;
    Rng r = {0x9E3779B97F4A7C15ull};
    s64 id_base = 600000, ts_base = (s64)(1790000000LL - 946684800LL) * 1000000LL;
    for (int f = 0; f < 400; f++) {
        PostRow rows[20];
        corpus_rows(&r, rows, 20, pool, &id_base, &ts_base);
        FeedW fw;
        feed_begin(&fw, out);
        for (int i = 0; i < 20; i++) feed_post(&fw, &rows[i]);
        feed_end(&fw);
        deflate_count(&dz, out, (u32)(fw.o - out), fw.hints, fw.nh, lit_freq, dist_freq);
    }
    // every symbol stays encodable: add one to each count
    for (int i = 0; i < NUM_LIT; i++) lit_freq[i] += 1;
    for (int i = 0; i < NUM_DIST; i++) dist_freq[i] += 1;
    huff_build(lit_freq, dist_freq);
}

internal void globals_init(const char *secret)
{
    timefmt_init();
    crc_init();
    http_init();
    jwt_init(secret);
    pg_templates_init();
    huffman_init();
}

internal int env_int(const char *name, int dflt)
{
    const char *v = getenv(name);
    return v && *v ? atoi(v) : dflt;
}

internal void config_init(void)
{
    cfg.start_ns = now_mono_ns();
    cfg.threads = env_int("THREADS", cpu_count());
    if (cfg.threads < 1) cfg.threads = 1;
    if (cfg.threads > MAX_CORES) cfg.threads = MAX_CORES;
    cfg.read_conns_total = env_int("DB_READ_CONNS", 0); // 0: automatic, see server_start
    cfg.batch_min = (u32)env_int("BATCH_MIN", 128);
    cfg.batch_us = env_int("BATCH_US", 4000);
    const char *h = getenv("HOST");
    snprintf(cfg.host, sizeof(cfg.host), "%s", h && *h ? h : "0.0.0.0");
    cfg.port = env_int("PORT", 3000);
    cfg.extra_port = env_int("EXTRA_PORT", 3001);
    g_alloc_abort = getenv("ALLOC_GUARD") && strcmp(getenv("ALLOC_GUARD"), "abort") == 0;
    // CPU_AFFINITY=1: pin loop i to the i-th CPU of the mask and steer connections by CPU. Off by default: the
    // README's rule 13 says no pinning of CPU, and whether that covers a process pinning its own threads is
    // the organiser's call.
    cfg.cpu_affinity = env_int("CPU_AFFINITY", 0) == 1;
    if (cfg.cpu_affinity) {
        int nc = cpu_list(cfg.cpus, MAX_CORES);
        b32 contiguous = nc >= cfg.threads;
        for (int i = 1; i < cfg.threads && contiguous; i++) contiguous = cfg.cpus[i] == cfg.cpus[0] + i;
        if (!contiguous) {
            fprintf(stderr, "CPU_AFFINITY ignored: the CPU mask is not contiguous or smaller than THREADS\n");
            cfg.cpu_affinity = 0;
        }
    }
    u32 nofile = raise_nofile();
    cfg.slots = Min(MAX_SLOTS, nofile > 64 ? nofile - 64 : nofile);
    // Ring and buffer-ring memory can count against RLIMIT_MEMLOCK (systemd's default is 8 MB for the whole
    // process): size each core's rings to its share. Defaults: SQ 4096, CQ 16384, 8192 receive buffers.
    {
        struct rlimit rl;
        u64 lim = Megabytes(8);
        if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
            rl.rlim_cur = rl.rlim_max;
            setrlimit(RLIMIT_MEMLOCK, &rl);
            getrlimit(RLIMIT_MEMLOCK, &rl);
            lim = rl.rlim_cur == RLIM_INFINITY ? Megabytes(1024) : (u64)rl.rlim_cur;
        }
        u64 budget = lim * 3 / 4 / (u64)cfg.threads;
        cfg.sq_entries = 4096;
        cfg.cq_entries = 16384;
        cfg.nbufs = RBUF_COUNT_MAX;
        for (;;) {
            u64 need = (u64)cfg.sq_entries * 64 + (u64)cfg.cq_entries * 16 + (u64)cfg.nbufs * 16 + 16384;
            if (need <= budget || cfg.cq_entries <= 1024) break;
            cfg.sq_entries = Max(cfg.sq_entries / 2, 256u);
            cfg.cq_entries /= 2;
            cfg.nbufs = Max(cfg.nbufs / 2, 1024u);
        }
    }
    if (cfg.slots < RESERVED_SLOTS + 1024) {
        fprintf(stderr, "fatal: open-file limit %u is too low\n", nofile);
        exit(1);
    }
}

global u8 *g_thread_stacks;
#define THREAD_STACK (2u << 20)

internal void server_start(pthread_t *threads)
{
    int n = cfg.threads;
    // Postgres read connections per core. Fewer, deeper pipelines cost less kernel time per request (one send and
    // one recv per connection per loop iteration), but the database needs enough backends to run feeds in
    // parallel: 64 in total, at least 6 and at most 16 per core (4 cores: 16 each, 8: 8, 16: 6).
    u32 nreaders;
    if (cfg.read_conns_total > 0) nreaders = (u32)((cfg.read_conns_total + n - 1) / n);
    else {
        nreaders = (u32)((64 + n - 1) / n);
        if (nreaders < 6) nreaders = 6;
        if (nreaders > 16) nreaders = 16;
    }
    if (nreaders < 1) nreaders = 1;
    if (nreaders > MAX_PG_PER_CORE) nreaders = MAX_PG_PER_CORE;
    while ((nreaders + 1) * (u32)n > 500 && nreaders > 1) nreaders--; // rule 5: at most 512 in total
    umm per = AlignUp(core_mem_size(cfg.slots, nreaders), 1 << 21);
    u8 *mem = reserve_memory(per * (umm)n);
    g_thread_stacks = reserve_memory((umm)THREAD_STACK * (umm)n);
    fprintf(stderr, "c-iouring: %d cores, %u read + 1 write postgres connections per core, %u slots per ring, "
                    "SQ %u CQ %u bufs %u, %s path\n", n, nreaders, cfg.slots, cfg.sq_entries, cfg.cq_entries,
            cfg.nbufs, FAST_X86 ? "AVX-512" : "scalar");
    for (int i = 0; i < n; i++) {
        Core *k = &cores[i];
        k->id = i;
        k->nslots = cfg.slots;
        k->nreaders = nreaders;
        core_layout(k, mem + per * (umm)i, per);
    }
    // listeners, in core order, so a SO_REUSEPORT group's socket index i belongs to core i
    for (int i = 0; i < n; i++) {
        cores[i].lfd[0] = listen_socket(cfg.host, cfg.port);
        cores[i].lfd[1] = listen_socket(cfg.host, cfg.extra_port);
    }
    if (cfg.cpu_affinity) {
        reuseport_by_cpu(cores[0].lfd[0], (u32)cfg.cpus[0]);
        reuseport_by_cpu(cores[0].lfd[1], (u32)cfg.cpus[0]);
    }
    for (int i = 0; i < n; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstack(&attr, g_thread_stacks + (umm)THREAD_STACK * (umm)i, THREAD_STACK);
        if (pthread_create(&threads[i], &attr, core_main, &cores[i]) != 0) die("pthread_create");
        pthread_attr_destroy(&attr);
    }
}

#include "train.c"
#include "selftest.c"

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0) return selftest_main();
    if (argc > 1 && strcmp(argv[1], "--bench") == 0) return bench_main();
    const char *secret = getenv("JWT_SECRET");
    if (!secret || !*secret) secret = "million-users-challenge";
    if (argc > 1 && strcmp(argv[1], "--train") == 0) return train_main(secret);
    const char *url = getenv("DATABASE_URL");
    if (!url || !*url) {
        fprintf(stderr, "fatal: DATABASE_URL is not set\n");
        return 1;
    }
    globals_init(secret);
    db_config_parse(&db_config, url);
    config_init();
    static pthread_t threads[MAX_CORES];
    server_start(threads);
    for (int i = 0; i < cfg.threads; i++) pthread_join(threads[i], 0);
    return 0;
}
