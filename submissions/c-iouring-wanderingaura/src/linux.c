// linux.c: raw io_uring syscalls and ring plumbing, sockets, clocks. Only 6.8-era io_uring features are used.
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/io_uring.h>

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#define __NR_io_uring_register 427
#endif

internal int sys_io_uring_setup(u32 entries, struct io_uring_params *p)
{
    return (int)syscall(__NR_io_uring_setup, entries, p);
}
internal int sys_io_uring_enter(int fd, u32 to_submit, u32 min_complete, u32 flags, void *arg, umm argsz)
{
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, arg, argsz);
}
internal int sys_io_uring_register(int fd, u32 op, void *arg, u32 nr)
{
    return (int)syscall(__NR_io_uring_register, fd, op, arg, nr);
}

internal void die(const char *what)
{
    fprintf(stderr, "fatal: %s (errno %d: %s)\n", what, errno, strerror(errno));
    exit(1);
}

// ---- time ----
internal inline s64 clock_ns(clockid_t id)
{
    struct timespec ts;
    clock_gettime(id, &ts);
    return (s64)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
internal inline s64 now_mono_ns(void) { return clock_ns(CLOCK_MONOTONIC); }
internal inline s64 now_real_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (s64)ts.tv_sec;
}

// ---- ring ----
typedef struct {
    int fd;
    u32 flags;
    // submission queue
    u32 *sq_khead;
    u32 *sq_ktail;
    u32 *sq_kflags;
    u32 *sq_array; // only when the kernel lacks NO_SQARRAY
    u32 sq_mask;
    u32 sq_entries;
    u32 sq_tail;      // our local tail (published on submit)
    u32 sq_submitted; // tail value last handed to the kernel
    struct io_uring_sqe *sqes;
    // completion queue
    u32 *cq_khead;
    u32 *cq_ktail;
    u32 cq_mask;
    u32 cq_entries;
    struct io_uring_cqe *cqes;
} Ring;

internal void ring_init(Ring *r, u32 sq_entries, u32 cq_entries)
{
    struct io_uring_params p;
    u32 base_flags = IORING_SETUP_CQSIZE | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_SINGLE_ISSUER |
                     IORING_SETUP_DEFER_TASKRUN;
    int fd = -1;
    u32 extra = IORING_SETUP_NO_SQARRAY;
    for (;;) {
        memset(&p, 0, sizeof(p));
        p.flags = base_flags | extra;
        p.cq_entries = cq_entries;
        fd = sys_io_uring_setup(sq_entries, &p);
        if (fd >= 0) break;
        if (errno == EINVAL && extra) { extra = 0; continue; } // kernel without NO_SQARRAY
        // The rings are physically contiguous kernel allocations: on a fragmented box a large one can fail.
        if (errno == ENOMEM && cq_entries > 1024) { cq_entries /= 2; sq_entries = Max(sq_entries / 2, 256u); continue; }
        die("io_uring_setup");
    }
    memset(r, 0, sizeof(*r));
    r->fd = fd;
    r->flags = p.flags;
    if (!(p.features & IORING_FEAT_SINGLE_MMAP)) die("io_uring: kernel lacks IORING_FEAT_SINGLE_MMAP");
    umm sq_sz = p.sq_off.array + p.sq_entries * sizeof(u32);
    umm cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    umm sz = Max(sq_sz, cq_sz);
    u8 *ptr = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
    if (ptr == MAP_FAILED) die("mmap sq ring");
    r->sq_khead = (u32 *)(ptr + p.sq_off.head);
    r->sq_ktail = (u32 *)(ptr + p.sq_off.tail);
    r->sq_kflags = (u32 *)(ptr + p.sq_off.flags);
    r->sq_mask = *(u32 *)(ptr + p.sq_off.ring_mask);
    r->sq_entries = *(u32 *)(ptr + p.sq_off.ring_entries);
    if (!(p.flags & IORING_SETUP_NO_SQARRAY)) {
        r->sq_array = (u32 *)(ptr + p.sq_off.array);
        for (u32 i = 0; i < r->sq_entries; i++) r->sq_array[i] = i;
    }
    r->cq_khead = (u32 *)(ptr + p.cq_off.head);
    r->cq_ktail = (u32 *)(ptr + p.cq_off.tail);
    r->cq_mask = *(u32 *)(ptr + p.cq_off.ring_mask);
    r->cq_entries = *(u32 *)(ptr + p.cq_off.ring_entries);
    r->cqes = (struct io_uring_cqe *)(ptr + p.cq_off.cqes);
    r->sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) die("mmap sqes");
}

// Hands every queued SQE to the kernel and optionally waits for completions (min_complete, timeout_us).
internal int ring_submit_wait(Ring *r, u32 min_complete, s64 timeout_us)
{
    u32 to_submit = r->sq_tail - r->sq_submitted;
    StoreRelease32(r->sq_ktail, r->sq_tail);
    r->sq_submitted = r->sq_tail;
    u32 flags = 0;
    struct io_uring_getevents_arg arg;
    struct __kernel_timespec ts;
    void *argp = 0;
    umm argsz = 0;
    if (min_complete) {
        flags |= IORING_ENTER_GETEVENTS;
        if (timeout_us > 0) {
            memset(&arg, 0, sizeof(arg));
            ts.tv_sec = timeout_us / 1000000;
            ts.tv_nsec = (timeout_us % 1000000) * 1000;
            arg.ts = (u64)(uintptr_t)&ts;
            argp = &arg;
            argsz = sizeof(arg);
            flags |= IORING_ENTER_EXT_ARG;
        }
    } else {
        // DEFER_TASKRUN: completions are only posted while we are in the kernel with GETEVENTS.
        flags |= IORING_ENTER_GETEVENTS;
    }
    for (;;) {
        int ret = sys_io_uring_enter(r->fd, to_submit, min_complete, flags, argp, argsz);
        if (ret >= 0) return ret;
        if (errno == ETIME || errno == EBUSY) return 0;
        if (errno == EINTR) { to_submit = 0; continue; }
        if (errno == EAGAIN) return 0;
        return -errno;
    }
}

internal inline struct io_uring_sqe *ring_sqe(Ring *r)
{
    if (unlikely(r->sq_tail - r->sq_submitted >= r->sq_entries)) {
        ring_submit_wait(r, 0, 0); // SQ full: hand what we have to the kernel (it consumes synchronously)
    }
    struct io_uring_sqe *sqe = &r->sqes[r->sq_tail & r->sq_mask];
    r->sq_tail++;
    memset(sqe, 0, sizeof(*sqe));
    return sqe;
}

// ---- provided receive buffers ----
// Ubuntu 24.04's 6.8 kernel (6.8.0-147) rejects every IORING_REGISTER_PBUF_RING with EINVAL, user memory or
// kernel-allocated, so ring-mapped buffers are out. Classic provided buffers (IORING_OP_PROVIDE_BUFFERS) work there
// with multishot recv. Buffers handed back during an iteration are marked in a bitmap and re-provided at the end
// of it as contiguous runs, one SQE per run, with the success completion suppressed.
#define BUFPOOL_MAX 65536
typedef struct {
    u8 *bufs;
    u32 buf_size;
    u32 count;
    u16 bgid;
    u32 nfreed;
    u64 freed[BUFPOOL_MAX / 64];
} BufPool;

internal void bufpool_provide(Ring *r, BufPool *b, u32 first, u32 n, u64 ud)
{
    struct io_uring_sqe *s = ring_sqe(r);
    s->opcode = IORING_OP_PROVIDE_BUFFERS;
    s->fd = (s32)n;
    s->addr = (u64)(uintptr_t)(b->bufs + (umm)first * b->buf_size);
    s->len = b->buf_size;
    s->off = first;
    s->buf_group = b->bgid;
    s->flags = IOSQE_CQE_SKIP_SUCCESS;
    s->user_data = ud;
}

internal void bufpool_init(Ring *r, BufPool *b, u16 bgid, u8 *bufs, u32 count, u32 buf_size, u64 ud)
{
    Assert(count <= BUFPOOL_MAX);
    b->bufs = bufs;
    b->buf_size = buf_size;
    b->count = count;
    b->bgid = bgid;
    b->nfreed = 0;
    memset(b->freed, 0, sizeof(b->freed));
    bufpool_provide(r, b, 0, count, ud);
}

internal inline void bufpool_put(BufPool *b, u16 bid)
{
    b->freed[bid >> 6] |= 1ull << (bid & 63);
    b->nfreed++;
}

internal void bufpool_publish(Ring *r, BufPool *b, u64 ud)
{
    if (!b->nfreed) return;
    u32 words = (b->count + 63) / 64;
    u32 run_start = 0, run_len = 0;
    for (u32 w = 0; w < words; w++) {
        u64 m = b->freed[w];
        if (!m) {
            if (run_len) { bufpool_provide(r, b, run_start, run_len, ud); run_len = 0; }
            continue;
        }
        b->freed[w] = 0;
        if (m == ~0ull) { // whole word
            if (!run_len) run_start = w * 64;
            run_len += 64;
            continue;
        }
        for (u32 bit = 0; bit < 64; bit++) {
            if (m & (1ull << bit)) {
                if (!run_len) run_start = w * 64 + bit;
                run_len++;
            } else if (run_len) {
                bufpool_provide(r, b, run_start, run_len, ud);
                run_len = 0;
            }
        }
    }
    if (run_len) bufpool_provide(r, b, run_start, run_len, ud);
    b->nfreed = 0;
}

// ---- registered (direct) file table ----
internal void ring_register_sparse_files(Ring *r, u32 nr, u32 alloc_off)
{
    struct io_uring_rsrc_register rr;
    memset(&rr, 0, sizeof(rr));
    rr.nr = nr;
    rr.flags = IORING_RSRC_REGISTER_SPARSE;
    if (sys_io_uring_register(r->fd, IORING_REGISTER_FILES2, &rr, sizeof(rr)) < 0) die("IORING_REGISTER_FILES2");
    struct io_uring_file_index_range range;
    memset(&range, 0, sizeof(range));
    range.off = alloc_off;
    range.len = nr - alloc_off;
    if (sys_io_uring_register(r->fd, IORING_REGISTER_FILE_ALLOC_RANGE, &range, 0) < 0)
        die("IORING_REGISTER_FILE_ALLOC_RANGE");
}

internal int ring_set_file(Ring *r, u32 slot, int fd)
{
    struct io_uring_files_update up;
    memset(&up, 0, sizeof(up));
    s32 fds[1] = {fd};
    up.offset = slot;
    up.fds = (u64)(uintptr_t)fds;
    return sys_io_uring_register(r->fd, IORING_REGISTER_FILES_UPDATE, &up, 1);
}

// ---- sockets ----
internal int listen_socket(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) die("socket");
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) die("SO_REUSEPORT");
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); // copied to accepted sockets
    int defer = 5;
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer, sizeof(defer));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((u16)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) die("bind");
    if (listen(fd, 65535) < 0) die("listen");
    return fd;
}

// Optional (CPU_AFFINITY=1): pick the listener in a SO_REUSEPORT group by the CPU that is processing the incoming
// SYN, so a connection is owned by the loop on the CPU where its packets are processed. Group index = cpu - first.
#include <linux/filter.h>
internal void reuseport_by_cpu(int fd, u32 first_cpu)
{
    struct sock_filter code[] = {
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, (u32)(SKF_AD_OFF + SKF_AD_CPU)},
        {BPF_ALU | BPF_SUB | BPF_K, 0, 0, first_cpu},
        {BPF_RET | BPF_A, 0, 0, 0},
    };
    struct sock_fprog prog = {(unsigned short)ArrayCount(code), code};
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof(prog)) < 0)
        fprintf(stderr, "warning: SO_ATTACH_REUSEPORT_CBPF failed: %s\n", strerror(errno));
}

internal int cpu_list(int *cpus, int max)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    int n = 0;
    if (sched_getaffinity(0, sizeof(set), &set) == 0)
        for (int c = 0; c < CPU_SETSIZE && n < max; c++)
            if (CPU_ISSET(c, &set)) cpus[n++] = c;
    return n;
}

internal int cpu_count(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) == 0) {
        int n = CPU_COUNT(&set);
        if (n > 0) return n;
    }
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

internal u32 raise_nofile(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
        getrlimit(RLIMIT_NOFILE, &rl);
        return rl.rlim_cur > 0xFFFFFFFFu ? 0xFFFFFFFFu : (u32)rl.rlim_cur;
    }
    return 1024;
}

// One reservation for all user-space memory, carved up at startup.
internal u8 *reserve_memory(umm size)
{
    u8 *p = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) die("mmap reserve");
    madvise(p, size, MADV_HUGEPAGE);
    return p;
}
internal void prefault(u8 *p, umm size)
{
    for (umm i = 0; i < size; i += 4096) p[i] = 0;
}
