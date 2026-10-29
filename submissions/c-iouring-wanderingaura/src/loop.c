// loop.c: one event loop per core. Each core owns its ring, listeners, client connections (direct descriptors),
// Postgres connections, memory and batches. Nothing is shared or locked between cores after startup.

#define MAX_CORES 64
#define RESERVED_SLOTS 512        // direct-descriptor slots 0..511: Postgres connections
#define MAX_SLOTS (1u << 20)      // 6.8's per-ring limit on registered files
#define CLIENT_BGID 1
#define RBUF_SIZE 2048
#define RBUF_COUNT_MAX 8192
#define POOL_BLOCK (64 * 1024)
#define POOL_BLOCKS 1024
#define ARENA_SIZE Megabytes(32)
#define ARENA_LOW Megabytes(8)    // below this much free arena, new work waits for the next iteration
#define PG_SBUF Kilobytes(256)
#define PG_RBUF Kilobytes(512)
#define PEND_CAP 8192
#define WB_BYTES Megabytes(1)
#define WB_STRS Kilobytes(512)
#define WB_ENTRIES 2048 // a failed batch is replayed one by one: 2x entries + syncs must fit in PEND_CAP
#define WRITER_SBUF (WB_BYTES + Kilobytes(256))
#define DEFER_CAP 131072
#define SQ_ENTRIES 4096
#define CQ_ENTRIES 16384
#define MAX_PG_PER_CORE 64
#define GZIP_MIN 512

enum {
    UD_ACCEPT = 1, UD_RECV, UD_SEND0, UD_SEND1, UD_SENDBLK, UD_CLOSE, UD_CANCEL, UD_PGRECV, UD_PGSEND, UD_MISC
};
#define UD(t, idx, gen) (((u64)(t) << 56) | ((u64)((idx) & 0xFFFFFF) << 32) | (u64)(u32)(gen))
#define UD_TYPE(u) ((u32)((u) >> 56))
#define UD_IDX(u) ((u32)((u) >> 32) & 0xFFFFFF)
#define UD_GEN(u) ((u32)(u))

enum {
    CF_OPEN = 1, CF_BUSY = 2, CF_SENDING = 4, CF_CLOSE_AFTER = 8, CF_RECV_ARMED = 16, CF_SEND_BLK = 32,
    CF_CONTINUED = 64
};

typedef struct {
    u32 gen;
    u16 flags;
    u16 rblk;  // pool block + 1 holding unparsed request bytes
    u32 rlen;
    u16 sblk;  // pool block + 1 holding bytes still to send
    u16 pad;
    u32 soff;
    u32 slen;
    u32 a_off; // the in-flight arena send
    u32 a_len;
} Conn;

enum { K_SYNC = 1, K_FEED, K_POST, K_HEALTH, K_NEWPOST, K_LIKE };
enum { PS_WAIT = 0, PS_DONE, PS_ERR };

typedef struct {
    u32 slot;
    u32 gen;
    u8 kind;
    u8 rflags;
    u8 state;
    u8 inserted;
    char sqlstate[6];
    s64 id;     // post id (read / like)
    s64 r_id;   // new post: id and created_at
    s64 r_ts;
    u32 body_off, body_len;
    u32 uname_off, uname_len;
    u32 msg_off, msg_len;
} Pend;

typedef struct {
    u32 slot;
    u32 epoch;
    b32 is_writer;
    b32 broken;
    s64 next_reconnect_ns;
    u8 *sbuf[2];
    u32 slen[2];
    u32 scap;
    u32 fill;
    u32 send_idx;
    u32 sent;
    b32 sending;
    u32 unsynced;
    u8 *rbuf;
    u32 rlen;
    Pend *q;
    u32 qhead, qcur, qtail;
    b32 group_failed;
} PgConn;

typedef struct {
    u8 *bytes;
    u32 used;
    u8 *strs;
    u32 sused;
    Pend *ents;
    u32 n;
} WBatch;

typedef struct {
    int id;
    Ring ring;
    BufPool rb;
    Conn *conns;
    u32 nslots;
    int lfd[2];
    u8 *pool;
    u16 *pool_free;
    u32 pool_nfree;
    Arena arena[2];
    u32 arena_out[2];
    u32 ai;
    struct io_uring_cqe *defer;
    u32 ndefer;
    PgConn pg[MAX_PG_PER_CORE + 1];
    u32 nreaders;
    PgConn *writer;
    WBatch wb[2];
    u32 wstage;      // batch accumulating new writes
    b32 wb_inflight; // the other batch is at Postgres
    Deflater dz;
    ScramCache scram;
    s64 now_s;
    s64 now_ns;
    char last_db_error[200];
    // memory
    u8 *mem;
    umm mem_size;
} Core;

typedef struct {
    int threads;
    int read_conns_total;
    u32 batch_min;
    s64 batch_us;
    char host[64];
    int port;
    int extra_port;
    s64 start_ns;
    u32 slots;
    b32 cpu_affinity;
    int cpus[MAX_CORES];
    u32 sq_entries;
    u32 cq_entries;
    u32 nbufs;
} Config;
global Config cfg;
global Core cores[MAX_CORES];
global volatile int g_stop;
global volatile int g_ready;

// ---- memory ----
internal u8 *carve(u8 **cur, umm size, umm align)
{
    u8 *p = (u8 *)AlignUp((uintptr_t)*cur, align);
    *cur = p + size;
    return p;
}

internal umm core_mem_size(u32 nslots, u32 nreaders)
{
    umm s = 0;
    s += AlignUp((umm)nslots * sizeof(Conn), 65536);
    s += AlignUp((umm)RBUF_COUNT_MAX * RBUF_SIZE, 65536);
    s += AlignUp((umm)POOL_BLOCKS * POOL_BLOCK, 65536) + AlignUp(POOL_BLOCKS * 2, 65536);
    s += 2 * AlignUp(ARENA_SIZE, 65536);
    s += AlignUp((umm)DEFER_CAP * sizeof(struct io_uring_cqe), 65536);
    s += (umm)nreaders * (2 * AlignUp(PG_SBUF, 4096) + AlignUp(PG_RBUF, 4096) + AlignUp(PEND_CAP * sizeof(Pend), 4096));
    s += 2 * AlignUp(WRITER_SBUF, 4096) + AlignUp(PG_RBUF, 4096) + AlignUp(PEND_CAP * sizeof(Pend), 4096);
    s += 2 * (AlignUp(WB_BYTES, 4096) + AlignUp(WB_STRS, 4096) + AlignUp(WB_ENTRIES * sizeof(Pend), 4096));
    return s + Megabytes(1);
}

internal void core_layout(Core *k, u8 *mem, umm size)
{
    k->mem = mem;
    k->mem_size = size;
    u8 *cur = mem;
    k->conns = (Conn *)carve(&cur, (umm)k->nslots * sizeof(Conn), 65536);
    k->rb.bufs = carve(&cur, (umm)RBUF_COUNT_MAX * RBUF_SIZE, 65536);
    k->pool = carve(&cur, (umm)POOL_BLOCKS * POOL_BLOCK, 65536);
    k->pool_free = (u16 *)carve(&cur, POOL_BLOCKS * 2, 65536);
    for (int i = 0; i < 2; i++) {
        k->arena[i].base = carve(&cur, ARENA_SIZE, 65536);
        k->arena[i].size = ARENA_SIZE;
        k->arena[i].used = 0;
    }
    k->defer = (struct io_uring_cqe *)carve(&cur, (umm)DEFER_CAP * sizeof(struct io_uring_cqe), 65536);
    for (u32 i = 0; i <= k->nreaders; i++) {
        PgConn *pc = &k->pg[i];
        b32 w = (i == k->nreaders);
        pc->is_writer = w;
        pc->scap = w ? WRITER_SBUF : PG_SBUF;
        pc->sbuf[0] = carve(&cur, pc->scap, 4096);
        pc->sbuf[1] = carve(&cur, pc->scap, 4096);
        pc->rbuf = carve(&cur, PG_RBUF, 4096);
        pc->q = (Pend *)carve(&cur, PEND_CAP * sizeof(Pend), 4096);
        pc->slot = i;
    }
    k->writer = &k->pg[k->nreaders];
    for (int i = 0; i < 2; i++) {
        k->wb[i].bytes = carve(&cur, WB_BYTES, 4096);
        k->wb[i].strs = carve(&cur, WB_STRS, 4096);
        k->wb[i].ents = (Pend *)carve(&cur, WB_ENTRIES * sizeof(Pend), 4096);
    }
    Assert((umm)(cur - mem) <= size);
}

// ---- pool blocks ----
internal inline u8 *blk_ptr(Core *k, u16 b) { return k->pool + (umm)(b - 1) * POOL_BLOCK; }
internal inline u16 blk_alloc(Core *k)
{
    if (!k->pool_nfree) return 0;
    return (u16)(k->pool_free[--k->pool_nfree] + 1);
}
internal inline void blk_free(Core *k, u16 b)
{
    if (b) k->pool_free[k->pool_nfree++] = (u16)(b - 1);
}

// ---- SQE helpers ----
internal inline void sqe_recv_multishot(Core *k, u32 slot)
{
    struct io_uring_sqe *s = ring_sqe(&k->ring);
    s->opcode = IORING_OP_RECV;
    s->fd = (s32)slot;
    s->flags = IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
    s->buf_group = CLIENT_BGID;
    s->ioprio = IORING_RECV_MULTISHOT;
    s->user_data = UD(UD_RECV, slot, k->conns[slot].gen);
    k->conns[slot].flags |= CF_RECV_ARMED;
}

internal inline void sqe_accept(Core *k, int li)
{
    struct io_uring_sqe *s = ring_sqe(&k->ring);
    s->opcode = IORING_OP_ACCEPT;
    s->fd = k->lfd[li];
    s->ioprio = IORING_ACCEPT_MULTISHOT;
    s->file_index = IORING_FILE_INDEX_ALLOC;
    s->user_data = UD(UD_ACCEPT, li, 0);
}

internal inline void sqe_send(Core *k, u32 slot, const u8 *p, u32 n, u32 msg_flags, u64 ud)
{
    struct io_uring_sqe *s = ring_sqe(&k->ring);
    s->opcode = IORING_OP_SEND;
    s->fd = (s32)slot;
    s->flags = IOSQE_FIXED_FILE;
    s->addr = (u64)(uintptr_t)p;
    s->len = n;
    s->msg_flags = msg_flags;
    s->user_data = ud;
}

// ---- connections ----
internal void conn_close(Core *k, u32 slot)
{
    Conn *c = &k->conns[slot];
    if (!(c->flags & CF_OPEN)) return;
    blk_free(k, c->rblk);
    blk_free(k, c->sblk);
    c->rblk = c->sblk = 0;
    c->rlen = c->soff = c->slen = 0;
    c->flags = 0;
    c->gen++;
    struct io_uring_sqe *s = ring_sqe(&k->ring);
    s->opcode = IORING_OP_ASYNC_CANCEL;
    s->fd = (s32)slot;
    s->cancel_flags = IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_FD_FIXED | IORING_ASYNC_CANCEL_ALL;
    s->flags = IOSQE_IO_HARDLINK;
    s->user_data = UD(UD_CANCEL, slot, 0);
    s = ring_sqe(&k->ring);
    s->opcode = IORING_OP_CLOSE;
    s->file_index = slot + 1;
    s->user_data = UD(UD_CLOSE, slot, 0);
}

internal void blk_send(Core *k, u32 slot)
{
    Conn *c = &k->conns[slot];
    c->flags |= CF_SENDING | CF_SEND_BLK;
    sqe_send(k, slot, blk_ptr(k, c->sblk) + c->soff, c->slen - c->soff, MSG_NOSIGNAL, UD(UD_SENDBLK, slot, c->gen));
}

internal b32 blk_append(Core *k, Conn *c, const u8 *p, u32 n)
{
    if (!c->sblk) {
        c->sblk = blk_alloc(k);
        if (!c->sblk) return 0;
        c->soff = c->slen = 0;
    }
    u8 *b = blk_ptr(k, c->sblk);
    if (c->slen + n > POOL_BLOCK && !(c->flags & CF_SEND_BLK) && c->soff) {
        memmove(b, b + c->soff, c->slen - c->soff);
        c->slen -= c->soff;
        c->soff = 0;
    }
    if (c->slen + n > POOL_BLOCK) return 0;
    memcpy(b + c->slen, p, n);
    c->slen += n;
    return 1;
}

internal b32 blk_prepend(Core *k, Conn *c, const u8 *p, u32 n)
{
    if (!c->sblk) {
        c->sblk = blk_alloc(k);
        if (!c->sblk) return 0;
        c->soff = c->slen = 0;
    }
    u8 *b = blk_ptr(k, c->sblk);
    u32 have = c->slen - c->soff;
    if (have + n > POOL_BLOCK) return 0;
    memmove(b + n, b + c->soff, have);
    memcpy(b, p, n);
    c->soff = 0;
    c->slen = have + n;
    return 1;
}

// Sends [p, p+n), which lives in the current arena. Order is kept per connection.
internal void conn_send(Core *k, u32 slot, u8 *p, u32 n)
{
    Conn *c = &k->conns[slot];
    if (!(c->flags & CF_OPEN)) return;
    if ((c->flags & CF_SENDING) || c->sblk) {
        if (!blk_append(k, c, p, n)) conn_close(k, slot);
        else if (!(c->flags & CF_SENDING)) blk_send(k, slot);
        return;
    }
    u32 a = k->ai;
    sqe_send(k, slot, p, n, MSG_DONTWAIT | MSG_NOSIGNAL, UD(UD_SEND0 + a, slot, c->gen));
    c->flags |= CF_SENDING;
    c->a_off = (u32)(p - k->arena[a].base);
    c->a_len = n;
    k->arena_out[a]++;
}

internal void respond(Core *k, u32 slot, int status, u8 *body, u8 *body_end, u32 rflags, b32 gzipped)
{
    Conn *c = &k->conns[slot];
    if (rflags & RF_CLOSE) c->flags |= CF_CLOSE_AFTER;
    u8 *start = http_prepend_header(body, (umm)(body_end - body), status, rflags, gzipped);
    Arena *a = &k->arena[k->ai];
    if ((umm)(body_end - a->base) > a->used) a->used = (umm)(body_end - a->base);
    conn_send(k, slot, start, (u32)(body_end - start));
}

internal inline u8 *resp_body(Core *k) { Arena *a = &k->arena[k->ai]; return a->base + a->used + RESP_HEADROOM; }

internal void respond_lit(Core *k, u32 slot, int status, const char *json, u32 rflags)
{
    u8 *b = resp_body(k);
    umm n = strlen(json);
    memcpy(b, json, n);
    respond(k, slot, status, b, b + n, rflags, 0);
}

internal void respond_error(Core *k, u32 slot, int status, const char *msg, u32 rflags)
{
    u8 *b = resp_body(k);
    u8 *o = b;
    memcpy(o, "{\"error\":\"", 10); o += 10;
    umm n = strlen(msg);
    memcpy(o, msg, n); o += n;
    memcpy(o, "\"}", 2); o += 2;
    respond(k, slot, status, b, o, rflags, 0);
}

internal void respond_degraded(Core *k, u32 slot, u32 rflags)
{
    u8 *b = resp_body(k);
    u8 *o = b;
    const char *pre = "{\"status\":\"degraded\",\"db\":\"unreachable\",\"error\":\"";
    memcpy(o, pre, strlen(pre)); o += strlen(pre);
    const char *e = k->last_db_error[0] ? k->last_db_error : "no database connection";
    o = write_json_str(o, (const u8 *)e, strlen(e));
    memcpy(o, "\"}", 2); o += 2;
    respond(k, slot, 503, b, o, rflags, 0);
}

// ---- Postgres plumbing ----
internal inline u32 pg_index(Core *k, PgConn *pc) { return (u32)(pc - k->pg); }

internal void pg_arm_recv(Core *k, PgConn *pc)
{
    struct io_uring_sqe *s = ring_sqe(&k->ring);
    s->opcode = IORING_OP_RECV;
    s->fd = (s32)pc->slot;
    s->flags = IOSQE_FIXED_FILE;
    s->addr = (u64)(uintptr_t)(pc->rbuf + pc->rlen);
    s->len = PG_RBUF - pc->rlen;
    s->user_data = UD(UD_PGRECV, pg_index(k, pc), pc->epoch);
}

internal void pg_kick_send(Core *k, PgConn *pc)
{
    if (pc->sending || pc->broken || pc->slen[pc->fill] == 0) return;
    u32 sb = pc->fill;
    pc->fill ^= 1;
    pc->slen[pc->fill] = 0;
    pc->send_idx = sb;
    pc->sent = 0;
    pc->sending = 1;
    sqe_send(k, pc->slot, pc->sbuf[sb], pc->slen[sb], MSG_NOSIGNAL, UD(UD_PGSEND, pg_index(k, pc), pc->epoch));
}

internal inline u32 pg_room(PgConn *pc) { return pc->scap - pc->slen[pc->fill]; }
internal inline u8 *pg_fill_ptr(PgConn *pc) { return pc->sbuf[pc->fill] + pc->slen[pc->fill]; }
internal inline u32 pg_qlen(PgConn *pc) { return pc->qtail - pc->qhead; }
internal inline Pend *pg_push(PgConn *pc) { return &pc->q[pc->qtail++ & (PEND_CAP - 1)]; }

internal void conn_pump(Core *k, u32 slot);

// The database answered this connection's request: let it continue with any buffered pipelined requests.
internal void conn_db_done(Core *k, u32 slot)
{
    Conn *c = &k->conns[slot];
    c->flags &= ~CF_BUSY;
    if (c->rblk) conn_pump(k, slot);
}

internal inline b32 pend_live(Core *k, Pend *e)
{
    Conn *c = &k->conns[e->slot];
    return c->gen == e->gen && (c->flags & CF_OPEN);
}

internal void pend_fail(Core *k, Pend *e)
{
    if (!pend_live(k, e)) return;
    if (e->kind == K_HEALTH) respond_degraded(k, e->slot, e->rflags);
    else respond_error(k, e->slot, 500, "internal server error", e->rflags);
    conn_db_done(k, e->slot);
}

internal void pg_fail(Core *k, PgConn *pc, const char *why)
{
    if (pc->broken) return;
    snprintf(k->last_db_error, sizeof(k->last_db_error), "%s", why);
    fprintf(stderr, "core %d: postgres connection %u lost: %s\n", k->id, pc->slot, why);
    for (u32 i = pc->qhead; i != pc->qtail; i++) {
        Pend *e = &pc->q[i & (PEND_CAP - 1)];
        if (e->kind != K_SYNC) pend_fail(k, e);
    }
    pc->qhead = pc->qcur = pc->qtail = 0;
    pc->slen[0] = pc->slen[1] = 0;
    pc->sending = 0;
    pc->unsynced = 0;
    pc->rlen = 0;
    pc->group_failed = 0;
    pc->broken = 1;
    pc->epoch++;
    pc->next_reconnect_ns = k->now_ns + 1000000000LL;
    ring_set_file(&k->ring, pc->slot, -1);
    if (pc->is_writer) {
        WBatch *a = &k->wb[k->wstage ^ 1];
        a->used = a->sused = a->n = 0;
        k->wb_inflight = 0;
    }
}

internal b32 pg_open(Core *k, PgConn *pc)
{
    char err[200];
    err[0] = 0;
    int fd = pg_connect(&db_config, &k->scram, err, sizeof(err));
    if (fd < 0) {
        snprintf(k->last_db_error, sizeof(k->last_db_error), "%s", err);
        pc->broken = 1;
        pc->next_reconnect_ns = k->now_ns + 1000000000LL;
        return 0;
    }
    if (ring_set_file(&k->ring, pc->slot, fd) < 0) {
        close(fd);
        snprintf(k->last_db_error, sizeof(k->last_db_error), "register postgres socket failed");
        pc->broken = 1;
        pc->next_reconnect_ns = k->now_ns + 1000000000LL;
        return 0;
    }
    close(fd); // the ring's file table holds the socket now
    pc->broken = 0;
    pc->epoch++;
    pc->rlen = 0;
    pc->slen[0] = pc->slen[1] = 0;
    pc->fill = 0;
    pc->sending = 0;
    pc->qhead = pc->qcur = pc->qtail = 0;
    pg_arm_recv(k, pc);
    return 1;
}

internal PgConn *pick_reader(Core *k, u32 need)
{
    PgConn *best = 0;
    u32 best_q = 0xFFFFFFFFu;
    for (u32 i = 0; i < k->nreaders; i++) {
        PgConn *pc = &k->pg[i];
        if (pc->broken || pg_room(pc) < need + 16 || pg_qlen(pc) >= PEND_CAP - 4) continue;
        u32 ql = pg_qlen(pc);
        if (ql < best_q) { best_q = ql; best = pc; }
    }
    return best;
}

internal void enqueue_read(Core *k, u32 slot, u8 kind, s64 id, u32 rflags)
{
    u32 need = kind == K_POST ? pg_tpl.post_len : (kind == K_FEED ? pg_tpl.feed_len : pg_tpl.health_len);
    PgConn *pc = pick_reader(k, need);
    if (!pc) {
        if (kind == K_HEALTH) respond_degraded(k, slot, rflags);
        else respond_error(k, slot, 500, "internal server error", rflags);
        return;
    }
    u8 *o = pg_fill_ptr(pc);
    if (kind == K_FEED) memcpy(o, pg_tpl.feed, pg_tpl.feed_len);
    else if (kind == K_HEALTH) memcpy(o, pg_tpl.health, pg_tpl.health_len);
    else {
        memcpy(o, pg_tpl.post, pg_tpl.post_len);
        store_be64(o + pg_tpl.post_id_off, (u64)id);
    }
    pc->slen[pc->fill] += need;
    Pend *e = pg_push(pc);
    memset(e, 0, sizeof(*e));
    e->slot = slot;
    e->gen = k->conns[slot].gen;
    e->kind = kind;
    e->rflags = (u8)rflags;
    e->id = id;
    pc->unsynced++;
    k->conns[slot].flags |= CF_BUSY;
}

internal void enqueue_write(Core *k, u32 slot, u8 kind, AuthUser *u, s64 post_id, Str body, u32 rflags)
{
    WBatch *b = &k->wb[k->wstage];
    PgConn *w = k->writer;
    if (w->broken || b->n >= WB_ENTRIES || b->used + body.count + 128 > WB_BYTES ||
        b->sused + u->username_len > WB_STRS) {
        respond_error(k, slot, 500, "internal server error", rflags);
        return;
    }
    Pend *e = &b->ents[b->n++];
    memset(e, 0, sizeof(*e));
    e->slot = slot;
    e->gen = k->conns[slot].gen;
    e->kind = kind;
    e->rflags = (u8)rflags;
    e->id = post_id;
    u8 uid[8];
    store_be64(uid, (u64)u->user_id);
    u8 *start = b->bytes + b->used;
    u8 *end;
    if (kind == K_NEWPOST) {
        Str params[2] = {{uid, 8}, body};
        end = pg_bind_exec(start, 'n', params, 2);
        e->body_off = (u32)((end - b->bytes) - 14 - body.count);
        e->body_len = (u32)body.count;
    } else {
        u8 pid[8];
        store_be64(pid, (u64)post_id);
        Str params[2] = {{uid, 8}, {pid, 8}};
        end = pg_bind_exec(start, 'l', params, 2);
    }
    e->msg_off = b->used;
    e->msg_len = (u32)(end - start);
    b->used += e->msg_len;
    e->uname_off = b->sused;
    e->uname_len = u->username_len;
    memcpy(b->strs + b->sused, u->username, u->username_len);
    b->sused += u->username_len;
    k->conns[slot].flags |= CF_BUSY;
}

// ---- results ----
typedef struct {
    const u8 *p;
    const u8 *end;
} RowIt;

internal inline b32 row_col(RowIt *r, const u8 **v, s32 *len)
{
    if (r->end - r->p < 4) return 0;
    *len = (s32)load_be32(r->p);
    r->p += 4;
    *v = r->p;
    if (*len > 0) {
        if (r->end - r->p < *len) return 0;
        r->p += *len;
    }
    return 1;
}

internal b32 parse_post_row(const u8 *b, u32 n, PostRow *row)
{
    if (n < 2 || load_be16(b) != 5) return 0;
    RowIt it = {b + 2, b + n};
    const u8 *v;
    s32 l;
    if (!row_col(&it, &v, &l) || l != 8) return 0;
    row->id = (s64)load_be64(v);
    if (!row_col(&it, &v, &l) || l < 0) return 0;
    row->body = v;
    row->body_len = (u32)l;
    if (!row_col(&it, &v, &l) || l != 8) return 0;
    row->ts = (s64)load_be64(v);
    if (!row_col(&it, &v, &l) || l < 0) return 0;
    row->author = v;
    row->author_len = (u32)l;
    if (!row_col(&it, &v, &l) || l != 4) return 0;
    row->likes = (s32)load_be32(v);
    return 1;
}

// Handles the messages of one finished statement (BindComplete, DataRows, then CommandComplete or ErrorResponse).
internal void pg_entry_done(Core *k, PgConn *pc, Pend *e, const u8 *p, u32 n)
{
    const u8 *end = p + n;
    b32 live = pend_live(k, e);
    if (e->kind == K_FEED) {
        if (!live) { e->state = PS_DONE; return; }
        u8 *json = resp_body(k);
        FeedW *fw = (FeedW *)arena_push_aligned(&k->arena[k->ai], sizeof(FeedW), 16);
        json = resp_body(k);
        feed_begin(fw, json);
        b32 bad = 0;
        for (const u8 *m = p; m < end;) {
            u8 t = m[0];
            u32 ml = load_be32(m + 1);
            if (t == 'D') {
                PostRow row;
                if (parse_post_row(m + 5, ml - 4, &row)) feed_post(fw, &row);
                else bad = 1;
            } else if (t == 'E') bad = 1;
            m += 1 + ml;
        }
        feed_end(fw);
        e->state = PS_DONE;
        if (bad) {
            respond_error(k, e->slot, 500, "internal server error", e->rflags);
        } else {
            u32 jl = (u32)(fw->o - json);
            Arena *a = &k->arena[k->ai];
            a->used = (umm)(fw->o - a->base);
            if ((e->rflags & RF_GZIP) && jl >= GZIP_MIN) {
                u8 *gz = resp_body(k);
                umm gl = gzip_compress(&k->dz, json, jl, fw->hints, fw->nh, gz);
                if (gl) respond(k, e->slot, 200, gz, gz + gl, e->rflags, 1);
                else respond(k, e->slot, 200, json, fw->o, e->rflags, 0);
            } else {
                respond(k, e->slot, 200, json, fw->o, e->rflags, 0);
            }
        }
        conn_db_done(k, e->slot);
        return;
    }
    if (e->kind == K_POST || e->kind == K_HEALTH) {
        e->state = PS_DONE;
        if (!live) return;
        b32 found = 0, bad = 0;
        PostRow row;
        for (const u8 *m = p; m < end;) {
            u8 t = m[0];
            u32 ml = load_be32(m + 1);
            if (t == 'D') {
                found = 1;
                if (e->kind == K_POST && !parse_post_row(m + 5, ml - 4, &row)) bad = 1;
            } else if (t == 'E') bad = 1;
            m += 1 + ml;
        }
        if (e->kind == K_HEALTH) {
            if (bad || !found) respond_degraded(k, e->slot, e->rflags);
            else {
                u8 *b = resp_body(k);
                u8 *o = b;
                memcpy(o, "{\"status\":\"ok\",\"db\":\"ok\",\"uptime_s\":", 36); o += 36;
                o = write_s64(o, (k->now_ns - cfg.start_ns) / 1000000000LL);
                *o++ = '}';
                respond(k, e->slot, 200, b, o, e->rflags, 0);
            }
        } else if (bad) {
            respond_error(k, e->slot, 500, "internal server error", e->rflags);
        } else if (!found) {
            respond_error(k, e->slot, 404, "post not found", e->rflags);
        } else {
            u8 *b = resp_body(k);
            u8 *o = b;
            memcpy(o, "{\"post\":", 8); o += 8;
            o = write_post_obj(o, &row);
            *o++ = '}';
            respond(k, e->slot, 200, b, o, e->rflags, 0);
        }
        conn_db_done(k, e->slot);
        return;
    }
    // writes: record now, answer after the commit (ReadyForQuery)
    e->state = PS_DONE;
    for (const u8 *m = p; m < end;) {
        u8 t = m[0];
        u32 ml = load_be32(m + 1);
        const u8 *b = m + 5;
        u32 bl = ml - 4;
        if (t == 'D' && e->kind == K_NEWPOST) {
            RowIt it = {b + 2, b + bl};
            const u8 *v;
            s32 l;
            if (bl >= 2 && load_be16(b) == 2 && row_col(&it, &v, &l) && l == 8) {
                e->r_id = (s64)load_be64(v);
                if (row_col(&it, &v, &l) && l == 8) e->r_ts = (s64)load_be64(v);
            }
        } else if (t == 'C' && e->kind == K_LIKE) {
            // "INSERT 0 <rows>"
            const u8 *q = b + bl;
            while (q > b && (q[-1] == 0)) q--;
            e->inserted = (q > b && q[-1] != '0');
        } else if (t == 'E') {
            e->state = PS_ERR;
            memset(e->sqlstate, 0, sizeof(e->sqlstate));
            for (u32 i = 0; i < bl && b[i];) {
                u8 f = b[i++];
                const char *v = (const char *)b + i;
                umm vl = strnlen(v, bl - i);
                if (f == 'C') memcpy(e->sqlstate, v, Min(vl, (umm)5));
                i += (u32)vl + 1;
            }
        }
        m += 1 + ml;
    }
    (void)pc;
}

internal void finish_write(Core *k, Pend *e, WBatch *b)
{
    if (!pend_live(k, e)) return;
    if (e->state != PS_DONE) {
        if (e->kind == K_LIKE && memcmp(e->sqlstate, "23503", 5) == 0)
            respond_error(k, e->slot, 404, "post not found", e->rflags);
        else
            respond_error(k, e->slot, 500, "internal server error", e->rflags);
    } else if (e->kind == K_NEWPOST) {
        u8 *body = resp_body(k);
        u8 *o = body;
        memcpy(o, "{\"post\":{\"id\":", 14); o += 14;
        o = write_s64(o, e->r_id);
        memcpy(o, ",\"body\":\"", 9); o += 9;
        o = write_json_str(o, b->bytes + e->body_off, e->body_len);
        memcpy(o, "\",\"created_at\":\"", 16); o += 16;
        o = write_timestamp(o, e->r_ts);
        memcpy(o, "\",\"author\":\"", 12); o += 12;
        o = write_json_str(o, b->strs + e->uname_off, e->uname_len);
        memcpy(o, "\",\"like_count\":0}}", 18); o += 18;
        respond(k, e->slot, 201, body, o, e->rflags, 0);
    } else {
        u8 *body = resp_body(k);
        u8 *o = body;
        if (e->inserted) { memcpy(o, "{\"liked\":true,\"already_liked\":false,\"post_id\":", 46); o += 46; }
        else { memcpy(o, "{\"liked\":true,\"already_liked\":true,\"post_id\":", 45); o += 45; }
        o = write_s64(o, e->id);
        *o++ = '}';
        respond(k, e->slot, e->inserted ? 201 : 200, body, o, e->rflags, 0);
    }
    conn_db_done(k, e->slot);
}

// A ReadyForQuery arrived: every statement since the previous Sync is final (committed, for writes).
internal void pg_group_end(Core *k, PgConn *pc)
{
    b32 failed = pc->group_failed;
    pc->group_failed = 0;
    u32 first = pc->qhead, sync = pc->qcur;
    u32 count = sync - first;
    if (pc->is_writer) {
        WBatch *b = &k->wb[k->wstage ^ 1];
        if (failed && count > 1) {
            // one statement failed and rolled back the rest: replay each on its own so each gets its own answer
            for (u32 i = first; i != sync; i++) {
                Pend *e = &pc->q[i & (PEND_CAP - 1)];
                Pend copy = *e;
                copy.state = PS_WAIT;
                u8 *o = pg_fill_ptr(pc);
                memcpy(o, b->bytes + copy.msg_off, copy.msg_len);
                o = pg_sync(o + copy.msg_len);
                pc->slen[pc->fill] += copy.msg_len + 5;
                *pg_push(pc) = copy;
                Pend *s = pg_push(pc);
                memset(s, 0, sizeof(*s));
                s->kind = K_SYNC;
            }
            pg_kick_send(k, pc);
        } else {
            for (u32 i = first; i != sync; i++) {
                Pend *e = &pc->q[i & (PEND_CAP - 1)];
                if (failed && e->state == PS_DONE) e->state = PS_ERR; // rolled back
                finish_write(k, e, b);
            }
        }
        pc->qhead = pc->qcur = sync + 1;
        if (pc->qhead == pc->qtail) {
            b->used = b->sused = b->n = 0;
            k->wb_inflight = 0;
        }
        return;
    }
    for (u32 i = first; i != sync; i++) {
        Pend *e = &pc->q[i & (PEND_CAP - 1)];
        if (e->state != PS_DONE) pend_fail(k, e);
    }
    pc->qhead = pc->qcur = sync + 1;
}

internal void pg_on_recv(Core *k, PgConn *pc, s32 res)
{
    if (res <= 0) {
        pg_fail(k, pc, res == 0 ? "server closed the connection" : strerror(-res));
        return;
    }
    pc->rlen += (u32)res;
    u32 off = 0;
    u8 *rb = pc->rbuf;
    for (;;) {
        u32 avail = pc->rlen - off;
        if (avail < 5) break;
        if (pc->qcur == pc->qtail) {
            // nothing outstanding: only asynchronous messages are acceptable here
            u8 t = rb[off];
            u32 ml = load_be32(rb + off + 1);
            if (avail < 1 + ml) break;
            if (t == 'N' || t == 'S' || t == 'A') { off += 1 + ml; continue; }
            pg_fail(k, pc, "protocol desync");
            return;
        }
        Pend *e = &pc->q[pc->qcur & (PEND_CAP - 1)];
        if (e->kind == K_SYNC) {
            u8 t = rb[off];
            u32 ml = load_be32(rb + off + 1);
            if (avail < 1 + ml) break;
            off += 1 + ml;
            if (t == 'Z') pg_group_end(k, pc);
            else if (t == 'E') pc->group_failed = 1;
            continue;
        }
        // find the message that ends this statement
        u32 j = off;
        u8 term = 0;
        while (pc->rlen - j >= 5) {
            u8 t = rb[j];
            u32 ml = load_be32(rb + j + 1);
            if (pc->rlen - j < 1 + ml) break;
            j += 1 + ml;
            if (t == 'C' || t == 'E' || t == 'I') { term = t; break; }
        }
        if (!term) break;
        pg_entry_done(k, pc, e, rb + off, j - off);
        off = j;
        if (term == 'E') {
            pc->group_failed = 1;
            if (!pc->is_writer && e->state != PS_DONE) e->state = PS_ERR;
            // Postgres skips everything up to the Sync: jump to the group's SYNC entry
            while (pc->q[pc->qcur & (PEND_CAP - 1)].kind != K_SYNC) pc->qcur++;
        } else {
            pc->qcur++;
        }
    }
    if (off) {
        memmove(rb, rb + off, pc->rlen - off);
        pc->rlen -= off;
    }
    if (pc->rlen >= PG_RBUF) {
        pg_fail(k, pc, "result too large");
        return;
    }
    if (!pc->broken) pg_arm_recv(k, pc);
}

internal void pg_on_send(Core *k, PgConn *pc, s32 res)
{
    if (res <= 0) {
        pg_fail(k, pc, res == 0 ? "send returned 0" : strerror(-res));
        return;
    }
    pc->sent += (u32)res;
    u32 sb = pc->send_idx;
    if (pc->sent < pc->slen[sb]) {
        sqe_send(k, pc->slot, pc->sbuf[sb] + pc->sent, pc->slen[sb] - pc->sent, MSG_NOSIGNAL,
                 UD(UD_PGSEND, pg_index(k, pc), pc->epoch));
        return;
    }
    pc->slen[sb] = 0;
    pc->sending = 0;
    pg_kick_send(k, pc);
}

internal void flush_pg(Core *k)
{
    for (u32 i = 0; i < k->nreaders; i++) {
        PgConn *pc = &k->pg[i];
        if (pc->broken) {
            if (k->now_ns >= pc->next_reconnect_ns) pg_open(k, pc);
            continue;
        }
        if (pc->unsynced) {
            pc->slen[pc->fill] = (u32)(pg_sync(pg_fill_ptr(pc)) - pc->sbuf[pc->fill]);
            Pend *s = pg_push(pc);
            memset(s, 0, sizeof(*s));
            s->kind = K_SYNC;
            pc->unsynced = 0;
        }
        pg_kick_send(k, pc);
    }
    PgConn *w = k->writer;
    if (w->broken) {
        if (k->now_ns >= w->next_reconnect_ns && pg_open(k, w)) k->wb_inflight = 0;
        if (w->broken) {
            // fail what is staged rather than holding it for a reconnect
            WBatch *b = &k->wb[k->wstage];
            for (u32 i = 0; i < b->n; i++) pend_fail(k, &b->ents[i]);
            b->n = b->used = b->sused = 0;
        }
        return;
    }
    WBatch *b = &k->wb[k->wstage];
    if (!k->wb_inflight && b->n) {
        // group commit: everything that queued up while the previous batch was committing, in one transaction
        if (pg_room(w) < b->used + 16) return;
        u8 *o = pg_fill_ptr(w);
        memcpy(o, b->bytes, b->used);
        o = pg_sync(o + b->used);
        w->slen[w->fill] = (u32)(o - w->sbuf[w->fill]);
        for (u32 i = 0; i < b->n; i++) *pg_push(w) = b->ents[i];
        Pend *s = pg_push(w);
        memset(s, 0, sizeof(*s));
        s->kind = K_SYNC;
        k->wstage ^= 1; // b is now the in-flight batch; the other one starts collecting
        WBatch *nb = &k->wb[k->wstage];
        nb->used = nb->sused = nb->n = 0;
        k->wb_inflight = 1;
        pg_kick_send(k, w);
    }
}

// ---- requests ----
internal b32 path_is(Str p, const char *lit)
{
    umm n = strlen(lit);
    return p.count == n && memcmp(p.data, lit, n) == 0;
}

internal int check_auth(Core *k, Request *req, AuthUser *u, u32 slot)
{
    if (!req->has_auth || req->auth.count < 7 || memcmp(req->auth.data, "Bearer ", 7) != 0) {
        respond_error(k, slot, 401, "missing bearer token", req->rflags);
        return 0;
    }
    Arena *a = &k->arena[k->ai];
    umm save = a->used;
    umm need = req->auth.count * 6 + 8192;
    if (arena_left(a) < need + RESP_HEADROOM + 4096) {
        respond_error(k, slot, 500, "internal server error", req->rflags);
        return 0;
    }
    u8 *scratch = (u8 *)arena_push(a, need);
    int r = jwt_verify(req->auth.data + 7, req->auth.count - 7, k->now_s, scratch, u);
    if (r != AUTH_OK) {
        a->used = save;
        respond_error(k, slot, 401, r == AUTH_PAYLOAD ? "invalid token payload" : "invalid or expired token",
                      req->rflags);
        return 0;
    }
    return 1; // u->username points into the scratch, which stays until the end of this iteration
}

internal void handle_request(Core *k, u32 slot, Request *req)
{
    Str path = req->path;
    u8 *q = memchr(path.data, '?', path.count);
    if (q) path.count = (umm)(q - path.data);
    u32 rf = req->rflags;
    if (req->method == M_GET) {
        if (path_is(path, "/feed")) { enqueue_read(k, slot, K_FEED, 0, rf); return; }
        if (path.count > 7 && memcmp(path.data, "/posts/", 7) == 0) {
            s64 id = 0;
            int r = parse_post_id(path.data + 7, path.count - 7, &id);
            if (r == ID_INVALID) respond_error(k, slot, 400, "invalid post id", rf);
            else if (r == ID_TOO_BIG) respond_error(k, slot, 404, "post not found", rf);
            else enqueue_read(k, slot, K_POST, id, rf);
            return;
        }
        if (path_is(path, "/health")) { enqueue_read(k, slot, K_HEALTH, 0, rf); return; }
        respond_error(k, slot, 404, "not found", rf);
        return;
    }
    if (req->method == M_POST) {
        if (path_is(path, "/posts")) {
            AuthUser u;
            if (!check_auth(k, req, &u, slot)) return;
            if (req->bad_length) { respond_error(k, slot, 400, "malformed JSON body", rf); return; }
            JField f[1] = {{S("body")}};
            Arena *a = &k->arena[k->ai];
            if (arena_left(a) < req->body.count + 65536) { respond_error(k, slot, 500, "internal server error", rf); return; }
            u8 *scratch = (u8 *)arena_push(a, req->body.count + 16);
            b32 obj;
            if (!json_extract(req->body.data, req->body.count, f, 1, scratch, &obj)) {
                respond_error(k, slot, 400, "malformed JSON body", rf);
                return;
            }
            if (!obj || f[0].kind != JF_STRING) { respond_error(k, slot, 400, "body is required", rf); return; }
            Str t = utf8_trim((Str){f[0].str, f[0].str_len});
            if (t.count == 0) { respond_error(k, slot, 400, "body is required", rf); return; }
            if (utf8_count(t.data, t.count) > 500) {
                respond_error(k, slot, 400, "body must be at most 500 characters", rf);
                return;
            }
            enqueue_write(k, slot, K_NEWPOST, &u, 0, t, rf);
            return;
        }
        if (path.count > 12 && memcmp(path.data, "/posts/", 7) == 0 &&
            memcmp(path.data + path.count - 5, "/like", 5) == 0) {
            AuthUser u;
            if (!check_auth(k, req, &u, slot)) return;
            s64 id = 0;
            int r = parse_post_id(path.data + 7, path.count - 12, &id);
            if (r == ID_INVALID) respond_error(k, slot, 400, "invalid post id", rf);
            else if (r == ID_TOO_BIG) respond_error(k, slot, 404, "post not found", rf);
            else enqueue_write(k, slot, K_LIKE, &u, id, (Str){0, 0}, rf);
            return;
        }
    }
    respond_error(k, slot, 404, "not found", rf);
}

// Parses and handles complete requests in [p, p+n) until the connection waits on the database. Returns bytes used.
internal umm parse_loop(Core *k, u32 slot, u8 *p, umm n)
{
    Conn *c = &k->conns[slot];
    u32 gen0 = c->gen;
    umm off = 0;
    while (off < n) {
        if (c->flags & CF_BUSY) break;
        Request req;
        req.expect_continue = 0;
        int r = http_parse(p + off, n - off, &req);
        if (r == 0) {
            if (req.expect_continue && !(c->flags & CF_CONTINUED)) {
                c->flags |= CF_CONTINUED;
                u8 *b = resp_body(k);
                memcpy(b, "HTTP/1.1 100 Continue\r\n\r\n", 25);
                k->arena[k->ai].used = (umm)(b + 25 - k->arena[k->ai].base);
                conn_send(k, slot, b, 25);
            }
            if (n - off > MAX_HEADER_BYTES + MAX_BODY_BYTES) {
                respond_error(k, slot, 400, "bad request", RF_CLOSE);
                return n;
            }
            break;
        }
        if (r < 0) {
            respond_error(k, slot, 400, "bad request", RF_CLOSE);
            return n;
        }
        c->flags &= ~CF_CONTINUED;
        handle_request(k, slot, &req);
        if (c->gen != gen0 || !(c->flags & CF_OPEN)) return n;
        off += req.total;
        if (req.rflags & RF_CLOSE) return n; // nothing after a closing request is read
    }
    return off;
}

internal void conn_pump(Core *k, u32 slot)
{
    Conn *c = &k->conns[slot];
    u16 blk = c->rblk;
    u8 *b = blk_ptr(k, blk);
    u32 gen0 = c->gen;
    umm used = parse_loop(k, slot, b, c->rlen);
    if (c->gen != gen0) return;
    if (used >= c->rlen) {
        blk_free(k, blk);
        c->rblk = 0;
        c->rlen = 0;
    } else if (used) {
        memmove(b, b + used, c->rlen - used);
        c->rlen -= (u32)used;
    }
}

internal void conn_on_data(Core *k, u32 slot, u8 *data, u32 n)
{
    Conn *c = &k->conns[slot];
    if (c->rblk) {
        if (c->rlen + n > POOL_BLOCK) {
            respond_error(k, slot, 400, "bad request", RF_CLOSE);
            return;
        }
        memcpy(blk_ptr(k, c->rblk) + c->rlen, data, n);
        c->rlen += n;
        if (!(c->flags & CF_BUSY)) conn_pump(k, slot);
        return;
    }
    u32 gen0 = c->gen;
    umm used = parse_loop(k, slot, data, n);
    if (c->gen != gen0 || used >= n) return;
    u16 blk = blk_alloc(k);
    if (!blk) { conn_close(k, slot); return; }
    c->rblk = blk;
    c->rlen = (u32)(n - used);
    memcpy(blk_ptr(k, blk), data + used, c->rlen);
}

// ---- completions ----
internal void on_accept(Core *k, struct io_uring_cqe *cqe)
{
    u32 li = UD_IDX(cqe->user_data);
    if (cqe->res >= 0) {
        u32 slot = (u32)cqe->res;
        if (slot >= k->nslots) {
            struct io_uring_sqe *s = ring_sqe(&k->ring);
            s->opcode = IORING_OP_CLOSE;
            s->file_index = slot + 1;
            s->user_data = UD(UD_CLOSE, 0, 0);
        } else {
            Conn *c = &k->conns[slot];
            u32 gen = c->gen + 1;
            memset(c, 0, sizeof(*c));
            c->gen = gen;
            c->flags = CF_OPEN;
            sqe_recv_multishot(k, slot);
        }
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) sqe_accept(k, (int)li);
}

internal void on_recv(Core *k, struct io_uring_cqe *cqe)
{
    u32 slot = UD_IDX(cqe->user_data);
    b32 has_buf = (cqe->flags & IORING_CQE_F_BUFFER) != 0;
    u16 bid = (u16)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    Conn *c = &k->conns[slot];
    b32 live = c->gen == UD_GEN(cqe->user_data) && (c->flags & CF_OPEN);
    if (live && !(cqe->flags & IORING_CQE_F_MORE)) c->flags &= ~CF_RECV_ARMED;
    if (live) {
        if (cqe->res > 0) {
            conn_on_data(k, slot, k->rb.bufs + (umm)bid * RBUF_SIZE, (u32)cqe->res);
        } else if (cqe->res == 0) {
            conn_close(k, slot);
        } else if (cqe->res != -ENOBUFS) {
            conn_close(k, slot);
        }
        if (c->gen == UD_GEN(cqe->user_data) && (c->flags & CF_OPEN) && !(c->flags & CF_RECV_ARMED))
            sqe_recv_multishot(k, slot);
    }
    if (has_buf) bufpool_put(&k->rb, bid);
}

internal void on_send_arena(Core *k, struct io_uring_cqe *cqe, u32 a)
{
    k->arena_out[a]--;
    u32 slot = UD_IDX(cqe->user_data);
    Conn *c = &k->conns[slot];
    if (c->gen != UD_GEN(cqe->user_data) || !(c->flags & CF_OPEN)) return;
    c->flags &= ~CF_SENDING;
    s32 res = cqe->res;
    if (res == (s32)c->a_len) {
        if (c->sblk && c->slen > c->soff) blk_send(k, slot);
        else if (c->flags & CF_CLOSE_AFTER) conn_close(k, slot);
        return;
    }
    if (res >= 0 || res == -EAGAIN) {
        u32 sent = res > 0 ? (u32)res : 0;
        if (!blk_prepend(k, c, k->arena[a].base + c->a_off + sent, c->a_len - sent)) {
            conn_close(k, slot);
            return;
        }
        blk_send(k, slot);
        return;
    }
    conn_close(k, slot);
}

internal void on_send_blk(Core *k, struct io_uring_cqe *cqe)
{
    u32 slot = UD_IDX(cqe->user_data);
    Conn *c = &k->conns[slot];
    if (c->gen != UD_GEN(cqe->user_data) || !(c->flags & CF_OPEN)) return;
    c->flags &= ~(CF_SENDING | CF_SEND_BLK);
    if (cqe->res <= 0) {
        if (cqe->res == -EAGAIN) { blk_send(k, slot); return; }
        conn_close(k, slot);
        return;
    }
    c->soff += (u32)cqe->res;
    if (c->soff < c->slen) { blk_send(k, slot); return; }
    blk_free(k, c->sblk);
    c->sblk = 0;
    c->soff = c->slen = 0;
    if (c->flags & CF_CLOSE_AFTER) conn_close(k, slot);
}

internal void handle_cqe(Core *k, struct io_uring_cqe *cqe, b32 from_defer)
{
    u32 t = UD_TYPE(cqe->user_data);
    switch (t) {
    case UD_SEND0: on_send_arena(k, cqe, 0); return;
    case UD_SEND1: on_send_arena(k, cqe, 1); return;
    case UD_SENDBLK: on_send_blk(k, cqe); return;
    case UD_PGSEND: {
        PgConn *pc = &k->pg[UD_IDX(cqe->user_data)];
        if (pc->epoch == UD_GEN(cqe->user_data) && !pc->broken) pg_on_send(k, pc, cqe->res);
        return;
    }
    case UD_CLOSE:
    case UD_CANCEL:
    case UD_MISC: return;
    }
    // work that produces output: hold it for the next iteration if this arena is nearly full
    if (arena_left(&k->arena[k->ai]) < ARENA_LOW && k->ndefer < DEFER_CAP) {
        k->defer[k->ndefer++] = *cqe;
        return;
    }
    (void)from_defer;
    switch (t) {
    case UD_ACCEPT: on_accept(k, cqe); return;
    case UD_RECV: on_recv(k, cqe); return;
    case UD_PGRECV: {
        PgConn *pc = &k->pg[UD_IDX(cqe->user_data)];
        if (pc->epoch == UD_GEN(cqe->user_data) && !pc->broken) pg_on_recv(k, pc, cqe->res);
        return;
    }
    }
}

internal void core_setup(Core *k)
{
    k->now_s = now_real_s();
    k->now_ns = now_mono_ns();
    // touch what the request path uses, so it never page-faults; conns and pool blocks fault in as used
    prefault(k->rb.bufs, (umm)cfg.nbufs * RBUF_SIZE);
    prefault(k->arena[0].base, ARENA_SIZE);
    prefault(k->arena[1].base, ARENA_SIZE);
    for (u32 i = 0; i <= k->nreaders; i++) {
        prefault(k->pg[i].sbuf[0], k->pg[i].scap);
        prefault(k->pg[i].sbuf[1], k->pg[i].scap);
        prefault(k->pg[i].rbuf, PG_RBUF);
    }
    for (u32 i = 0; i < POOL_BLOCKS; i++) k->pool_free[i] = (u16)(POOL_BLOCKS - 1 - i);
    k->pool_nfree = POOL_BLOCKS;
    ring_init(&k->ring, cfg.sq_entries, cfg.cq_entries);
    ring_register_sparse_files(&k->ring, k->nslots, RESERVED_SLOTS);
    bufpool_init(&k->ring, &k->rb, CLIENT_BGID, k->rb.bufs, cfg.nbufs, RBUF_SIZE, UD(UD_MISC, 0, 0));
    // Postgres first, so the listeners only open once queries can run
    for (u32 i = 0; i <= k->nreaders; i++) {
        PgConn *pc = &k->pg[i];
        if (!pg_open(k, pc)) fprintf(stderr, "core %d: postgres connect failed: %s\n", k->id, k->last_db_error);
    }
    sqe_accept(k, 0); // listeners were created in core order by the main thread (server_start)
    sqe_accept(k, 1);
}

internal void core_iterate(Core *k)
{
    u32 min_wait = k->ndefer ? 0 : cfg.batch_min;
    ring_submit_wait(&k->ring, min_wait, cfg.batch_us);
    k->now_s = now_real_s();
    k->now_ns = now_mono_ns();
    // ping-pong arenas: the other one is free once every send that points into it has completed
    u32 cand = k->ai ^ 1;
    if (k->arena_out[cand] == 0) {
        k->ai = cand;
        arena_reset(&k->arena[cand]);
    }
    if (k->ndefer) {
        static __thread struct io_uring_cqe local[4096];
        u32 n = Min(k->ndefer, (u32)4096);
        memcpy(local, k->defer, n * sizeof(struct io_uring_cqe));
        memmove(k->defer, k->defer + n, (k->ndefer - n) * sizeof(struct io_uring_cqe));
        k->ndefer -= n;
        for (u32 i = 0; i < n; i++) handle_cqe(k, &local[i], 1);
    }
    Ring *r = &k->ring;
    u32 head = *r->cq_khead;
    for (;;) {
        u32 tail = LoadAcquire32(r->cq_ktail);
        if (head == tail) break;
        while (head != tail) {
            struct io_uring_cqe cqe = r->cqes[head & r->cq_mask];
            head++;
            handle_cqe(k, &cqe, 0);
        }
        StoreRelease32(r->cq_khead, head);
    }
    bufpool_publish(&k->ring, &k->rb, UD(UD_MISC, 0, 0));
    flush_pg(k);
}

internal void *core_main(void *arg)
{
    Core *k = (Core *)arg;
    if (cfg.cpu_affinity) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cfg.cpus[k->id], &set);
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }
    core_setup(k);
    SERVING_BEGIN();
    __atomic_add_fetch(&g_ready, 1, __ATOMIC_RELEASE);
    while (!g_stop) core_iterate(k);
    return 0;
}
