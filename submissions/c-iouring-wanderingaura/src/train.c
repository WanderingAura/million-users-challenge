// train.c: `server --train`, the profile run for PGO (build.sh). It starts an in-process mock Postgres that speaks
// the wire protocol with canned binary rows, starts the real server against it, and drives it over loopback with
// the load generator's request mix (gzip feed, single posts, likes, new posts) plus the error paths.

typedef struct {
    int fd;
    u8 *in;
    u32 inlen, inoff;
    u8 *out;
    u32 outlen;
    Rng rng;
    s64 next_id;
    s64 ts;
    u8 pool[65536];
} Mock;

#define MOCK_IN (1u << 20)
#define MOCK_OUT (4u << 20)

internal b32 mock_fill(Mock *m, u32 need)
{
    while (m->inlen - m->inoff < need) {
        if (m->inoff) {
            memmove(m->in, m->in + m->inoff, m->inlen - m->inoff);
            m->inlen -= m->inoff;
            m->inoff = 0;
        }
        ssize_t r = recv(m->fd, m->in + m->inlen, MOCK_IN - m->inlen, 0);
        if (r <= 0) return 0;
        m->inlen += (u32)r;
    }
    return 1;
}

internal void mock_flush(Mock *m)
{
    u32 off = 0;
    while (off < m->outlen) {
        ssize_t w = send(m->fd, m->out + off, m->outlen - off, MSG_NOSIGNAL);
        if (w <= 0) break;
        off += (u32)w;
    }
    m->outlen = 0;
}

internal u8 *mock_msg(Mock *m, u8 type)
{
    if (m->outlen > MOCK_OUT - 65536) mock_flush(m);
    u8 *p = m->out + m->outlen;
    p[0] = type;
    return p;
}
internal void mock_end(Mock *m, u8 *start, u8 *end)
{
    store_be32(start + 1, (u32)(end - start - 1));
    m->outlen += (u32)(end - start);
}

internal void mock_simple(Mock *m, u8 type, const void *body, u32 n)
{
    u8 *s = mock_msg(m, type);
    if (n) memcpy(s + 5, body, n);
    mock_end(m, s, s + 5 + n);
}

internal void mock_post_row(Mock *m, PostRow *r)
{
    u8 *s = mock_msg(m, 'D');
    u8 *o = s + 5;
    store_be16(o, 5); o += 2;
    store_be32(o, 8); o += 4; store_be64(o, (u64)r->id); o += 8;
    store_be32(o, r->body_len); o += 4; memcpy(o, r->body, r->body_len); o += r->body_len;
    store_be32(o, 8); o += 4; store_be64(o, (u64)r->ts); o += 8;
    store_be32(o, r->author_len); o += 4; memcpy(o, r->author, r->author_len); o += r->author_len;
    store_be32(o, 4); o += 4; store_be32(o, (u32)r->likes); o += 4;
    mock_end(m, s, o);
}

internal void *mock_conn_main(void *arg)
{
    Mock *m = (Mock *)arg;
    // startup message
    if (!mock_fill(m, 4)) return 0;
    u32 len = load_be32(m->in + m->inoff);
    if (!mock_fill(m, len)) return 0;
    m->inoff += len;
    u8 ok[4] = {0, 0, 0, 0};
    mock_simple(m, 'R', ok, 4);
    mock_simple(m, 'Z', "I", 1);
    mock_flush(m);
    char stmt = 0;
    s64 p1 = 0, p2 = 0;
    b32 in_error = 0;
    u32 like_toggle = 0;
    for (;;) {
        if (!mock_fill(m, 5)) return 0;
        u8 t = m->in[m->inoff];
        u32 ml = load_be32(m->in + m->inoff + 1);
        if (!mock_fill(m, 1 + ml)) return 0;
        u8 *b = m->in + m->inoff + 5;
        u32 bl = ml - 4;
        m->inoff += 1 + ml;
        switch (t) {
        case 'Q': {
            u32 n = 1;
            for (u32 i = 0; i < bl; i++) n += b[i] == ';';
            for (u32 i = 0; i < n; i++) mock_simple(m, 'C', "SET", 4);
            mock_simple(m, 'Z', "I", 1);
            mock_flush(m);
        } break;
        case 'P': if (!in_error) mock_simple(m, '1', 0, 0); break;
        case 'B': {
            u8 *q = b;
            q += strlen((char *)q) + 1;          // portal
            stmt = (char)q[0];
            q += strlen((char *)q) + 1;          // statement
            u16 nf = load_be16(q); q += 2 + 2 * nf;
            u16 np = load_be16(q); q += 2;
            p1 = p2 = 0;
            for (u16 i = 0; i < np; i++) {
                s32 l = (s32)load_be32(q); q += 4;
                if (l == 8 && i == 0) p1 = (s64)load_be64(q);
                if (l == 8 && i == 1) p2 = (s64)load_be64(q);
                if (l > 0) q += l;
            }
            if (!in_error) mock_simple(m, '2', 0, 0);
        } break;
        case 'E': {
            if (in_error) break;
            PostRow rows[20];
            if (stmt == 'f') {
                s64 idb = m->next_id, tsb = m->ts;
                corpus_rows(&m->rng, rows, 20, m->pool, &idb, &tsb);
                for (int i = 0; i < 20; i++) mock_post_row(m, &rows[i]);
                mock_simple(m, 'C', "SELECT 20", 10);
            } else if (stmt == 'p') {
                if (p1 % 13 != 0) {
                    s64 idb = p1, tsb = m->ts;
                    corpus_rows(&m->rng, rows, 1, m->pool, &idb, &tsb);
                    mock_post_row(m, &rows[0]);
                    mock_simple(m, 'C', "SELECT 1", 9);
                } else mock_simple(m, 'C', "SELECT 0", 9);
            } else if (stmt == 'h') {
                u8 row[10];
                store_be16(row, 1);
                store_be32(row + 2, 4);
                store_be32(row + 6, 1);
                mock_simple(m, 'D', row, 10);
                mock_simple(m, 'C', "SELECT 1", 9);
            } else if (stmt == 'n') {
                u8 row[26];
                store_be16(row, 2);
                store_be32(row + 2, 8);
                store_be64(row + 6, (u64)(++m->next_id));
                store_be32(row + 14, 8);
                store_be64(row + 18, (u64)(m->ts += 1234567));
                mock_simple(m, 'D', row, 26);
                mock_simple(m, 'C', "INSERT 0 1", 11);
            } else if (stmt == 'l') {
                if (p2 % 101 == 0) {
                    const char err[] = "SERROR\0C23503\0Minsert or update violates foreign key constraint\0";
                    mock_simple(m, 'E', err, sizeof(err));
                    in_error = 1;
                } else {
                    mock_simple(m, 'C', (like_toggle++ & 1) ? "INSERT 0 1" : "INSERT 0 0", 11);
                }
            }
            (void)p1;
        } break;
        case 'S':
            in_error = 0;
            mock_simple(m, 'Z', "I", 1);
            mock_flush(m);
            break;
        case 'X': return 0;
        default: break;
        }
    }
}

internal void *mock_listener_main(void *arg)
{
    int lfd = (int)(intptr_t)arg;
    u64 seed = 1;
    for (;;) {
        int fd = accept(lfd, 0, 0);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        Mock *m = (Mock *)calloc(1, sizeof(Mock));
        m->fd = fd;
        m->in = (u8 *)malloc(MOCK_IN);
        m->out = (u8 *)malloc(MOCK_OUT);
        m->rng.s = 0x1234567ull + seed++ * 0x9E3779B97F4A7C15ull;
        m->next_id = 700000;
        m->ts = (s64)(1790000000LL - 946684800LL) * 1000000LL;
        pthread_t t;
        pthread_create(&t, 0, mock_conn_main, m);
        pthread_detach(t);
    }
    return 0;
}

// ---- client ----
typedef struct {
    int fd;
    u8 buf[262144];
    u32 len;
} TrainConn;

typedef struct {
    int port;
    int nconns;
    s64 deadline_ns;
    u64 seed;
    u64 requests;
    u64 statuses[6]; // 2xx, 400, 401, 404, 5xx, other
    u64 bytes;
    char tokens[64][512];
} TrainClient;

internal int train_dial(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((u16)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

internal void train_sign(char *out, const char *secret_unused, u32 uid, s64 exp, const char *name)
{
    (void)secret_unused;
    char payload[256];
    int pl = snprintf(payload, sizeof(payload), "{\"sub\":\"%u\",\"username\":\"%s\",\"iat\":%lld,\"exp\":%lld}", uid,
                      name, (long long)(exp - 3600), (long long)exp);
    umm o = 0;
    memcpy(out, jwt_ctx.std_header, jwt_ctx.std_header_len);
    o += jwt_ctx.std_header_len;
    out[o++] = '.';
    o += b64_encode((u8 *)out + o, (const u8 *)payload, (umm)pl, b64url_enc, 0);
    u8 mac[32];
    hmac_sha256_k(&jwt_ctx.key, out, o, mac);
    out[o++] = '.';
    o += b64_encode((u8 *)out + o, mac, 32, b64url_enc, 0);
    out[o] = 0;
}

// Reads one response; returns its status (0 on failure).
internal int train_read(TrainConn *c, u64 *bytes)
{
    for (;;) {
        s64 he = header_end_scalar(c->buf, c->len);
        if (he > 0) {
            int status = atoi((char *)c->buf + 9);
            u32 cl = 0;
            for (s64 i = 0; i + 16 < he; i++) {
                if (memcmp(c->buf + i, "\r\nContent-Length: ", 18) == 0) { cl = (u32)atoi((char *)c->buf + i + 18); break; }
            }
            if (status == 100) {
                memmove(c->buf, c->buf + he, c->len - (u32)he);
                c->len -= (u32)he;
                continue;
            }
            if (c->len >= (u32)he + cl) {
                u32 total = (u32)he + cl;
                *bytes += total;
                memmove(c->buf, c->buf + total, c->len - total);
                c->len -= total;
                return status;
            }
        }
        ssize_t r = recv(c->fd, c->buf + c->len, sizeof(c->buf) - c->len, 0);
        if (r <= 0) return 0;
        c->len += (u32)r;
    }
}

internal void *train_client_main(void *arg)
{
    TrainClient *tc = (TrainClient *)arg;
    TrainConn *conns = (TrainConn *)calloc((umm)tc->nconns, sizeof(TrainConn));
    for (int i = 0; i < tc->nconns; i++) {
        conns[i].fd = train_dial(tc->port + (i & 1));
        if (conns[i].fd < 0) { fprintf(stderr, "train: connect failed\n"); return 0; }
    }
    Rng r = {tc->seed};
    s64 now = now_real_s();
    for (int i = 0; i < 64; i++) {
        char name[64];
        snprintf(name, sizeof(name), "%s_%s_%d", corpus_adj[i % ArrayCount(corpus_adj)],
                 corpus_noun[(i * 7) % ArrayCount(corpus_noun)], i + 1);
        train_sign(tc->tokens[i], 0, (u32)(i + 1), now + 3600, name);
    }
    char expired[512], badsig[512];
    train_sign(expired, 0, 5, now - 10, "x");
    train_sign(badsig, 0, 5, now + 3600, "x");
    badsig[strlen(badsig) - 2] ^= 1;
    char req[4096], body[1024];
    while (now_mono_ns() < tc->deadline_ns) {
        for (int i = 0; i < tc->nconns; i++) {
            u32 roll = rng_range(&r, 0, 999);
            const char *tok = tc->tokens[rng_next(&r) % 64];
            int n;
            if (roll < 420) {
                n = snprintf(req, sizeof(req), "GET /feed HTTP/1.1\r\nHost: x\r\nUser-Agent: train\r\n%s\r\n",
                             roll < 400 ? "Accept-Encoding: gzip\r\n" : "");
            } else if (roll < 840) {
                n = snprintf(req, sizeof(req), "GET /posts/%u HTTP/1.1\r\nHost: x\r\nUser-Agent: train\r\n"
                                               "Accept-Encoding: gzip\r\n\r\n", rng_range(&r, 1, 600000));
            } else if (roll < 930) {
                n = snprintf(req, sizeof(req), "POST /posts/%u/like HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                                               "Content-Length: 0\r\n\r\n", rng_range(&r, 1, 600000), tok);
            } else if (roll < 955) {
                int bl = snprintf(body, sizeof(body), "{\"body\":\"user %u says hi at %lld (VU %u, iter %u)\"}",
                                  rng_range(&r, 1, 20000), (long long)now, rng_range(&r, 1, 99999), rng_range(&r, 1, 9));
                n = snprintf(req, sizeof(req), "POST /posts HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                                               "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", tok, bl, body);
            } else if (roll < 962) {
                n = snprintf(req, sizeof(req), "GET /health HTTP/1.1\r\nHost: x\r\n\r\n");
            } else if (roll < 970) {
                n = snprintf(req, sizeof(req), "GET /posts/abc HTTP/1.1\r\nHost: x\r\n\r\n");
            } else if (roll < 975) {
                n = snprintf(req, sizeof(req), "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n");
            } else if (roll < 982) {
                n = snprintf(req, sizeof(req), "POST /posts/7/like HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                                               "Content-Length: 0\r\n\r\n", (roll & 1) ? expired : badsig);
            } else if (roll < 988) {
                n = snprintf(req, sizeof(req), "POST /posts HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}");
            } else {
                const char *bodies[] = {"{bad json", "{\"body\":\"   \"}", "{\"body\":123}", "{}",
                                        "{\"body\":\"\\u00e9t\\u00e9 \\\"q\\\" \\n x\"}"};
                const char *bd = bodies[roll % 5];
                n = snprintf(req, sizeof(req), "POST /posts HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                                               "Content-Length: %zu\r\n\r\n%s", tok, strlen(bd), bd);
            }
            if (send(conns[i].fd, req, (umm)n, MSG_NOSIGNAL) != n) { fprintf(stderr, "train: send failed\n"); return 0; }
        }
        for (int i = 0; i < tc->nconns; i++) {
            int st = train_read(&conns[i], &tc->bytes);
            if (!st) { fprintf(stderr, "train: connection dropped\n"); return 0; }
            tc->requests++;
            int b = st < 300 ? 0 : st == 400 ? 1 : st == 401 ? 2 : st == 404 ? 3 : st >= 500 ? 4 : 5;
            tc->statuses[b]++;
        }
    }
    for (int i = 0; i < tc->nconns; i++) close(conns[i].fd);
    return 0;
}

internal int train_main(const char *secret)
{
    globals_init(secret);
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(lfd, 1024) < 0) die("train: mock listen");
    socklen_t al = sizeof(a);
    getsockname(lfd, (struct sockaddr *)&a, &al);
    char url[128];
    snprintf(url, sizeof(url), "postgres://train:train@127.0.0.1:%d/train", ntohs(a.sin_port));
    pthread_t mt;
    pthread_create(&mt, 0, mock_listener_main, (void *)(intptr_t)lfd);
    db_config_parse(&db_config, url);
    if (!getenv("THREADS")) setenv("THREADS", "2", 1);
    if (!getenv("DB_READ_CONNS")) setenv("DB_READ_CONNS", "8", 1);
    if (!getenv("PORT")) setenv("PORT", "39080", 1);
    if (!getenv("EXTRA_PORT")) setenv("EXTRA_PORT", "39081", 1);
    if (!getenv("HOST")) setenv("HOST", "127.0.0.1", 1);
    config_init();
    static pthread_t threads[MAX_CORES];
    server_start(threads);
    while (__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE) < cfg.threads) usleep(1000);
    int seconds = env_int("TRAIN_SECONDS", 4);
    int nclients = env_int("TRAIN_CLIENTS", 2);
    static TrainClient clients[8];
    pthread_t ct[8];
    if (nclients > 8) nclients = 8;
    for (int i = 0; i < nclients; i++) {
        clients[i].port = cfg.port;
        clients[i].nconns = 96;
        clients[i].deadline_ns = now_mono_ns() + (s64)seconds * 1000000000LL;
        clients[i].seed = 0xC0FFEEull + (u64)i * 7919;
        pthread_create(&ct[i], 0, train_client_main, &clients[i]);
    }
    u64 total = 0, st[6] = {0}, bytes = 0;
    for (int i = 0; i < nclients; i++) {
        pthread_join(ct[i], 0);
        total += clients[i].requests;
        bytes += clients[i].bytes;
        for (int j = 0; j < 6; j++) st[j] += clients[i].statuses[j];
    }
    g_stop = 1;
    for (int i = 0; i < cfg.threads; i++) pthread_join(threads[i], 0);
    fprintf(stderr, "train: %llu requests in %ds (2xx %llu, 400 %llu, 401 %llu, 404 %llu, 5xx %llu, other %llu), "
                    "%llu response bytes, alloc violations %d\n",
            (unsigned long long)total, seconds, (unsigned long long)st[0], (unsigned long long)st[1],
            (unsigned long long)st[2], (unsigned long long)st[3], (unsigned long long)st[4],
            (unsigned long long)st[5], (unsigned long long)bytes, g_alloc_violations);
    if (total == 0 || st[4] > total / 20) {
        fprintf(stderr, "train: the server did not answer properly\n");
        return 1;
    }
    return 0;
}
