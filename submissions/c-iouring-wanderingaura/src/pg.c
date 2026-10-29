// pg.c: Postgres v3 wire protocol. Connection setup is blocking (startup and reconnects only): startup message,
// trust / cleartext / SCRAM-SHA-256 auth, session SETs, and the five statements prepared once per connection.
// The request path only builds Bind/Execute/Sync bytes and parses binary results (loop.c).
#include <poll.h>

// The SPEC's SQL (rule 3), unchanged.
#define SQL_POST_COLS "SELECT p.id, p.body, p.created_at, u.username, " \
    "(SELECT count(*) FROM likes l WHERE l.post_id = p.id)::int AS like_count " \
    "FROM posts p JOIN users u ON u.id = p.user_id"
global const char *sql_feed = SQL_POST_COLS " ORDER BY p.created_at DESC, p.id DESC LIMIT 20";
global const char *sql_post = SQL_POST_COLS " WHERE p.id = $1";
global const char *sql_newpost = "INSERT INTO posts (user_id, body) VALUES ($1, $2) RETURNING id, created_at";
global const char *sql_like = "INSERT INTO likes (user_id, post_id) VALUES ($1, $2) ON CONFLICT (user_id, post_id) DO NOTHING";
global const char *sql_health = "SELECT 1";

typedef struct {
    char user[128];
    char password[256];
    char host[256];
    char port[16];
    char dbname[128];
} DbConfig;
global DbConfig db_config;

internal int url_unhex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
internal void url_copy(char *dst, umm cap, const char *s, umm n)
{
    umm o = 0;
    for (umm i = 0; i < n && o + 1 < cap; i++) {
        if (s[i] == '%' && i + 2 < n && url_unhex(s[i + 1]) >= 0 && url_unhex(s[i + 2]) >= 0) {
            dst[o++] = (char)(url_unhex(s[i + 1]) * 16 + url_unhex(s[i + 2]));
            i += 2;
        } else dst[o++] = s[i];
    }
    dst[o] = 0;
}

// postgres://user:pass@host:port/db?params
internal void db_config_parse(DbConfig *c, const char *url)
{
    memset(c, 0, sizeof(*c));
    strcpy(c->host, "localhost");
    strcpy(c->port, "5432");
    const char *p = strstr(url, "://");
    p = p ? p + 3 : url;
    const char *at = strrchr(p, '@');
    const char *slash = strchr(at ? at : p, '/');
    if (at) {
        const char *colon = memchr(p, ':', (umm)(at - p));
        if (colon) {
            url_copy(c->user, sizeof(c->user), p, (umm)(colon - p));
            url_copy(c->password, sizeof(c->password), colon + 1, (umm)(at - colon - 1));
        } else url_copy(c->user, sizeof(c->user), p, (umm)(at - p));
        p = at + 1;
    }
    const char *hend = slash ? slash : p + strlen(p);
    const char *q = memchr(p, '?', (umm)(hend - p));
    if (q) hend = q;
    const char *colon = memchr(p, ':', (umm)(hend - p));
    if (colon) {
        url_copy(c->host, sizeof(c->host), p, (umm)(colon - p));
        url_copy(c->port, sizeof(c->port), colon + 1, (umm)(hend - colon - 1));
    } else if (hend > p) url_copy(c->host, sizeof(c->host), p, (umm)(hend - p));
    if (slash) {
        const char *d = slash + 1;
        const char *dq = strchr(d, '?');
        url_copy(c->dbname, sizeof(c->dbname), d, dq ? (umm)(dq - d) : strlen(d));
    }
    if (!c->user[0]) {
        const char *u = getenv("USER");
        snprintf(c->user, sizeof(c->user), "%s", u ? u : "postgres");
    }
    if (!c->dbname[0]) snprintf(c->dbname, sizeof(c->dbname), "%s", c->user);
}

// ---- message builders ----
internal inline u8 *pg_sync(u8 *o)
{
    o[0] = 'S';
    store_be32(o + 1, 4);
    return o + 5;
}

// Bind (unnamed portal, statement `stmt`, every parameter and result in binary) + Execute.
internal u8 *pg_bind_exec(u8 *o, char stmt, const Str *params, int np)
{
    u8 *b = o;
    *o++ = 'B';
    o += 4;
    *o++ = 0;          // portal ""
    *o++ = (u8)stmt;   // statement name (one letter)
    *o++ = 0;
    store_be16(o, np ? 1 : 0); o += 2;
    if (np) { store_be16(o, 1); o += 2; }
    store_be16(o, (u16)np); o += 2;
    for (int i = 0; i < np; i++) {
        store_be32(o, (u32)params[i].count); o += 4;
        memcpy(o, params[i].data, params[i].count); o += params[i].count;
    }
    store_be16(o, 1); o += 2;
    store_be16(o, 1); o += 2;
    store_be32(b + 1, (u32)(o - b - 1));
    *o++ = 'E';
    store_be32(o, 9); o += 4;
    *o++ = 0;
    store_be32(o, 0); o += 4;
    return o;
}

// Prebuilt read messages: the feed and health ones never change; the post one gets its id patched in.
typedef struct {
    u8 feed[32];
    u32 feed_len;
    u8 health[32];
    u32 health_len;
    u8 post[48];
    u32 post_len;
    u32 post_id_off;
} PgTemplates;
global PgTemplates pg_tpl;

internal void pg_templates_init(void)
{
    pg_tpl.feed_len = (u32)(pg_bind_exec(pg_tpl.feed, 'f', 0, 0) - pg_tpl.feed);
    pg_tpl.health_len = (u32)(pg_bind_exec(pg_tpl.health, 'h', 0, 0) - pg_tpl.health);
    u8 marker[8] = {0xA5, 0x5A, 0xC3, 0x3C, 0x96, 0x69, 0xF0, 0x0F};
    Str p = {marker, 8};
    pg_tpl.post_len = (u32)(pg_bind_exec(pg_tpl.post, 'p', &p, 1) - pg_tpl.post);
    for (u32 i = 0; i + 8 <= pg_tpl.post_len; i++)
        if (memcmp(pg_tpl.post + i, marker, 8) == 0) { pg_tpl.post_id_off = i; break; }
    Assert(pg_tpl.post_id_off);
}

// ---- blocking connection setup ----
typedef struct {
    int fd;
    u8 buf[65536];
    u32 len, off;
} PgSync;

typedef struct {
    u8 salt[128];
    u32 salt_len;
    u32 iters;
    u8 salted[32];
    b32 valid;
} ScramCache; // SaltedPassword for this role's salt: a key derivation, reused across this core's connections

internal b32 pgs_write(PgSync *s, const u8 *p, umm n)
{
    while (n) {
        ssize_t w = send(s->fd, p, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        p += w;
        n -= (umm)w;
    }
    return 1;
}

// Reads one message. Returns its type (0 on failure); *body/*blen point into the buffer.
internal u8 pgs_read(PgSync *s, u8 **body, u32 *blen)
{
    for (;;) {
        if (s->len - s->off >= 5) {
            u32 ml = load_be32(s->buf + s->off + 1);
            if (ml < 4 || ml > sizeof(s->buf) - 1) return 0;
            if (s->len - s->off >= 1 + ml) {
                u8 t = s->buf[s->off];
                *body = s->buf + s->off + 5;
                *blen = ml - 4;
                s->off += 1 + ml;
                return t;
            }
        }
        if (s->off) {
            memmove(s->buf, s->buf + s->off, s->len - s->off);
            s->len -= s->off;
            s->off = 0;
        }
        ssize_t r = recv(s->fd, s->buf + s->len, sizeof(s->buf) - s->len, 0);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return 0;
        }
        s->len += (u32)r;
    }
}

internal void pg_error_text(const u8 *b, u32 n, char *out, umm cap)
{
    // fields: type byte + cstring; 'M' is the message
    out[0] = 0;
    u32 i = 0;
    while (i < n && b[i]) {
        u8 f = b[i++];
        const char *v = (const char *)b + i;
        umm vl = strnlen(v, n - i);
        if (f == 'M') snprintf(out, cap, "%.*s", (int)vl, v);
        i += (u32)vl + 1;
    }
    if (!out[0]) snprintf(out, cap, "error");
}

internal s64 b64std_decode(u8 *o, const char *s, umm n)
{
    s8 dec[256];
    memset(dec, -1, sizeof(dec));
    for (int i = 0; i < 64; i++) dec[(u8)b64std_enc[i]] = (s8)i;
    u8 *start = o;
    u32 acc = 0;
    int bits = 0;
    for (umm i = 0; i < n; i++) {
        if (s[i] == '=') break;
        s8 v = dec[(u8)s[i]];
        if (v < 0) return -1;
        acc = (acc << 6) | (u32)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            *o++ = (u8)(acc >> bits);
        }
    }
    return (s64)(o - start);
}

internal int tcp_connect(const char *host, const char *port, int timeout_ms)
{
    struct addrinfo hints, *res = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) continue;
        int r = connect(fd, a->ai_addr, a->ai_addrlen);
        if (r < 0 && errno == EINPROGRESS) {
            struct pollfd pf = {fd, POLLOUT, 0};
            if (poll(&pf, 1, timeout_ms) == 1) {
                int err = 0;
                socklen_t el = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                r = err ? -1 : 0;
            } else r = -1;
        }
        if (r == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

internal b32 pg_scram(PgSync *s, const DbConfig *cfg, ScramCache *cache, char *err, umm errcap)
{
    u8 rnd[18];
    if (getrandom(rnd, sizeof(rnd), 0) != (ssize_t)sizeof(rnd)) {
        for (int i = 0; i < 18; i++) rnd[i] = (u8)(now_mono_ns() >> (i % 8));
    }
    char nonce[32];
    umm nl = b64_encode((u8 *)nonce, rnd, sizeof(rnd), b64std_enc, 1);
    nonce[nl] = 0;
    char first_bare[128];
    int fbl = snprintf(first_bare, sizeof(first_bare), "n=,r=%s", nonce);
    // SASLInitialResponse
    u8 msg[512];
    u8 *o = msg;
    *o++ = 'p';
    o += 4;
    memcpy(o, "SCRAM-SHA-256", 14); o += 14;
    u32 cfl = 3 + (u32)fbl;
    store_be32(o, cfl); o += 4;
    memcpy(o, "n,,", 3); o += 3;
    memcpy(o, first_bare, (umm)fbl); o += fbl;
    store_be32(msg + 1, (u32)(o - msg - 1));
    if (!pgs_write(s, msg, (umm)(o - msg))) { snprintf(err, errcap, "write failed"); return 0; }
    u8 *b;
    u32 bl;
    u8 t = pgs_read(s, &b, &bl);
    if (t == 'E') { pg_error_text(b, bl, err, errcap); return 0; }
    if (t != 'R' || bl < 4 || load_be32(b) != 11) { snprintf(err, errcap, "unexpected SASL reply"); return 0; }
    char server_first[512];
    umm sfl = Min(bl - 4, sizeof(server_first) - 1);
    memcpy(server_first, b + 4, sfl);
    server_first[sfl] = 0;
    const char *r = strstr(server_first, "r=");
    const char *sp = strstr(server_first, ",s=");
    const char *ip = strstr(server_first, ",i=");
    if (!r || !sp || !ip) { snprintf(err, errcap, "bad server-first"); return 0; }
    const char *rend = strchr(r, ',');
    char snonce[256];
    snprintf(snonce, sizeof(snonce), "%.*s", (int)(rend - r - 2), r + 2);
    const char *send_ = strchr(sp + 3, ',');
    u8 salt[128];
    s64 saltl = b64std_decode(salt, sp + 3, send_ ? (umm)(send_ - sp - 3) : strlen(sp + 3));
    u32 iters = (u32)strtoul(ip + 3, 0, 10);
    if (saltl <= 0 || saltl > 120 || !iters) { snprintf(err, errcap, "bad salt"); return 0; }
    u8 salted[32];
    if (cache->valid && cache->iters == iters && cache->salt_len == (u32)saltl && memcmp(cache->salt, salt, (umm)saltl) == 0) {
        memcpy(salted, cache->salted, 32);
    } else {
        pbkdf2_sha256(cfg->password, strlen(cfg->password), salt, (umm)saltl, iters, salted);
        memcpy(cache->salt, salt, (umm)saltl);
        cache->salt_len = (u32)saltl;
        cache->iters = iters;
        memcpy(cache->salted, salted, 32);
        cache->valid = 1;
    }
    u8 client_key[32], stored_key[32], client_sig[32], proof[32];
    hmac_sha256(salted, 32, "Client Key", 10, client_key);
    sha256(client_key, 32, stored_key);
    char final_wo[300];
    int fwl = snprintf(final_wo, sizeof(final_wo), "c=biws,r=%s", snonce);
    char auth_msg[1200];
    int aml = snprintf(auth_msg, sizeof(auth_msg), "%s,%s,%s", first_bare, server_first, final_wo);
    hmac_sha256(stored_key, 32, auth_msg, (umm)aml, client_sig);
    for (int i = 0; i < 32; i++) proof[i] = client_key[i] ^ client_sig[i];
    char proof64[64];
    umm pl = b64_encode((u8 *)proof64, proof, 32, b64std_enc, 1);
    o = msg;
    *o++ = 'p';
    o += 4;
    memcpy(o, final_wo, (umm)fwl); o += fwl;
    memcpy(o, ",p=", 3); o += 3;
    memcpy(o, proof64, pl); o += pl;
    store_be32(msg + 1, (u32)(o - msg - 1));
    if (!pgs_write(s, msg, (umm)(o - msg))) { snprintf(err, errcap, "write failed"); return 0; }
    t = pgs_read(s, &b, &bl);
    if (t == 'E') { pg_error_text(b, bl, err, errcap); return 0; }
    if (t != 'R' || bl < 4 || load_be32(b) != 12) { snprintf(err, errcap, "unexpected SASL final"); return 0; }
    return 1;
}

internal u8 *pg_put_parse(u8 *o, char name, const char *sql, const u32 *oids, int n)
{
    u8 *b = o;
    *o++ = 'P';
    o += 4;
    *o++ = (u8)name;
    *o++ = 0;
    umm l = strlen(sql);
    memcpy(o, sql, l + 1); o += l + 1;
    store_be16(o, (u16)n); o += 2;
    for (int i = 0; i < n; i++) { store_be32(o, oids[i]); o += 4; }
    store_be32(b + 1, (u32)(o - b - 1));
    return o;
}

// Opens one connection, authenticates, sets session options and prepares the statements. Returns the fd or -1.
internal int pg_connect(const DbConfig *cfg, ScramCache *cache, char *err, umm errcap)
{
    static __thread PgSync s; // per thread, startup/reconnect only
    s.len = s.off = 0;
    s.fd = tcp_connect(cfg->host, cfg->port, 3000);
    if (s.fd < 0) { snprintf(err, errcap, "connect to %s:%s failed: %s", cfg->host, cfg->port, strerror(errno)); return -1; }
    u8 msg[1024];
    u8 *o = msg + 4;
    store_be32(o, 196608); o += 4;
#define PUTS(str) do { umm l_ = strlen(str); memcpy(o, str, l_ + 1); o += l_ + 1; } while (0)
    PUTS("user"); PUTS(cfg->user);
    PUTS("database"); PUTS(cfg->dbname);
    PUTS("client_encoding"); PUTS("UTF8");
    PUTS("application_name"); PUTS("c-iouring");
#undef PUTS
    *o++ = 0;
    store_be32(msg, (u32)(o - msg));
    if (!pgs_write(&s, msg, (umm)(o - msg))) goto fail_io;
    for (;;) {
        u8 *b;
        u32 bl;
        u8 t = pgs_read(&s, &b, &bl);
        if (!t) goto fail_io;
        if (t == 'E') { pg_error_text(b, bl, err, errcap); goto fail; }
        if (t == 'R') {
            u32 code = bl >= 4 ? load_be32(b) : 99;
            if (code == 0) continue;
            if (code == 3) {
                o = msg;
                *o++ = 'p';
                o += 4;
                umm l = strlen(cfg->password);
                memcpy(o, cfg->password, l + 1); o += l + 1;
                store_be32(msg + 1, (u32)(o - msg - 1));
                if (!pgs_write(&s, msg, (umm)(o - msg))) goto fail_io;
                continue;
            }
            if (code == 10) {
                if (!pg_scram(&s, cfg, cache, err, errcap)) goto fail;
                continue;
            }
            snprintf(err, errcap, "unsupported auth method %u", code);
            goto fail;
        }
        if (t == 'Z') break;
    }
    // session settings + prepared statements, one round trip
    o = msg;
    const char *setq = "SET plan_cache_mode = force_generic_plan; SET jit = off";
    *o++ = 'Q';
    store_be32(o, (u32)(4 + strlen(setq) + 1)); o += 4;
    memcpy(o, setq, strlen(setq) + 1); o += strlen(setq) + 1;
    {
        static const u32 oid_int8[1] = {20};
        static const u32 oid_int8_text[2] = {20, 25};
        static const u32 oid_int8_int8[2] = {20, 20};
        static u8 big[4096];
        u8 *q = big;
        memcpy(q, msg, (umm)(o - msg)); q += o - msg;
        q = pg_put_parse(q, 'f', sql_feed, 0, 0);
        q = pg_put_parse(q, 'p', sql_post, oid_int8, 1);
        q = pg_put_parse(q, 'n', sql_newpost, oid_int8_text, 2);
        q = pg_put_parse(q, 'l', sql_like, oid_int8_int8, 2);
        q = pg_put_parse(q, 'h', sql_health, 0, 0);
        q = pg_sync(q);
        if (!pgs_write(&s, big, (umm)(q - big))) goto fail_io;
    }
    int ready = 0;
    while (ready < 2) { // one Z for the simple query, one for the Sync
        u8 *b;
        u32 bl;
        u8 t = pgs_read(&s, &b, &bl);
        if (!t) goto fail_io;
        if (t == 'E') { pg_error_text(b, bl, err, errcap); goto fail; }
        if (t == 'Z') ready++;
    }
    {
        struct timeval tv = {0, 0};
        setsockopt(s.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    return s.fd;
fail_io:
    if (!err[0]) snprintf(err, errcap, "i/o error talking to postgres: %s", strerror(errno));
fail:
    close(s.fd);
    return -1;
}
