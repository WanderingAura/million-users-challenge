// selftest.c: `server --selftest`. Checks the pieces that are easy to get subtly wrong: gzip output (decoded by an
// independent inflater below), CRC32, SIMD vs scalar scans, SHA-256/HMAC/PBKDF2 vectors, timestamps, JSON, JWT.

// ---- a small, strict inflater (after Mark Adler's puff.c) used only to check our gzip output ----
typedef struct {
    const u8 *in;
    umm inlen, inpos;
    u32 bitbuf, bitcnt;
    u8 *out;
    umm outcap, outpos;
} Inf;

typedef struct {
    s16 count[16];
    s16 symbol[320];
} InfHuff;

internal int inf_bits(Inf *s, int need)
{
    s64 val = s->bitbuf;
    while (s->bitcnt < (u32)need) {
        if (s->inpos >= s->inlen) return -1;
        val |= (s64)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = (u32)(val >> need);
    s->bitcnt -= (u32)need;
    return (int)(val & ((1L << need) - 1));
}

internal int inf_stored(Inf *s)
{
    s->bitbuf = 0;
    s->bitcnt = 0;
    if (s->inpos + 4 > s->inlen) return -1;
    u32 len = s->in[s->inpos] | ((u32)s->in[s->inpos + 1] << 8);
    u32 nlen = s->in[s->inpos + 2] | ((u32)s->in[s->inpos + 3] << 8);
    s->inpos += 4;
    if (len != (~nlen & 0xffff)) return -2;
    if (s->inpos + len > s->inlen || s->outpos + len > s->outcap) return -1;
    memcpy(s->out + s->outpos, s->in + s->inpos, len);
    s->inpos += len;
    s->outpos += len;
    return 0;
}

internal int inf_decode(Inf *s, const InfHuff *h)
{
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= 15; len++) {
        int b = inf_bits(s, 1);
        if (b < 0) return -10;
        code |= b;
        int count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -10;
}

internal int inf_construct(InfHuff *h, const s16 *length, int n)
{
    for (int len = 0; len <= 15; len++) h->count[len] = 0;
    for (int sym = 0; sym < n; sym++) h->count[length[sym]]++;
    if (h->count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len <= 15; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return left;
    }
    s16 offs[16];
    offs[1] = 0;
    for (int len = 1; len < 15; len++) offs[len + 1] = (s16)(offs[len] + h->count[len]);
    for (int sym = 0; sym < n; sym++)
        if (length[sym] != 0) h->symbol[offs[length[sym]]++] = (s16)sym;
    return left;
}

internal int inf_codes(Inf *s, const InfHuff *lencode, const InfHuff *distcode)
{
    for (;;) {
        int sym = inf_decode(s, lencode);
        if (sym < 0) return sym;
        if (sym < 256) {
            if (s->outpos >= s->outcap) return 1;
            s->out[s->outpos++] = (u8)sym;
        } else if (sym > 256) {
            sym -= 257;
            if (sym >= 29) return -10;
            int len = len_base[sym] + inf_bits(s, len_extra[sym]);
            int dsym = inf_decode(s, distcode);
            if (dsym < 0 || dsym >= 30) return -10;
            umm dist = dist_base[dsym] + (umm)inf_bits(s, dist_extra[dsym]);
            if (dist > s->outpos) return -11;
            if (s->outpos + (umm)len > s->outcap) return 1;
            while (len--) {
                s->out[s->outpos] = s->out[s->outpos - dist];
                s->outpos++;
            }
        } else return 0;
    }
}

internal int inf_fixed(Inf *s)
{
    static InfHuff lencode, distcode;
    static int virgin = 1;
    if (virgin) {
        s16 lengths[288];
        int sym = 0;
        for (; sym < 144; sym++) lengths[sym] = 8;
        for (; sym < 256; sym++) lengths[sym] = 9;
        for (; sym < 280; sym++) lengths[sym] = 7;
        for (; sym < 288; sym++) lengths[sym] = 8;
        inf_construct(&lencode, lengths, 288);
        for (sym = 0; sym < 30; sym++) lengths[sym] = 5;
        inf_construct(&distcode, lengths, 30);
        virgin = 0;
    }
    return inf_codes(s, &lencode, &distcode);
}

internal int inf_dynamic(Inf *s)
{
    static const s16 order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    s16 lengths[320];
    InfHuff lencode, distcode;
    int nlen = inf_bits(s, 5) + 257;
    int ndist = inf_bits(s, 5) + 1;
    int ncode = inf_bits(s, 4) + 4;
    if (nlen > 286 || ndist > 30) return -3;
    int index;
    for (index = 0; index < ncode; index++) lengths[order[index]] = (s16)inf_bits(s, 3);
    for (; index < 19; index++) lengths[order[index]] = 0;
    if (inf_construct(&lencode, lengths, 19) != 0) return -4;
    index = 0;
    while (index < nlen + ndist) {
        int symbol = inf_decode(s, &lencode);
        if (symbol < 0) return symbol;
        if (symbol < 16) lengths[index++] = (s16)symbol;
        else {
            int len = 0;
            if (symbol == 16) {
                if (index == 0) return -5;
                len = lengths[index - 1];
                symbol = 3 + inf_bits(s, 2);
            } else if (symbol == 17) symbol = 3 + inf_bits(s, 3);
            else symbol = 11 + inf_bits(s, 7);
            if (index + symbol > nlen + ndist) return -6;
            while (symbol--) lengths[index++] = (s16)len;
        }
    }
    if (lengths[256] == 0) return -9;
    int err = inf_construct(&lencode, lengths, nlen);
    if (err && (err < 0 || nlen != lencode.count[0] + lencode.count[1])) return -7;
    err = inf_construct(&distcode, lengths + nlen, ndist);
    if (err && (err < 0 || ndist != distcode.count[0] + distcode.count[1])) return -8;
    return inf_codes(s, &lencode, &distcode);
}

// Decodes a gzip member; returns the decoded length or -1.
internal s64 gunzip(const u8 *in, umm inlen, u8 *out, umm outcap)
{
    if (inlen < 18 || in[0] != 0x1f || in[1] != 0x8b || in[2] != 8 || in[3] != 0) return -1;
    Inf s = {in, inlen - 8, 10, 0, 0, out, outcap, 0};
    int last;
    do {
        last = inf_bits(&s, 1);
        int type = inf_bits(&s, 2);
        int err = type == 0 ? inf_stored(&s) : type == 1 ? inf_fixed(&s) : type == 2 ? inf_dynamic(&s) : -1;
        if (err != 0) return -1;
    } while (!last);
    if (s.inpos != inlen - 8) return -1;
    u32 crc = load_u32(in + inlen - 8), isize = load_u32(in + inlen - 4);
    if (crc != crc32_gzip_table(out, s.outpos) || isize != (u32)s.outpos) return -1;
    return (s64)s.outpos;
}

// ---- tests ----
global int st_failures;
#define CHECK(cond, ...) do { if (!(cond)) { st_failures++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)

internal void hex32(const u8 *d, char *out)
{
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", d[i]);
}

internal void test_crypto(void)
{
    u8 d[32];
    char h[65];
    sha256("abc", 3, d);
    hex32(d, h);
    CHECK(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0, "sha256(abc) %s", h);
    sha256("", 0, d);
    hex32(d, h);
    CHECK(strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0, "sha256() %s", h);
    const char *m56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(m56, strlen(m56), d);
    hex32(d, h);
    CHECK(strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0, "sha256(56) %s", h);
    hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, d);
    hex32(d, h);
    CHECK(strcmp(h, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0, "hmac %s", h);
    pbkdf2_sha256("password", 8, (const u8 *)"salt", 4, 1, d);
    hex32(d, h);
    CHECK(strcmp(h, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b") == 0, "pbkdf2 1 %s", h);
    pbkdf2_sha256("password", 8, (const u8 *)"salt", 4, 4096, d);
    hex32(d, h);
    CHECK(strcmp(h, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a") == 0, "pbkdf2 4096 %s", h);
}

internal void test_scans(Rng *r)
{
    static u8 buf[512];
    for (int iter = 0; iter < 200000; iter++) {
        u32 n = rng_range(r, 0, 300);
        u32 mode = rng_range(r, 0, 3);
        for (u32 i = 0; i < n; i++) {
            u32 x = rng_next(r);
            if (mode == 0) buf[i] = (u8)x;
            else if (mode == 1) buf[i] = (u8)(0x21 + x % 90);
            else if (mode == 2) buf[i] = (x % 50 == 0) ? (u8)"\"\\\n\r\x01\x80\xc3"[x % 7] : (u8)('a' + x % 26);
            else buf[i] = (x % 40 == 0) ? (u8)"\r\n"[x & 1] : (u8)('A' + x % 26);
        }
        CHECK(escape_scan(buf, n) == escape_scan_scalar(buf, n), "escape_scan n=%u", n);
        CHECK(ascii_scan(buf, n) == ascii_scan_scalar(buf, n), "ascii_scan n=%u", n);
        CHECK(header_end(buf, n) == header_end_scalar(buf, n), "header_end n=%u", n);
        if (st_failures > 10) return;
    }
    // CRC: PCLMUL path against the table on every length
    for (u32 n = 0; n < 2000; n++) {
        for (u32 i = 0; i < n; i++) buf[i % sizeof(buf)] = (u8)rng_next(r);
        static u8 big[4096];
        for (u32 i = 0; i < n; i++) big[i] = (u8)rng_next(r);
        CHECK(crc32_gzip(big, n) == crc32_gzip_table(big, n), "crc n=%u", n);
    }
    CHECK(crc32_gzip_table((const u8 *)"123456789", 9) == 0xCBF43926u, "crc check value");
}

internal void test_time(void)
{
    u8 o[32];
    // 2025-12-31T23:59:19.409Z plus 999 microseconds: truncated, not rounded
    s64 unix_ms = 1767225559409LL;
    s64 pg_us = (unix_ms - 946684800000LL) * 1000 + 999;
    write_timestamp(o, pg_us);
    o[24] = 0;
    CHECK(strcmp((char *)o, "2025-12-31T23:59:19.409Z") == 0, "ts %s", o);
    write_timestamp(o, 0);
    o[24] = 0;
    CHECK(strcmp((char *)o, "2000-01-01T00:00:00.000Z") == 0, "ts0 %s", o);
    write_timestamp(o, -1);
    o[24] = 0;
    CHECK(strcmp((char *)o, "1999-12-31T23:59:59.999Z") == 0, "ts-1 %s", o);
    // 2024-02-29 (leap day)
    write_timestamp(o, (1709164800000LL - 946684800000LL) * 1000 + 123456);
    o[24] = 0;
    CHECK(strcmp((char *)o, "2024-02-29T00:00:00.123Z") == 0, "leap %s", o);
    u8 *e = write_u64(o, 0);
    CHECK(e - o == 1 && o[0] == '0', "u64 0");
    e = write_s64(o, -9223372036854775807LL - 1);
    *e = 0;
    CHECK(strcmp((char *)o, "-9223372036854775808") == 0, "s64 min %s", o);
}

internal void test_json(void)
{
    u8 scratch[4096];
    JField f[1] = {{S("body")}};
    b32 obj;
    const char *cases_ok[] = {"{\"body\":\"x\"}", " { \"a\" : [1, 2.5e3, {\"b\":null}], \"body\" : \"y\" } ",
                              "{\"body\":\"\\u00e9\\ud83d\\ude00\"}", "{\"body\":1,\"body\":\"last\"}", "[]", "\"s\""};
    for (umm i = 0; i < ArrayCount(cases_ok); i++) {
        memset(f, 0, sizeof(f));
        f[0].key = S("body");
        CHECK(json_extract((const u8 *)cases_ok[i], strlen(cases_ok[i]), f, 1, scratch, &obj), "valid json %s",
              cases_ok[i]);
    }
    memset(f, 0, sizeof(f));
    f[0].key = S("body");
    json_extract((const u8 *)cases_ok[2], strlen(cases_ok[2]), f, 1, scratch, &obj);
    CHECK(f[0].kind == JF_STRING && f[0].str_len == 6 && memcmp(f[0].str, "\xc3\xa9\xf0\x9f\x98\x80", 6) == 0, "unicode");
    memset(f, 0, sizeof(f));
    f[0].key = S("body");
    json_extract((const u8 *)cases_ok[3], strlen(cases_ok[3]), f, 1, scratch, &obj);
    CHECK(f[0].kind == JF_STRING && f[0].str_len == 4, "duplicate key: last wins");
    const char *cases_bad[] = {"{bad json", "{\"body\":\"x\"", "{\"body\":\"x\"}x", "", "{\"a\":01}", "{\"a\":\"\x01\"}",
                               "{\"a\":tru}", "{\"a\":1,}", "{\"a\":\"\xff\"}", "{\"a\":\"\\x\"}"};
    for (umm i = 0; i < ArrayCount(cases_bad); i++) {
        memset(f, 0, sizeof(f));
        f[0].key = S("body");
        CHECK(!json_extract((const u8 *)cases_bad[i], strlen(cases_bad[i]), f, 1, scratch, &obj), "invalid json %s",
              cases_bad[i]);
    }
    Str t = utf8_trim(S("  \t caf\xc3\xa9 \xe2\x9c\x93 \xc2\xa0\n"));
    CHECK(t.count == 9 && memcmp(t.data, "caf\xc3\xa9 \xe2\x9c\x93", 9) == 0, "trim");
    CHECK(utf8_count((const u8 *)"caf\xc3\xa9", 5) == 4, "count");
    u8 out[64];
    u8 *e = write_json_str(out, (const u8 *)"a\"b\\c\nd\x01/", 9);
    *e = 0;
    CHECK(strcmp((char *)out, "a\\\"b\\\\c\\nd\\u0001/") == 0, "escape %s", out);
}

internal void test_jwt(void)
{
    char tok[512];
    s64 now = 1800000000;
    train_sign(tok, 0, 42, now + 100, "golden_ember_1");
    static u8 scratch[65536];
    AuthUser u;
    int r = jwt_verify((const u8 *)tok, strlen(tok), now, scratch, &u);
    CHECK(r == AUTH_OK && u.user_id == 42 && u.username_len == 14, "jwt ok %d", r);
    r = jwt_verify((const u8 *)tok, strlen(tok), now + 100, scratch, &u);
    CHECK(r == AUTH_INVALID, "jwt expired %d", r);
    tok[strlen(tok) - 3] ^= 1;
    r = jwt_verify((const u8 *)tok, strlen(tok), now, scratch, &u);
    CHECK(r == AUTH_INVALID, "jwt bad sig %d", r);
    r = jwt_verify((const u8 *)"abc", 3, now, scratch, &u);
    CHECK(r == AUTH_INVALID, "jwt garbage %d", r);
    // a token from the seed's generator format must verify against the challenge secret
}

internal void test_gzip(Rng *r)
{
    static u8 pool[1 << 20], json[1 << 20], gz[1 << 21], back[1 << 20];
    static Deflater dz;
    umm total_in = 0, total_out = 0;
    for (int iter = 0; iter < 3000; iter++) {
        PostRow rows[20];
        int n = (int)rng_range(r, 0, 20);
        s64 idb = 500000, tsb = (s64)(1767225600LL - 946684800LL) * 1000000LL;
        u32 mode = rng_range(r, 0, 3);
        if (mode == 0) {
            corpus_rows(r, rows, n, pool, &idb, &tsb);
        } else {
            u8 *o = pool;
            for (int i = 0; i < n; i++) {
                rows[i].id = rng_range(r, 1, 0x7fffffff);
                rows[i].ts = (s64)rng_next(r) * 1000;
                rows[i].likes = rng_range(r, 0, 100000);
                rows[i].body = o;
                u32 bl = rng_range(r, 0, 500);
                for (u32 j = 0; j < bl; j++) {
                    u32 x = rng_next(r);
                    if (mode == 1) *o++ = (u8)x;                                   // any byte, controls included
                    else if (mode == 2) *o++ = (u8)"ab\"\\\n \xc3\xa9\xe2\x9c\x93"[x % 11];
                    else *o++ = (u8)('a' + (x % 3));                              // long repeats
                }
                rows[i].body_len = bl;
                rows[i].author = o;
                u32 al = rng_range(r, 1, 40);
                for (u32 j = 0; j < al; j++) *o++ = (u8)('a' + rng_next(r) % 26);
                rows[i].author_len = al;
            }
        }
        FeedW fw;
        feed_begin(&fw, json);
        for (int i = 0; i < n; i++) feed_post(&fw, &rows[i]);
        feed_end(&fw);
        u32 jl = (u32)(fw.o - json);
        umm gl = gzip_compress(&dz, json, jl, fw.hints, fw.nh, gz);
        if (gl == 0) continue; // not smaller: sent uncompressed
        s64 bl = gunzip(gz, gl, back, sizeof(back));
        CHECK(bl == (s64)jl && memcmp(back, json, jl) == 0, "gzip roundtrip iter=%d mode=%u n=%d jl=%u gl=%zu bl=%lld",
              iter, mode, n, jl, gl, (long long)bl);
        if (mode == 0 && n == 20) { total_in += jl; total_out += gl; }
        if (st_failures > 10) return;
    }
    if (total_in) fprintf(stderr, "gzip: synthetic feeds %.1f%% of original size\n", 100.0 * total_out / total_in);
}

internal void test_http(void)
{
    Request q;
    const char *g = "GET /posts/5?x=1 HTTP/1.1\r\nHost: a\r\nAccept-Encoding: deflate, gzip\r\nAuthorization: Bearer t\r\n\r\n";
    CHECK(http_parse((const u8 *)g, strlen(g), &q) == 1 && q.method == M_GET && (q.rflags & RF_GZIP) && q.has_auth &&
          q.auth.count == 8 && q.total == strlen(g), "http get");
    const char *p = "POST /posts HTTP/1.1\r\ncontent-length: 5\r\n\r\nhel";
    CHECK(http_parse((const u8 *)p, strlen(p), &q) == 0, "http incomplete body");
    const char *p2 = "POST /posts HTTP/1.1\r\ncontent-length: 5\r\nConnection: close\r\n\r\nhello";
    CHECK(http_parse((const u8 *)p2, strlen(p2), &q) == 1 && q.body.count == 5 && (q.rflags & RF_CLOSE), "http body");
    s64 id;
    CHECK(parse_post_id((const u8 *)"0", 1, &id) == ID_INVALID, "id 0");
    CHECK(parse_post_id((const u8 *)"-1", 2, &id) == ID_INVALID, "id -1");
    CHECK(parse_post_id((const u8 *)"1.5", 3, &id) == ID_INVALID, "id 1.5");
    CHECK(parse_post_id((const u8 *)"abc", 3, &id) == ID_INVALID, "id abc");
    CHECK(parse_post_id((const u8 *)"250000", 6, &id) == ID_OK && id == 250000, "id ok");
    CHECK(parse_post_id((const u8 *)"99999999999999999999", 20, &id) == ID_TOO_BIG, "id big");
}

internal int selftest_main(void)
{
    globals_init("million-users-challenge");
    Rng r = {0xDEADBEEFCAFEull};
    test_crypto();
    test_scans(&r);
    test_time();
    test_json();
    test_jwt();
    test_http();
    test_gzip(&r);
    fprintf(stderr, "selftest (%s path): %s, %d failure(s)\n", FAST_X86 ? "AVX-512" : "scalar",
            st_failures ? "FAILED" : "ok", st_failures);
    return st_failures ? 1 : 0;
}

// ---- `server --bench`: user-space cost of the hot paths, in ns per operation ----
internal int bench_main(void)
{
    globals_init("million-users-challenge");
    static u8 pool[65536], json[65536], gz[131072], scratch[65536];
    static Deflater dz;
    Rng r = {42};
    PostRow rows[20];
    s64 idb = 500000, tsb = (s64)(1767225600LL - 946684800LL) * 1000000LL;
    corpus_rows(&r, rows, 20, pool, &idb, &tsb);
    volatile umm sink = 0;
    int iters = 200000;
    s64 t0 = now_mono_ns();
    for (int i = 0; i < iters; i++) {
        FeedW fw;
        feed_begin(&fw, json);
        for (int j = 0; j < 20; j++) feed_post(&fw, &rows[j]);
        feed_end(&fw);
        sink += (umm)(fw.o - json);
    }
    s64 t1 = now_mono_ns();
    FeedW fw;
    feed_begin(&fw, json);
    for (int j = 0; j < 20; j++) feed_post(&fw, &rows[j]);
    feed_end(&fw);
    u32 jl = (u32)(fw.o - json);
    umm gl = 0;
    for (int i = 0; i < iters; i++) gl = gzip_compress(&dz, json, jl, fw.hints, fw.nh, gz);
    s64 t2 = now_mono_ns();
    for (int i = 0; i < iters * 10; i++) sink += crc32_gzip(json, jl);
    s64 t3 = now_mono_ns();
    const char *req = "GET /feed HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: mload\r\nAccept-Encoding: gzip\r\n\r\n";
    Request q;
    for (int i = 0; i < iters * 10; i++) { http_parse((const u8 *)req, strlen(req), &q); sink += q.total; }
    s64 t4 = now_mono_ns();
    char tok[512];
    train_sign(tok, 0, 42, 1900000000, "golden_ember_1");
    AuthUser u;
    umm tl = strlen(tok);
    for (int i = 0; i < iters; i++) sink += (umm)jwt_verify((const u8 *)tok, tl, 1800000000, scratch, &u);
    s64 t5 = now_mono_ns();
    for (int i = 0; i < iters * 10; i++) { u8 *o = write_post_obj(json, &rows[i % 20]); sink += (umm)(o - json); }
    s64 t6 = now_mono_ns();
    fprintf(stderr, "bench (%s path): feed json %.0f ns (%u bytes), gzip %.0f ns (%zu bytes), crc32 %.0f ns, "
                    "http parse %.0f ns, jwt verify %.0f ns, post json %.0f ns\n",
            FAST_X86 ? "AVX-512" : "scalar", (f64)(t1 - t0) / iters, jl, (f64)(t2 - t1) / iters, gl,
            (f64)(t3 - t2) / (iters * 10), (f64)(t4 - t3) / (iters * 10), (f64)(t5 - t4) / iters,
            (f64)(t6 - t5) / (iters * 10));
    (void)sink;
    return 0;
}
