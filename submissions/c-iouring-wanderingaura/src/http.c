// http.c: HTTP/1.1 request parsing, response framing, and the JSON bodies for posts and the feed.

enum { M_OTHER = 0, M_GET, M_POST };

enum {
    RF_GZIP = 1,       // client accepts gzip
    RF_CLOSE = 2,      // close the connection after this response
    RF_KEEPALIVE10 = 4 // HTTP/1.0 client asked for keep-alive: say so in the response
};

typedef struct {
    u32 method;
    Str path;
    Str auth;
    b32 has_auth;
    u32 rflags;
    b32 expect_continue;
    b32 chunked;
    b32 bad_length;
    Str body;
    umm total; // bytes this request occupies in the stream
} Request;

#define MAX_HEADER_BYTES 16384
#define MAX_BODY_BYTES 65536

internal inline b32 ieq(const u8 *a, const char *lower, umm n)
{
    for (umm i = 0; i < n; i++) {
        u8 c = a[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c != (u8)lower[i]) return 0;
    }
    return 1;
}

internal b32 contains_token_ci(const u8 *p, umm n, const char *tok)
{
    umm tl = strlen(tok);
    for (umm i = 0; i + tl <= n; i++)
        if (ieq(p + i, tok, tl)) return 1;
    return 0;
}

// Returns 1 for a complete request, 0 if more bytes are needed, -1 for a malformed one.
internal int http_parse(const u8 *p, umm n, Request *r)
{
    s64 he = header_end(p, n);
    if (he < 0) return n > MAX_HEADER_BYTES ? -1 : 0;
    memset(r, 0, sizeof(*r));
    const u8 *end = p + he;
    // request line
    const u8 *sp1 = memchr(p, ' ', (umm)(end - p));
    if (!sp1) return -1;
    umm ml = (umm)(sp1 - p);
    if (ml == 3 && memcmp(p, "GET", 3) == 0) r->method = M_GET;
    else if (ml == 4 && memcmp(p, "POST", 4) == 0) r->method = M_POST;
    else r->method = M_OTHER;
    const u8 *path = sp1 + 1;
    const u8 *sp2 = memchr(path, ' ', (umm)(end - path));
    if (!sp2) return -1;
    r->path = (Str){(u8 *)path, (umm)(sp2 - path)};
    const u8 *eol = memchr(sp2, '\r', (umm)(end - sp2));
    if (!eol) return -1;
    b32 http10 = (eol - sp2 - 1 == 8) && memcmp(sp2 + 1, "HTTP/1.0", 8) == 0;
    b32 conn_close = 0, conn_keepalive = 0;
    u64 clen = 0;
    b32 has_clen = 0;
    const u8 *h = eol + 2;
    while (h < end - 2) {
        const u8 *le = memchr(h, '\r', (umm)(end - h));
        if (!le) break;
        const u8 *colon = memchr(h, ':', (umm)(le - h));
        if (colon) {
            umm nl = (umm)(colon - h);
            const u8 *v = colon + 1;
            while (v < le && (*v == ' ' || *v == '\t')) v++;
            const u8 *ve = le;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
            umm vl = (umm)(ve - v);
            switch (nl) {
            case 6:
                if (ieq(h, "expect", 6) && vl >= 12 && ieq(v, "100-continue", 12)) r->expect_continue = 1;
                break;
            case 10:
                if (ieq(h, "connection", 10)) {
                    if (contains_token_ci(v, vl, "close")) conn_close = 1;
                    if (contains_token_ci(v, vl, "keep-alive")) conn_keepalive = 1;
                }
                break;
            case 13:
                if (ieq(h, "authorization", 13)) {
                    r->auth = (Str){(u8 *)v, vl};
                    r->has_auth = 1;
                }
                break;
            case 14:
                if (ieq(h, "content-length", 14)) {
                    if (vl == 0 || vl > 9) { r->bad_length = 1; break; }
                    u64 x = 0;
                    for (umm i = 0; i < vl; i++) {
                        if (v[i] < '0' || v[i] > '9') { r->bad_length = 1; break; }
                        x = x * 10 + (v[i] - '0');
                    }
                    clen = x;
                    has_clen = 1;
                }
                break;
            case 15:
                if (ieq(h, "accept-encoding", 15) && contains_token_ci(v, vl, "gzip")) r->rflags |= RF_GZIP;
                break;
            case 17:
                if (ieq(h, "transfer-encoding", 17) && contains_token_ci(v, vl, "chunked")) r->chunked = 1;
                break;
            }
        }
        h = le + 2;
    }
    if (http10) {
        if (conn_keepalive && !conn_close) r->rflags |= RF_KEEPALIVE10;
        else r->rflags |= RF_CLOSE;
    } else if (conn_close) r->rflags |= RF_CLOSE;
    if (r->bad_length || r->chunked) {
        // We do not take chunked bodies (nothing sends them); answer and close.
        r->rflags |= RF_CLOSE;
        r->total = n;
        return 1;
    }
    if (has_clen && clen > MAX_BODY_BYTES) {
        r->bad_length = 1;
        r->rflags |= RF_CLOSE;
        r->total = n;
        return 1;
    }
    if ((u64)(n - (umm)he) < clen) return 0;
    r->body = (Str){(u8 *)end, (umm)clen};
    r->total = (umm)he + (umm)clen;
    return 1;
}

// ---- responses ----
#define RESP_HEADROOM 192

global const char *status_line[600];

internal void http_init(void)
{
    status_line[200] = "HTTP/1.1 200 OK\r\n";
    status_line[201] = "HTTP/1.1 201 Created\r\n";
    status_line[400] = "HTTP/1.1 400 Bad Request\r\n";
    status_line[401] = "HTTP/1.1 401 Unauthorized\r\n";
    status_line[404] = "HTTP/1.1 404 Not Found\r\n";
    status_line[500] = "HTTP/1.1 500 Internal Server Error\r\n";
    status_line[503] = "HTTP/1.1 503 Service Unavailable\r\n";
}

// Writes the header so that it ends exactly at `body`; returns where the response starts.
internal u8 *http_prepend_header(u8 *body, umm body_len, int status, u32 rflags, b32 gzipped)
{
    u8 tmp[RESP_HEADROOM];
    u8 *o = tmp;
    const char *sl = status_line[status];
    umm sll = strlen(sl);
    memcpy(o, sl, sll); o += sll;
    memcpy(o, "Content-Type: application/json\r\n", 32); o += 32;
    if (gzipped) { memcpy(o, "Content-Encoding: gzip\r\n", 24); o += 24; }
    if (rflags & RF_CLOSE) { memcpy(o, "Connection: close\r\n", 19); o += 19; }
    else if (rflags & RF_KEEPALIVE10) { memcpy(o, "Connection: keep-alive\r\n", 24); o += 24; }
    memcpy(o, "Content-Length: ", 16); o += 16;
    o = write_u64(o, body_len);
    memcpy(o, "\r\n\r\n", 4); o += 4;
    umm hl = (umm)(o - tmp);
    memcpy(body - hl, tmp, hl);
    return body - hl;
}

// ---- JSON bodies ----
typedef struct {
    s64 id;
    const u8 *body;
    u32 body_len;
    s64 ts;
    const u8 *author;
    u32 author_len;
    s64 likes;
} PostRow;

#define POST_JSON_MAX(r) (128 + JSON_STR_MAX((r)->body_len) + JSON_STR_MAX((r)->author_len))

internal u8 *write_post_obj(u8 *o, const PostRow *r)
{
    memcpy(o, "{\"id\":", 6); o += 6;
    o = write_s64(o, r->id);
    memcpy(o, ",\"body\":\"", 9); o += 9;
    o = write_json_str(o, r->body, r->body_len);
    memcpy(o, "\",\"created_at\":\"", 16); o += 16;
    o = write_timestamp(o, r->ts);
    memcpy(o, "\",\"author\":\"", 12); o += 12;
    o = write_json_str(o, r->author, r->author_len);
    memcpy(o, "\",\"like_count\":", 15); o += 15;
    o = write_s64(o, r->likes);
    *o++ = '}';
    return o;
}

// Feed writer: records where the constant fragments sit so the gzip writer can turn them into back-references.
enum { FRAG_BODY = 0, FRAG_TS, FRAG_AUTHOR, FRAG_LIKES, FRAG_SEP };
#define FEED_MAX_HINTS 128

typedef struct {
    u8 *start;
    u8 *o;
    Hint hints[FEED_MAX_HINTS];
    u32 nh;
    u32 count;
} FeedW;

internal inline void feed_frag(FeedW *f, const char *s, u16 len, u16 frag)
{
    if (f->nh < FEED_MAX_HINTS) {
        f->hints[f->nh].pos = (u32)(f->o - f->start);
        f->hints[f->nh].len = len;
        f->hints[f->nh].frag = frag;
        f->nh++;
    }
    memcpy(f->o, s, len);
    f->o += len;
}

internal void feed_begin(FeedW *f, u8 *out)
{
    f->start = f->o = out;
    f->nh = 0;
    f->count = 0;
}

internal void feed_post(FeedW *f, const PostRow *r)
{
    if (f->count == 0) {
        memcpy(f->o, "{\"posts\":[{\"id\":", 16);
        f->o += 16;
    } else {
        feed_frag(f, "},{\"id\":", 8, FRAG_SEP);
    }
    f->o = write_s64(f->o, r->id);
    feed_frag(f, ",\"body\":\"", 9, FRAG_BODY);
    f->o = write_json_str(f->o, r->body, r->body_len);
    feed_frag(f, "\",\"created_at\":\"", 16, FRAG_TS);
    f->o = write_timestamp(f->o, r->ts);
    feed_frag(f, "\",\"author\":\"", 12, FRAG_AUTHOR);
    f->o = write_json_str(f->o, r->author, r->author_len);
    feed_frag(f, "\",\"like_count\":", 15, FRAG_LIKES);
    f->o = write_s64(f->o, r->likes);
    f->count++;
}

internal void feed_end(FeedW *f)
{
    if (f->count == 0) {
        memcpy(f->o, "{\"posts\":[]}", 12);
        f->o += 12;
    } else {
        memcpy(f->o, "}]}", 3);
        f->o += 3;
    }
}

// ---- routing helpers ----
enum { ID_OK = 0, ID_INVALID, ID_TOO_BIG };

internal int parse_post_id(const u8 *p, umm n, s64 *out)
{
    if (n == 0) return ID_INVALID;
    u64 v = 0;
    for (umm i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return ID_INVALID;
        if (v > 922337203685477580ull) return ID_TOO_BIG;
        v = v * 10 + (p[i] - '0');
        if (v > 9223372036854775807ull) return ID_TOO_BIG;
    }
    if (v == 0) return ID_INVALID;
    *out = (s64)v;
    return ID_OK;
}
