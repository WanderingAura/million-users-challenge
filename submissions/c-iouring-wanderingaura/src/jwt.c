// jwt.c: HS256 verification, in full, on every request (rule 9). The HMAC key schedule is computed once.

global s8 b64url_dec[256];
global const char b64url_enc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
global const char b64std_enc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct {
    HmacKey key;
    u8 std_header[64]; // base64url of {"alg":"HS256","typ":"JWT"}: the header every client sends
    umm std_header_len;
} JwtCtx;
global JwtCtx jwt_ctx;

internal umm b64_encode(u8 *o, const u8 *p, umm n, const char *alphabet, b32 pad)
{
    u8 *start = o;
    umm i = 0;
    for (; i + 3 <= n; i += 3) {
        u32 v = ((u32)p[i] << 16) | ((u32)p[i + 1] << 8) | p[i + 2];
        *o++ = (u8)alphabet[v >> 18];
        *o++ = (u8)alphabet[(v >> 12) & 63];
        *o++ = (u8)alphabet[(v >> 6) & 63];
        *o++ = (u8)alphabet[v & 63];
    }
    if (n - i == 1) {
        u32 v = (u32)p[i] << 16;
        *o++ = (u8)alphabet[v >> 18];
        *o++ = (u8)alphabet[(v >> 12) & 63];
        if (pad) { *o++ = '='; *o++ = '='; }
    } else if (n - i == 2) {
        u32 v = ((u32)p[i] << 16) | ((u32)p[i + 1] << 8);
        *o++ = (u8)alphabet[v >> 18];
        *o++ = (u8)alphabet[(v >> 12) & 63];
        *o++ = (u8)alphabet[(v >> 6) & 63];
        if (pad) *o++ = '=';
    }
    return (umm)(o - start);
}

// Decodes unpadded base64url. Returns the decoded length, or -1.
internal s64 b64url_decode(u8 *o, const u8 *p, umm n)
{
    while (n && p[n - 1] == '=') n--;
    if (n % 4 == 1) return -1;
    u8 *start = o;
    umm i = 0;
    for (; i + 4 <= n; i += 4) {
        s32 a = b64url_dec[p[i]], b = b64url_dec[p[i + 1]], c = b64url_dec[p[i + 2]], d = b64url_dec[p[i + 3]];
        if ((a | b | c | d) < 0) return -1;
        u32 v = ((u32)a << 18) | ((u32)b << 12) | ((u32)c << 6) | (u32)d;
        *o++ = (u8)(v >> 16);
        *o++ = (u8)(v >> 8);
        *o++ = (u8)v;
    }
    umm r = n - i;
    if (r == 2) {
        s32 a = b64url_dec[p[i]], b = b64url_dec[p[i + 1]];
        if ((a | b) < 0) return -1;
        *o++ = (u8)(((u32)a << 2) | ((u32)b >> 4));
    } else if (r == 3) {
        s32 a = b64url_dec[p[i]], b = b64url_dec[p[i + 1]], c = b64url_dec[p[i + 2]];
        if ((a | b | c) < 0) return -1;
        u32 v = ((u32)a << 18) | ((u32)b << 12) | ((u32)c << 6);
        *o++ = (u8)(v >> 16);
        *o++ = (u8)(v >> 8);
    }
    return (s64)(o - start);
}

internal void jwt_init(const char *secret)
{
    memset(b64url_dec, -1, sizeof(b64url_dec));
    for (int i = 0; i < 64; i++) b64url_dec[(u8)b64url_enc[i]] = (s8)i;
    hmac_key_init(&jwt_ctx.key, secret, strlen(secret));
    const char *h = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    jwt_ctx.std_header_len = b64_encode(jwt_ctx.std_header, (const u8 *)h, strlen(h), b64url_enc, 0);
}

enum { AUTH_OK = 0, AUTH_MISSING, AUTH_INVALID, AUTH_PAYLOAD };

typedef struct {
    s64 user_id;
    u8 *username; // points into the scratch passed to jwt_verify
    u32 username_len;
} AuthUser;

internal b32 jwt_header_ok(const u8 *h, umm n, u8 *scratch)
{
    if (n == jwt_ctx.std_header_len && memcmp(h, jwt_ctx.std_header, n) == 0) return 1;
    if (n > 1024) return 0;
    s64 dl = b64url_decode(scratch, h, n);
    if (dl < 0) return 0;
    JField f[1] = {{S("alg")}};
    b32 obj;
    u8 *fs = scratch + 1024;
    if (!json_extract(scratch, (umm)dl, f, 1, fs, &obj) || !obj) return 0;
    return f[0].kind == JF_STRING && f[0].str_len == 5 && memcmp(f[0].str, "HS256", 5) == 0;
}

// tok is the text after "Bearer ". scratch needs 4 * token length + 4 KB.
internal int jwt_verify(const u8 *tok, umm n, s64 now, u8 *scratch, AuthUser *out)
{
    if (n == 0 || n > 8192) return AUTH_INVALID;
    const u8 *d1 = memchr(tok, '.', n);
    if (!d1) return AUTH_INVALID;
    const u8 *d2 = memchr(d1 + 1, '.', (umm)(tok + n - d1 - 1));
    if (!d2) return AUTH_INVALID;
    if (memchr(d2 + 1, '.', (umm)(tok + n - d2 - 1))) return AUTH_INVALID;
    const u8 *hdr = tok;
    umm hdr_n = (umm)(d1 - tok);
    const u8 *pay = d1 + 1;
    umm pay_n = (umm)(d2 - pay);
    const u8 *sig = d2 + 1;
    umm sig_n = (umm)(tok + n - sig);
    if (sig_n != 43) return AUTH_INVALID;

    // signature over "header.payload"
    u8 mac[32];
    hmac_sha256_k(&jwt_ctx.key, tok, (umm)(d2 - tok), mac);
    u8 enc[44];
    b64_encode(enc, mac, 32, b64url_enc, 0);
    u8 diff = 0;
    for (int i = 0; i < 43; i++) diff |= (u8)(enc[i] ^ sig[i]);
    if (diff) return AUTH_INVALID;

    if (!jwt_header_ok(hdr, hdr_n, scratch)) return AUTH_INVALID;

    s64 pl = b64url_decode(scratch, pay, pay_n);
    if (pl < 0) return AUTH_INVALID;
    JField f[4] = {{S("exp")}, {S("sub")}, {S("username")}, {S("nbf")}};
    b32 obj;
    u8 *fs = scratch + AlignUp((umm)pl, 16);
    if (!json_extract(scratch, (umm)pl, f, 4, fs, &obj) || !obj) return AUTH_INVALID;
    if (f[0].kind != JF_NUMBER) return AUTH_INVALID;
    if (f[0].is_int ? (now >= f[0].ival) : ((f64)now >= f[0].fval)) return AUTH_INVALID;
    if (f[3].kind == JF_NUMBER && (f[3].is_int ? (now < f[3].ival) : ((f64)now < f[3].fval))) return AUTH_INVALID;

    if (f[1].kind != JF_STRING || f[1].str_len == 0 || f[1].str_len > 18) return AUTH_PAYLOAD;
    s64 uid = 0;
    for (umm i = 0; i < f[1].str_len; i++) {
        u8 c = f[1].str[i];
        if (c < '0' || c > '9') return AUTH_PAYLOAD;
        uid = uid * 10 + (c - '0');
    }
    if (uid <= 0) return AUTH_PAYLOAD;
    if (f[2].kind != JF_STRING || f[2].str_len > 1024) return AUTH_PAYLOAD;
    out->user_id = uid;
    out->username = f[2].str;
    out->username_len = (u32)f[2].str_len;
    return AUTH_OK;
}
