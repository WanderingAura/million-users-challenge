// sha256.c: SHA-256 (plain C; Cascade Lake has no SHA-NI), HMAC with precomputed midstates, PBKDF2 for SCRAM.

typedef struct {
    u32 h[8];
    u64 total; // bytes compressed so far
    u8 buf[64];
    u32 buffered;
} Sha256;

global const u32 sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

internal void sha256_compress(u32 *h, const u8 *block)
{
    u32 w[64];
    for (int i = 0; i < 16; i++) w[i] = load_be32(block + 4 * i);
    for (int i = 16; i < 64; i++) {
        u32 s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        u32 S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        u32 ch = (e & f) ^ (~e & g);
        u32 t1 = hh + S1 + ch + sha256_k[i] + w[i];
        u32 S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        u32 maj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

internal void sha256_init(Sha256 *s)
{
    static const u32 iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s->h, iv, sizeof(iv));
    s->total = 0;
    s->buffered = 0;
}

internal void sha256_update(Sha256 *s, const void *data, umm n)
{
    const u8 *p = (const u8 *)data;
    if (s->buffered) {
        umm take = Min(n, 64 - s->buffered);
        memcpy(s->buf + s->buffered, p, take);
        s->buffered += (u32)take;
        p += take;
        n -= take;
        if (s->buffered < 64) return;
        sha256_compress(s->h, s->buf);
        s->total += 64;
        s->buffered = 0;
    }
    while (n >= 64) {
        sha256_compress(s->h, p);
        s->total += 64;
        p += 64;
        n -= 64;
    }
    if (n) {
        memcpy(s->buf, p, n);
        s->buffered = (u32)n;
    }
}

internal void sha256_final(Sha256 *s, u8 out[32])
{
    u64 bits = (s->total + s->buffered) * 8;
    u8 pad[72];
    umm padlen = (s->buffered < 56) ? (56 - s->buffered) : (120 - s->buffered);
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    store_be64(pad + padlen, bits);
    sha256_update(s, pad, padlen + 8);
    for (int i = 0; i < 8; i++) store_be32(out + 4 * i, s->h[i]);
}

internal void sha256(const void *data, umm n, u8 out[32])
{
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, data, n);
    sha256_final(&s, out);
}

// HMAC key schedule: the states after absorbing (key ^ ipad) and (key ^ opad). Computing these once per key is a
// key schedule, not a cache of any result: every message is still hashed in full.
typedef struct {
    Sha256 inner;
    Sha256 outer;
} HmacKey;

internal void hmac_key_init(HmacKey *k, const void *key, umm keylen)
{
    u8 kb[64];
    memset(kb, 0, 64);
    if (keylen > 64) sha256(key, keylen, kb);
    else memcpy(kb, key, keylen);
    u8 pad[64];
    for (int i = 0; i < 64; i++) pad[i] = kb[i] ^ 0x36;
    sha256_init(&k->inner);
    sha256_update(&k->inner, pad, 64);
    for (int i = 0; i < 64; i++) pad[i] = kb[i] ^ 0x5c;
    sha256_init(&k->outer);
    sha256_update(&k->outer, pad, 64);
}

internal void hmac_sha256_k(const HmacKey *k, const void *msg, umm n, u8 out[32])
{
    Sha256 s = k->inner;
    sha256_update(&s, msg, n);
    u8 ih[32];
    sha256_final(&s, ih);
    s = k->outer;
    sha256_update(&s, ih, 32);
    sha256_final(&s, out);
}

internal void hmac_sha256(const void *key, umm keylen, const void *msg, umm n, u8 out[32])
{
    HmacKey k;
    hmac_key_init(&k, key, keylen);
    hmac_sha256_k(&k, msg, n, out);
}

// PBKDF2-HMAC-SHA256 with a 32-byte output (one block), as SCRAM-SHA-256 needs.
internal void pbkdf2_sha256(const void *pass, umm passlen, const u8 *salt, umm saltlen, u32 iters, u8 out[32])
{
    HmacKey k;
    hmac_key_init(&k, pass, passlen);
    u8 msg[256];
    Assert(saltlen + 4 <= sizeof(msg));
    memcpy(msg, salt, saltlen);
    store_be32(msg + saltlen, 1);
    u8 u[32];
    hmac_sha256_k(&k, msg, saltlen + 4, u);
    memcpy(out, u, 32);
    for (u32 i = 1; i < iters; i++) {
        hmac_sha256_k(&k, u, 32, u);
        for (int j = 0; j < 32; j++) out[j] ^= u[j];
    }
}
