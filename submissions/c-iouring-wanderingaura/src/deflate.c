// deflate.c: a gzip writer built for the feed. The JSON writer tells it where the constant key fragments are
// ("hints"), so those become back-references to the previous post with no searching. Everything else goes through
// a small greedy LZ77 (4-byte hash, one candidate). There is one dynamic-Huffman block per response whose code
// (and the header bits that describe it) are built once at startup from a synthetic corpus, so per response there
// is no frequency counting and no tree building. CRC32 uses PCLMUL folding on x86 and a table elsewhere.

typedef struct {
    u32 pos;
    u16 len;
    u16 frag;
} Hint;

#define LZ_HASH_BITS 12
#define LZ_MAX_INPUT (1u << 17) // larger bodies are sent uncompressed
#define NUM_FRAGS 8

typedef struct {
    u32 table[1 << LZ_HASH_BITS];
    u32 base;
} Deflater;

// ---- static DEFLATE tables ----
global const u16 len_base[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
global const u8 len_extra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
global const u16 dist_base[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
                                  1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
global const u8 dist_extra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
global const u8 clen_order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

#define NUM_LIT 286
#define NUM_DIST 30

typedef struct {
    u32 bits;
    u8 nbits;
} Code;

typedef struct {
    Code lit[NUM_LIT];   // literal / end-of-block codes
    Code len[259];       // length 3..258: length symbol code + extra bits, combined
    Code dist[NUM_DIST]; // distance symbol codes (extra bits added at encode time)
    u8 dist_sym[512];    // zlib-style: dist-1 < 256 -> [dist-1], else [256 + ((dist-1) >> 7)]
    u8 len_sym[259];
    u8 header[512];      // precomputed block header bits (BFINAL, BTYPE=2, HLIT.. code lengths)
    u32 header_bits;
} HuffTables;
global HuffTables huff;

global u32 crc_table[8][256];

// ---- CRC32 ----
internal void crc_init(void)
{
    for (u32 i = 0; i < 256; i++) {
        u32 c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc_table[0][i] = c;
    }
    for (u32 i = 0; i < 256; i++) {
        u32 c = crc_table[0][i];
        for (int t = 1; t < 8; t++) {
            c = crc_table[0][c & 0xFF] ^ (c >> 8);
            crc_table[t][i] = c;
        }
    }
}

// Raw register update (no pre/post inversion).
internal u32 crc32_raw_table(u32 c, const u8 *p, umm n)
{
    while (n >= 8) {
        u32 a = load_u32(p) ^ c, b = load_u32(p + 4);
        c = crc_table[7][a & 0xFF] ^ crc_table[6][(a >> 8) & 0xFF] ^ crc_table[5][(a >> 16) & 0xFF] ^
            crc_table[4][a >> 24] ^ crc_table[3][b & 0xFF] ^ crc_table[2][(b >> 8) & 0xFF] ^
            crc_table[1][(b >> 16) & 0xFF] ^ crc_table[0][b >> 24];
        p += 8;
        n -= 8;
    }
    while (n--) c = crc_table[0][(c ^ *p++) & 0xFF] ^ (c >> 8);
    return c;
}

#if FAST_X86
// Folding with PCLMULQDQ (Intel's "Fast CRC Computation Using PCLMULQDQ", bit-reflected constants for the gzip
// polynomial). len >= 64 and a multiple of 16. Takes and returns the raw register.
__attribute__((target("pclmul,sse4.1"))) internal u32 crc32_raw_pclmul(u32 crc, const u8 *buf, umm len)
{
    const __m128i k1k2 = _mm_set_epi64x(0x01c6e41596, 0x0154442bd4);
    const __m128i k3k4 = _mm_set_epi64x(0x00ccaa009e, 0x01751997d0);
    const __m128i k5k0 = _mm_set_epi64x(0, 0x0163cd6124);
    const __m128i poly = _mm_set_epi64x(0x01f7011641, 0x01db710641);
    __m128i x0, x1, x2, x3, x4, x5, x6, x7, x8, y5, y6, y7, y8;
    x1 = _mm_loadu_si128((const __m128i *)(buf + 0x00));
    x2 = _mm_loadu_si128((const __m128i *)(buf + 0x10));
    x3 = _mm_loadu_si128((const __m128i *)(buf + 0x20));
    x4 = _mm_loadu_si128((const __m128i *)(buf + 0x30));
    x1 = _mm_xor_si128(x1, _mm_cvtsi32_si128((int)crc));
    x0 = k1k2;
    buf += 64;
    len -= 64;
    while (len >= 64) {
        x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
        x6 = _mm_clmulepi64_si128(x2, x0, 0x00);
        x7 = _mm_clmulepi64_si128(x3, x0, 0x00);
        x8 = _mm_clmulepi64_si128(x4, x0, 0x00);
        x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
        x2 = _mm_clmulepi64_si128(x2, x0, 0x11);
        x3 = _mm_clmulepi64_si128(x3, x0, 0x11);
        x4 = _mm_clmulepi64_si128(x4, x0, 0x11);
        y5 = _mm_loadu_si128((const __m128i *)(buf + 0x00));
        y6 = _mm_loadu_si128((const __m128i *)(buf + 0x10));
        y7 = _mm_loadu_si128((const __m128i *)(buf + 0x20));
        y8 = _mm_loadu_si128((const __m128i *)(buf + 0x30));
        x1 = _mm_xor_si128(_mm_xor_si128(x1, x5), y5);
        x2 = _mm_xor_si128(_mm_xor_si128(x2, x6), y6);
        x3 = _mm_xor_si128(_mm_xor_si128(x3, x7), y7);
        x4 = _mm_xor_si128(_mm_xor_si128(x4, x8), y8);
        buf += 64;
        len -= 64;
    }
    x0 = k3k4;
    x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
    x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
    x1 = _mm_xor_si128(_mm_xor_si128(x1, x2), x5);
    x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
    x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
    x1 = _mm_xor_si128(_mm_xor_si128(x1, x3), x5);
    x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
    x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
    x1 = _mm_xor_si128(_mm_xor_si128(x1, x4), x5);
    while (len >= 16) {
        x2 = _mm_loadu_si128((const __m128i *)buf);
        x5 = _mm_clmulepi64_si128(x1, x0, 0x00);
        x1 = _mm_clmulepi64_si128(x1, x0, 0x11);
        x1 = _mm_xor_si128(_mm_xor_si128(x1, x2), x5);
        buf += 16;
        len -= 16;
    }
    x2 = _mm_clmulepi64_si128(x1, x0, 0x10);
    x3 = _mm_setr_epi32(~0, 0, ~0, 0);
    x1 = _mm_srli_si128(x1, 8);
    x1 = _mm_xor_si128(x1, x2);
    x0 = k5k0;
    x2 = _mm_srli_si128(x1, 4);
    x1 = _mm_and_si128(x1, x3);
    x1 = _mm_clmulepi64_si128(x1, x0, 0x00);
    x1 = _mm_xor_si128(x1, x2);
    x0 = poly;
    x2 = _mm_and_si128(x1, x3);
    x2 = _mm_clmulepi64_si128(x2, x0, 0x10);
    x2 = _mm_and_si128(x2, x3);
    x2 = _mm_clmulepi64_si128(x2, x0, 0x00);
    x1 = _mm_xor_si128(x1, x2);
    return (u32)_mm_extract_epi32(x1, 1);
}
#endif

internal u32 crc32_gzip(const u8 *p, umm n)
{
    u32 c = 0xFFFFFFFFu;
#if FAST_X86
    if (n >= 64) {
        umm chunk = n & ~(umm)15;
        c = crc32_raw_pclmul(c, p, chunk);
        p += chunk;
        n -= chunk;
    }
#endif
    c = crc32_raw_table(c, p, n);
    return ~c;
}
internal u32 crc32_gzip_table(const u8 *p, umm n) { return ~crc32_raw_table(0xFFFFFFFFu, p, n); }

// ---- Huffman construction (startup only) ----
// Code lengths for n symbols (all frequencies must be >= 1), limited to maxlen by flattening the frequencies.
internal void huff_lengths(const u32 *freq_in, int n, int maxlen, u8 *lens)
{
    u32 freq[NUM_LIT];
    for (int i = 0; i < n; i++) freq[i] = freq_in[i] ? freq_in[i] : 1;
    for (;;) {
        // nodes: 0..n-1 leaves, n.. internal
        u64 w[2 * NUM_LIT];
        int parent[2 * NUM_LIT];
        b32 alive[2 * NUM_LIT];
        int count = n;
        for (int i = 0; i < n; i++) { w[i] = freq[i]; alive[i] = 1; parent[i] = -1; }
        for (int left = n; left > 1; left--) {
            int a = -1, b = -1;
            for (int i = 0; i < count; i++) {
                if (!alive[i]) continue;
                if (a < 0 || w[i] < w[a]) { b = a; a = i; }
                else if (b < 0 || w[i] < w[b]) b = i;
            }
            alive[a] = alive[b] = 0;
            w[count] = w[a] + w[b];
            alive[count] = 1;
            parent[count] = -1;
            parent[a] = parent[b] = count;
            count++;
        }
        int maxl = 0;
        for (int i = 0; i < n; i++) {
            int l = 0;
            for (int x = i; parent[x] >= 0; x = parent[x]) l++;
            if (n == 1) l = 1;
            lens[i] = (u8)l;
            if (l > maxl) maxl = l;
        }
        if (maxl <= maxlen) return;
        for (int i = 0; i < n; i++) freq[i] = (freq[i] + 1) / 2;
    }
}

internal u32 bit_reverse(u32 v, int n)
{
    u32 r = 0;
    for (int i = 0; i < n; i++) { r = (r << 1) | (v & 1); v >>= 1; }
    return r;
}

internal void huff_codes(const u8 *lens, int n, Code *codes)
{
    u32 bl_count[16] = {0}, next_code[16] = {0};
    for (int i = 0; i < n; i++) bl_count[lens[i]]++;
    bl_count[0] = 0;
    u32 code = 0;
    for (int b = 1; b <= 15; b++) {
        code = (code + bl_count[b - 1]) << 1;
        next_code[b] = code;
    }
    for (int i = 0; i < n; i++) {
        codes[i].nbits = lens[i];
        codes[i].bits = lens[i] ? bit_reverse(next_code[lens[i]]++, lens[i]) : 0;
    }
}

typedef struct {
    u64 acc;
    u32 nbits;
    u8 *out;
} BitW;

internal inline void bw_put(BitW *w, u32 bits, u32 n)
{
    w->acc |= (u64)bits << w->nbits;
    w->nbits += n;
    if (w->nbits >= 32) {
        store_u64(w->out, w->acc);
        u32 adv = w->nbits >> 3;
        w->out += adv;
        w->acc >>= adv * 8;
        w->nbits &= 7;
    }
}
internal inline u8 *bw_finish(BitW *w)
{
    while (w->nbits > 0) {
        *w->out++ = (u8)w->acc;
        w->acc >>= 8;
        w->nbits = w->nbits > 8 ? w->nbits - 8 : 0;
    }
    return w->out;
}

internal void huff_build(const u32 *lit_freq, const u32 *dist_freq)
{
    u8 lit_lens[NUM_LIT], dist_lens[NUM_DIST];
    huff_lengths(lit_freq, NUM_LIT, 15, lit_lens);
    huff_lengths(dist_freq, NUM_DIST, 15, dist_lens);
    huff_codes(lit_lens, NUM_LIT, huff.lit);
    huff_codes(dist_lens, NUM_DIST, huff.dist);
    for (int l = 3; l <= 258; l++) {
        int s = 0;
        while (s < 28 && len_base[s + 1] <= l) s++;
        huff.len_sym[l] = (u8)s;
        Code c = huff.lit[257 + s];
        huff.len[l].bits = c.bits | ((u32)(l - len_base[s]) << c.nbits);
        huff.len[l].nbits = (u8)(c.nbits + len_extra[s]);
    }
    for (int d = 1; d <= 32768; d++) {
        int s = 0;
        while (s < 29 && dist_base[s + 1] <= d) s++;
        if (d - 1 < 256) huff.dist_sym[d - 1] = (u8)s;
        else huff.dist_sym[256 + ((d - 1) >> 7)] = (u8)s;
    }
    // header: run-length code the 316 code lengths
    u8 all[NUM_LIT + NUM_DIST];
    memcpy(all, lit_lens, NUM_LIT);
    memcpy(all + NUM_LIT, dist_lens, NUM_DIST);
    int total = NUM_LIT + NUM_DIST;
    u16 rle_sym[NUM_LIT + NUM_DIST];
    u8 rle_extra[NUM_LIT + NUM_DIST];
    int nrle = 0;
    for (int i = 0; i < total;) {
        u8 v = all[i];
        int run = 1;
        while (i + run < total && all[i + run] == v) run++;
        int r = run;
        if (v == 0) {
            while (r >= 11) { int k = Min(r, 138); rle_sym[nrle] = 18; rle_extra[nrle++] = (u8)(k - 11); r -= k; }
            if (r >= 3) { rle_sym[nrle] = 17; rle_extra[nrle++] = (u8)(r - 3); r = 0; }
            while (r-- > 0) { rle_sym[nrle] = 0; rle_extra[nrle++] = 0; }
        } else {
            rle_sym[nrle] = v; rle_extra[nrle++] = 0; r--;
            while (r >= 3) { int k = Min(r, 6); rle_sym[nrle] = 16; rle_extra[nrle++] = (u8)(k - 3); r -= k; }
            while (r-- > 0) { rle_sym[nrle] = v; rle_extra[nrle++] = 0; }
        }
        i += run;
    }
    u32 clen_freq[19] = {0};
    for (int i = 0; i < nrle; i++) clen_freq[rle_sym[i]]++;
    // only used symbols get a code: give the unused ones length 0
    u8 clen_lens[19];
    {
        u32 f[19];
        int map[19], m = 0;
        for (int i = 0; i < 19; i++) if (clen_freq[i]) { map[m] = i; f[m++] = clen_freq[i]; }
        u8 l[19];
        huff_lengths(f, m, 7, l);
        memset(clen_lens, 0, sizeof(clen_lens));
        for (int i = 0; i < m; i++) clen_lens[map[i]] = l[i];
    }
    Code clen_codes[19];
    huff_codes(clen_lens, 19, clen_codes);
    int hclen = 19;
    while (hclen > 4 && clen_lens[clen_order[hclen - 1]] == 0) hclen--;
    memset(huff.header, 0, sizeof(huff.header));
    BitW w = {0, 0, huff.header};
    bw_put(&w, 1, 1);                 // BFINAL
    bw_put(&w, 2, 2);                 // BTYPE = dynamic
    bw_put(&w, NUM_LIT - 257, 5);
    bw_put(&w, NUM_DIST - 1, 5);
    bw_put(&w, (u32)(hclen - 4), 4);
    for (int i = 0; i < hclen; i++) bw_put(&w, clen_lens[clen_order[i]], 3);
    for (int i = 0; i < nrle; i++) {
        Code c = clen_codes[rle_sym[i]];
        bw_put(&w, c.bits, c.nbits);
        if (rle_sym[i] == 16) bw_put(&w, rle_extra[i], 2);
        else if (rle_sym[i] == 17) bw_put(&w, rle_extra[i], 3);
        else if (rle_sym[i] == 18) bw_put(&w, rle_extra[i], 7);
    }
    huff.header_bits = (u32)((w.out - huff.header) * 8 + w.nbits);
    bw_finish(&w);
    Assert(huff.header_bits <= sizeof(huff.header) * 8);
}

// ---- tokenizer / encoder ----
internal inline u32 lz_hash(u32 v) { return (v * 2654435761u) >> (32 - LZ_HASH_BITS); }

typedef struct {
    BitW w;
    u32 *lit_freq;  // counting mode (startup corpus) when non-null
    u32 *dist_freq;
} Emit;

internal inline __attribute__((always_inline)) void emit_lit(Emit *e, b32 counting, u8 c)
{
    if (counting) { e->lit_freq[c]++; return; }
    Code k = huff.lit[c];
    bw_put(&e->w, k.bits, k.nbits);
}

internal inline __attribute__((always_inline)) void emit_match(Emit *e, b32 counting, u32 len, u32 dist)
{
    u32 dsym = dist <= 256 ? huff.dist_sym[dist - 1] : huff.dist_sym[256 + ((dist - 1) >> 7)];
    if (counting) {
        e->lit_freq[257 + huff.len_sym[len]]++;
        e->dist_freq[dsym]++;
        return;
    }
    Code l = huff.len[len];
    bw_put(&e->w, l.bits, l.nbits);
    Code d = huff.dist[dsym];
    bw_put(&e->w, d.bits | ((dist - dist_base[dsym]) << d.nbits), d.nbits + dist_extra[dsym]);
}

internal inline __attribute__((always_inline)) void lz_region(Deflater *z, Emit *e, b32 counting, const u8 *buf,
                                                                u32 i, u32 end)
{
    while (i < end) {
        if (end - i >= 4) {
            u32 v = load_u32(buf + i);
            u32 h = lz_hash(v);
            u32 cand = z->table[h];
            z->table[h] = i + z->base;
            if (cand >= z->base && cand - z->base < i) {
                u32 c = cand - z->base;
                u32 dist = i - c;
                if (dist <= 32768 && load_u32(buf + c) == v) {
                    u32 len = 4, limit = Min(258u, end - i);
                    while (len < limit && buf[c + len] == buf[i + len]) len++;
                    emit_match(e, counting, len, dist);
                    i += len;
                    continue;
                }
            }
        }
        emit_lit(e, counting, buf[i]);
        i++;
    }
}

internal inline __attribute__((always_inline)) void tokenize(Deflater *z, Emit *e, b32 counting, const u8 *buf,
                                                               u32 n, const Hint *hints, u32 nh)
{
    s64 last[NUM_FRAGS];
    for (int i = 0; i < NUM_FRAGS; i++) last[i] = -1;
    if (z->base < LZ_MAX_INPUT || z->base > 0xFFFFFFFFu - 2 * LZ_MAX_INPUT) { // first use, or about to wrap
        memset(z->table, 0, sizeof(z->table));
        z->base = LZ_MAX_INPUT;
    }
    u32 pos = 0, hi = 0;
    while (pos < n) {
        u32 next = hi < nh ? hints[hi].pos : n;
        if (next > pos) lz_region(z, e, counting, buf, pos, next);
        if (next >= pos) pos = next;
        if (hi >= nh) break;
        Hint h = hints[hi++];
        if (h.pos < pos) continue; // already covered by an extended match
        u32 limit_end = hi < nh ? hints[hi].pos : n;
        s64 lp = last[h.frag];
        last[h.frag] = pos;
        if (lp >= 0 && pos - lp <= 32768) {
            u32 dist = (u32)(pos - lp);
            u32 len = h.len;
            u32 limit = Min(258u, limit_end - pos);
            while (len < limit && buf[pos + len] == buf[pos + len - dist]) len++;
            emit_match(e, counting, len, dist);
            pos += len;
        } else {
            u32 fend = Min(pos + h.len, n);
            lz_region(z, e, counting, buf, pos, fend);
            pos = fend;
        }
    }
    z->base += LZ_MAX_INPUT;
    if (counting) e->lit_freq[256]++;
}

global const u8 gzip_header[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3};

// Compresses src into out (which needs 2 * n + 1 KB). Returns the gzip size, or 0 if it would not be smaller.
internal umm gzip_compress(Deflater *z, const u8 *src, u32 n, const Hint *hints, u32 nh, u8 *out)
{
    if (n >= LZ_MAX_INPUT) return 0;
    memcpy(out, gzip_header, 10);
    u8 *o = out + 10;
    u32 hbytes = huff.header_bits >> 3, hrem = huff.header_bits & 7;
    memcpy(o, huff.header, hbytes);
    Emit e;
    e.w.out = o + hbytes;
    e.w.acc = hrem ? (huff.header[hbytes] & ((1u << hrem) - 1)) : 0;
    e.w.nbits = hrem;
    e.lit_freq = e.dist_freq = 0;
    tokenize(z, &e, 0, src, n, hints, nh);
    Code eob = huff.lit[256];
    bw_put(&e.w, eob.bits, eob.nbits);
    o = bw_finish(&e.w);
    store_u32(o, crc32_gzip(src, n));
    store_u32(o + 4, n);
    o += 8;
    umm size = (umm)(o - out);
    return size < n ? size : 0;
}

internal void deflate_count(Deflater *z, const u8 *src, u32 n, const Hint *hints, u32 nh, u32 *lit_freq,
                            u32 *dist_freq)
{
    Emit e;
    memset(&e, 0, sizeof(e));
    e.lit_freq = lit_freq;
    e.dist_freq = dist_freq;
    tokenize(z, &e, 1, src, n, hints, nh);
}

// Before the real tables exist, counting needs dist_sym / len_sym; fill those from the static tables.
internal void deflate_static_init(void)
{
    for (int l = 3; l <= 258; l++) {
        int s = 0;
        while (s < 28 && len_base[s + 1] <= l) s++;
        huff.len_sym[l] = (u8)s;
    }
    for (int d = 1; d <= 32768; d++) {
        int s = 0;
        while (s < 29 && dist_base[s + 1] <= d) s++;
        if (d - 1 < 256) huff.dist_sym[d - 1] = (u8)s;
        else huff.dist_sym[256 + ((d - 1) >> 7)] = (u8)s;
    }
}
