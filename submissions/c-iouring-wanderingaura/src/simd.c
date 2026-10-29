// simd.c: byte scanning. FAST_X86 uses AVX-512BW/VL on 256-bit vectors (mask compares and masked tail loads, so
// nothing reads past the buffer). 256-bit width keeps Cascade Lake out of its AVX-512 frequency licence.
// The scalar versions are the reference: both paths must return identical results.

internal umm escape_scan_scalar(const u8 *p, umm n)
{
    for (umm i = 0; i < n; i++) {
        u8 c = p[i];
        if (c < 0x20 || c == '"' || c == '\\') return i;
    }
    return n;
}

// Index of the first byte that JSON needs escaped (", \, or < 0x20), or n.
internal umm escape_scan(const u8 *p, umm n)
{
#if FAST_X86
    const __m256i q = _mm256_set1_epi8('"');
    const __m256i bs = _mm256_set1_epi8('\\');
    const __m256i sp = _mm256_set1_epi8(0x20);
    umm i = 0;
    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(p + i));
        __mmask32 m = _mm256_cmpeq_epi8_mask(v, q) | _mm256_cmpeq_epi8_mask(v, bs) | _mm256_cmplt_epu8_mask(v, sp);
        if (m) return i + (umm)__builtin_ctz(m);
    }
    if (i < n) {
        __mmask32 lm = (__mmask32)((1u << (n - i)) - 1);
        __m256i v = _mm256_maskz_loadu_epi8(lm, p + i);
        __mmask32 m = (_mm256_cmpeq_epi8_mask(v, q) | _mm256_cmpeq_epi8_mask(v, bs) | _mm256_cmplt_epu8_mask(v, sp)) & lm;
        if (m) return i + (umm)__builtin_ctz(m);
    }
    return n;
#else
    return escape_scan_scalar(p, n);
#endif
}

internal umm ascii_scan_scalar(const u8 *p, umm n)
{
    for (umm i = 0; i < n; i++)
        if (p[i] & 0x80) return i;
    return n;
}

// Index of the first byte >= 0x80, or n.
internal umm ascii_scan(const u8 *p, umm n)
{
#if FAST_X86
    umm i = 0;
    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(p + i));
        __mmask32 m = _mm256_movepi8_mask(v);
        if (m) return i + (umm)__builtin_ctz(m);
    }
    if (i < n) {
        __mmask32 lm = (__mmask32)((1u << (n - i)) - 1);
        __m256i v = _mm256_maskz_loadu_epi8(lm, p + i);
        __mmask32 m = _mm256_movepi8_mask(v) & lm;
        if (m) return i + (umm)__builtin_ctz(m);
    }
    return n;
#else
    return ascii_scan_scalar(p, n);
#endif
}

internal s64 header_end_scalar(const u8 *p, umm n)
{
    for (umm i = 0; i + 4 <= n; i++)
        if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' && p[i + 3] == '\n') return (s64)(i + 4);
    return -1;
}

// Offset just past the first "\r\n\r\n", or -1.
internal s64 header_end(const u8 *p, umm n)
{
#if FAST_X86
    if (n < 4) return -1;
    const __m256i cr = _mm256_set1_epi8('\r');
    const __m256i lf = _mm256_set1_epi8('\n');
    umm last = n - 3; // candidate starts are 0..last-1
    umm i = 0;
    for (; i + 32 <= last; i += 32) {
        __mmask32 m = _mm256_cmpeq_epi8_mask(_mm256_loadu_si256((const __m256i *)(p + i)), cr);
        if (!m) continue;
        m &= _mm256_cmpeq_epi8_mask(_mm256_loadu_si256((const __m256i *)(p + i + 1)), lf);
        m &= _mm256_cmpeq_epi8_mask(_mm256_loadu_si256((const __m256i *)(p + i + 2)), cr);
        m &= _mm256_cmpeq_epi8_mask(_mm256_loadu_si256((const __m256i *)(p + i + 3)), lf);
        if (m) return (s64)(i + (umm)__builtin_ctz(m) + 4);
    }
    if (i < last) {
        umm k = last - i;
        __mmask32 lm = (__mmask32)(k >= 32 ? 0xFFFFFFFFu : ((1u << k) - 1));
        __mmask32 m = _mm256_cmpeq_epi8_mask(_mm256_maskz_loadu_epi8(lm, p + i), cr) & lm;
        m &= _mm256_cmpeq_epi8_mask(_mm256_maskz_loadu_epi8(lm, p + i + 1), lf);
        m &= _mm256_cmpeq_epi8_mask(_mm256_maskz_loadu_epi8(lm, p + i + 2), cr);
        m &= _mm256_cmpeq_epi8_mask(_mm256_maskz_loadu_epi8(lm, p + i + 3), lf);
        if (m) return (s64)(i + (umm)__builtin_ctz(m) + 4);
    }
    return -1;
#else
    return header_end_scalar(p, n);
#endif
}
