// json.c: the response writer (string escaping) and a small strict parser for request bodies and JWT payloads.

global const char hex_digits[] = "0123456789abcdef";

// Escapes ", \ and control characters (as JSON.stringify does); everything else, UTF-8 included, is copied.
internal inline u8 *write_json_str(u8 *o, const u8 *p, umm n)
{
    for (;;) {
        umm k = escape_scan(p, n);
        memcpy(o, p, k);
        o += k;
        if (k == n) return o;
        u8 c = p[k];
        *o++ = '\\';
        switch (c) {
        case '"': *o++ = '"'; break;
        case '\\': *o++ = '\\'; break;
        case '\n': *o++ = 'n'; break;
        case '\r': *o++ = 'r'; break;
        case '\t': *o++ = 't'; break;
        case '\b': *o++ = 'b'; break;
        case '\f': *o++ = 'f'; break;
        default:
            *o++ = 'u'; *o++ = '0'; *o++ = '0';
            *o++ = (u8)hex_digits[c >> 4];
            *o++ = (u8)hex_digits[c & 15];
        }
        p += k + 1;
        n -= k + 1;
    }
}
// Worst case: every byte becomes \u00XX.
#define JSON_STR_MAX(n) ((n) * 6)

// ---- UTF-8 ----
// Decodes one code point at p (p < end). Returns its length, or 0 if the sequence is invalid.
internal inline u32 utf8_decode(const u8 *p, const u8 *end, u32 *cp)
{
    u8 c = p[0];
    if (c < 0x80) { *cp = c; return 1; }
    if (c < 0xC2) return 0;
    if (c < 0xE0) {
        if (end - p < 2 || (p[1] & 0xC0) != 0x80) return 0;
        *cp = ((u32)(c & 0x1F) << 6) | (p[1] & 0x3F);
        return 2;
    }
    if (c < 0xF0) {
        if (end - p < 3 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) return 0;
        u32 v = ((u32)(c & 0x0F) << 12) | ((u32)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
        if (v < 0x800 || (v >= 0xD800 && v <= 0xDFFF)) return 0;
        *cp = v;
        return 3;
    }
    if (c < 0xF5) {
        if (end - p < 4 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 || (p[3] & 0xC0) != 0x80) return 0;
        u32 v = ((u32)(c & 0x07) << 18) | ((u32)(p[1] & 0x3F) << 12) | ((u32)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
        if (v < 0x10000 || v > 0x10FFFF) return 0;
        *cp = v;
        return 4;
    }
    return 0;
}

internal inline u8 *utf8_encode(u8 *o, u32 cp)
{
    if (cp < 0x80) { *o++ = (u8)cp; }
    else if (cp < 0x800) { *o++ = (u8)(0xC0 | (cp >> 6)); *o++ = (u8)(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) {
        *o++ = (u8)(0xE0 | (cp >> 12)); *o++ = (u8)(0x80 | ((cp >> 6) & 0x3F)); *o++ = (u8)(0x80 | (cp & 0x3F));
    } else {
        *o++ = (u8)(0xF0 | (cp >> 18)); *o++ = (u8)(0x80 | ((cp >> 12) & 0x3F));
        *o++ = (u8)(0x80 | ((cp >> 6) & 0x3F)); *o++ = (u8)(0x80 | (cp & 0x3F));
    }
    return o;
}

// JavaScript's String.prototype.trim() whitespace set.
internal inline b32 is_js_space(u32 cp)
{
    if (cp <= 0x20) return cp == 0x20 || (cp >= 0x09 && cp <= 0x0D);
    if (cp < 0xA0) return 0;
    return cp == 0xA0 || cp == 0x1680 || (cp >= 0x2000 && cp <= 0x200A) || cp == 0x2028 || cp == 0x2029 ||
           cp == 0x202F || cp == 0x205F || cp == 0x3000 || cp == 0xFEFF;
}

// Trims a valid UTF-8 string in place (returns the trimmed view).
internal Str utf8_trim(Str s)
{
    const u8 *p = s.data, *end = s.data + s.count;
    while (p < end) {
        u32 cp;
        u32 l = utf8_decode(p, end, &cp);
        if (!l || !is_js_space(cp)) break;
        p += l;
    }
    // trailing: walk back to the start of each code point
    while (end > p) {
        const u8 *q = end - 1;
        while (q > p && (*q & 0xC0) == 0x80) q--;
        u32 cp;
        u32 l = utf8_decode(q, end, &cp);
        if (!l || q + l != end || !is_js_space(cp)) break;
        end = q;
    }
    return (Str){(u8 *)p, (umm)(end - p)};
}

internal umm utf8_count(const u8 *p, umm n)
{
    umm c = 0;
    for (umm i = 0; i < n; i++) c += (p[i] & 0xC0) != 0x80;
    return c;
}

// ---- parser ----
typedef struct {
    const u8 *p;
    const u8 *end;
    int depth;
} Jp;

internal inline void jp_ws(Jp *j)
{
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')) j->p++;
}

internal inline int hexval(u8 c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

internal b32 jp_hex4(Jp *j, u32 *v)
{
    if (j->end - j->p < 4) return 0;
    u32 r = 0;
    for (int i = 0; i < 4; i++) {
        int h = hexval(j->p[i]);
        if (h < 0) return 0;
        r = (r << 4) | (u32)h;
    }
    j->p += 4;
    *v = r;
    return 1;
}

// Parses a string at j->p (which must be '"'). Decoded UTF-8 goes to out (may be 0 to skip; out needs room for
// the raw length). Invalid UTF-8 or raw control characters fail.
internal b32 jp_string(Jp *j, u8 *out, umm *outlen)
{
    if (j->p >= j->end || *j->p != '"') return 0;
    j->p++;
    u8 *o = out;
    for (;;) {
        const u8 *s = j->p;
        umm left = (umm)(j->end - s);
        umm k = escape_scan(s, left); // stops at " \ or control
        if (k == left) return 0;
        // validate the UTF-8 in the run
        umm a = ascii_scan(s, k);
        if (a < k) {
            const u8 *q = s + a, *qe = s + k;
            while (q < qe) {
                if (*q < 0x80) { q++; continue; }
                u32 cp;
                u32 l = utf8_decode(q, qe, &cp);
                if (!l) return 0;
                q += l;
            }
        }
        if (o) { memcpy(o, s, k); o += k; }
        j->p = s + k;
        u8 c = *j->p;
        if (c == '"') { j->p++; break; }
        if (c < 0x20) return 0;
        // backslash
        j->p++;
        if (j->p >= j->end) return 0;
        u8 e = *j->p++;
        u32 cp;
        switch (e) {
        case '"': cp = '"'; break;
        case '\\': cp = '\\'; break;
        case '/': cp = '/'; break;
        case 'b': cp = '\b'; break;
        case 'f': cp = '\f'; break;
        case 'n': cp = '\n'; break;
        case 'r': cp = '\r'; break;
        case 't': cp = '\t'; break;
        case 'u': {
            if (!jp_hex4(j, &cp)) return 0;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                u32 lo;
                if (j->end - j->p >= 6 && j->p[0] == '\\' && j->p[1] == 'u') {
                    const u8 *save = j->p;
                    j->p += 2;
                    if (jp_hex4(j, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    else { j->p = save; cp = 0xFFFD; }
                } else cp = 0xFFFD;
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) cp = 0xFFFD;
        } break;
        default: return 0;
        }
        if (o) o = utf8_encode(o, cp);
    }
    if (outlen) *outlen = (umm)(o - out);
    return 1;
}

// Strict JSON number. On success sets *is_int / *ival when it is a plain integer that fits, and *fval always.
internal b32 jp_number(Jp *j, b32 *is_int, s64 *ival, f64 *fval)
{
    const u8 *s = j->p;
    const u8 *q = s;
    if (q < j->end && *q == '-') q++;
    if (q >= j->end) return 0;
    if (*q == '0') q++;
    else if (*q >= '1' && *q <= '9') { while (q < j->end && *q >= '0' && *q <= '9') q++; }
    else return 0;
    b32 integer = 1;
    if (q < j->end && *q == '.') {
        integer = 0;
        q++;
        if (q >= j->end || *q < '0' || *q > '9') return 0;
        while (q < j->end && *q >= '0' && *q <= '9') q++;
    }
    if (q < j->end && (*q == 'e' || *q == 'E')) {
        integer = 0;
        q++;
        if (q < j->end && (*q == '+' || *q == '-')) q++;
        if (q >= j->end || *q < '0' || *q > '9') return 0;
        while (q < j->end && *q >= '0' && *q <= '9') q++;
    }
    umm n = (umm)(q - s);
    j->p = q;
    char tmp[64];
    if (n >= sizeof(tmp)) { // absurdly long number: still valid JSON
        if (is_int) *is_int = 0;
        if (fval) *fval = 0;
        return 1;
    }
    memcpy(tmp, s, n);
    tmp[n] = 0;
    if (fval) *fval = strtod(tmp, 0);
    if (is_int) {
        *is_int = 0;
        if (integer && n <= 18) {
            *is_int = 1;
            if (ival) *ival = strtoll(tmp, 0, 10);
        }
    }
    return 1;
}

internal b32 jp_skip_value(Jp *j);

internal b32 jp_skip_container(Jp *j, u8 open)
{
    u8 close = open == '{' ? '}' : ']';
    if (++j->depth > 64) return 0;
    j->p++;
    jp_ws(j);
    if (j->p < j->end && *j->p == close) { j->p++; j->depth--; return 1; }
    for (;;) {
        jp_ws(j);
        if (open == '{') {
            if (!jp_string(j, 0, 0)) return 0;
            jp_ws(j);
            if (j->p >= j->end || *j->p != ':') return 0;
            j->p++;
        }
        if (!jp_skip_value(j)) return 0;
        jp_ws(j);
        if (j->p >= j->end) return 0;
        if (*j->p == ',') { j->p++; continue; }
        if (*j->p == close) { j->p++; j->depth--; return 1; }
        return 0;
    }
}

internal b32 jp_lit(Jp *j, const char *lit, umm n)
{
    if ((umm)(j->end - j->p) < n || memcmp(j->p, lit, n) != 0) return 0;
    j->p += n;
    return 1;
}

internal b32 jp_skip_value(Jp *j)
{
    jp_ws(j);
    if (j->p >= j->end) return 0;
    switch (*j->p) {
    case '{':
    case '[': return jp_skip_container(j, *j->p);
    case '"': return jp_string(j, 0, 0);
    case 't': return jp_lit(j, "true", 4);
    case 'f': return jp_lit(j, "false", 5);
    case 'n': return jp_lit(j, "null", 4);
    default: return jp_number(j, 0, 0, 0);
    }
}

// A requested top-level field of an object.
enum { JF_ABSENT = 0, JF_STRING, JF_NUMBER, JF_OTHER };
typedef struct {
    Str key;
    int kind;
    u8 *str;      // decoded string (points into the caller's scratch)
    umm str_len;
    b32 is_int;
    s64 ival;
    f64 fval;
} JField;

// Parses a complete JSON document. If it is an object, fills the requested top-level fields (last duplicate wins).
// scratch must hold at least n bytes per string field. Returns 0 if the document is not valid JSON.
internal b32 json_extract(const u8 *p, umm n, JField *fields, int nfields, u8 *scratch, b32 *is_object)
{
    Jp j = {p, p + n, 0};
    *is_object = 0;
    jp_ws(&j);
    if (j.p >= j.end) return 0;
    if (*j.p != '{') {
        if (!jp_skip_value(&j)) return 0;
        jp_ws(&j);
        return j.p == j.end;
    }
    *is_object = 1;
    j.p++;
    j.depth = 1;
    jp_ws(&j);
    u8 keybuf[64];
    if (j.p < j.end && *j.p == '}') {
        j.p++;
    } else {
        for (;;) {
            jp_ws(&j);
            // key: decode into keybuf when short, otherwise just validate
            const u8 *ks = j.p;
            Jp kj = j;
            umm klen = 0;
            b32 short_key = 0;
            {
                // find the raw key length cheaply to decide
                if (kj.p >= kj.end || *kj.p != '"') return 0;
                const u8 *q = kj.p + 1;
                while (q < kj.end && *q != '"' && *q != '\\') q++;
                short_key = (q < kj.end && *q == '"' && (umm)(q - ks - 1) < sizeof(keybuf));
            }
            if (short_key) {
                if (!jp_string(&j, keybuf, &klen)) return 0;
            } else {
                if (!jp_string(&j, 0, 0)) return 0;
                klen = (umm)-1;
            }
            jp_ws(&j);
            if (j.p >= j.end || *j.p != ':') return 0;
            j.p++;
            jp_ws(&j);
            JField *f = 0;
            if (klen != (umm)-1) {
                for (int i = 0; i < nfields; i++)
                    if (fields[i].key.count == klen && memcmp(fields[i].key.data, keybuf, klen) == 0) f = &fields[i];
            }
            if (!f) {
                if (!jp_skip_value(&j)) return 0;
            } else if (j.p < j.end && *j.p == '"') {
                f->str = scratch + (f - fields) * n; // each field gets its own n-byte slice
                if (!jp_string(&j, f->str, &f->str_len)) return 0;
                f->kind = JF_STRING;
            } else if (j.p < j.end && (*j.p == '-' || (*j.p >= '0' && *j.p <= '9'))) {
                if (!jp_number(&j, &f->is_int, &f->ival, &f->fval)) return 0;
                f->kind = JF_NUMBER;
            } else {
                if (!jp_skip_value(&j)) return 0;
                f->kind = JF_OTHER;
            }
            jp_ws(&j);
            if (j.p >= j.end) return 0;
            if (*j.p == ',') { j.p++; continue; }
            if (*j.p == '}') { j.p++; break; }
            return 0;
        }
    }
    jp_ws(&j);
    return j.p == j.end;
}
