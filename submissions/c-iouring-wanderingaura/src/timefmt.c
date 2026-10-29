// timefmt.c: Postgres binary timestamptz (microseconds since 2000-01-01 UTC) -> "YYYY-MM-DDTHH:MM:SS.mmmZ",
// truncated to milliseconds. Dates come from a table built at startup; integers use a two-digit table.

#define DAY_TABLE_DAYS (366 * 101) // 2000-01-01 .. ~2100
global u8 day_table[DAY_TABLE_DAYS][10];
global char digit_pairs[200];

// Howard Hinnant's civil_from_days, days relative to 1970-01-01.
internal void civil_from_days(s64 z, s64 *y, u32 *m, u32 *d)
{
    z += 719468;
    s64 era = (z >= 0 ? z : z - 146096) / 146097;
    u32 doe = (u32)(z - era * 146097);
    u32 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    s64 yy = (s64)yoe + era * 400;
    u32 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    u32 mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = yy + (*m <= 2);
}

internal void format_date10(u8 *o, s64 days_since_2000)
{
    s64 y;
    u32 m, d;
    civil_from_days(days_since_2000 + 10957, &y, &m, &d);
    if (y < 0) y = 0;
    if (y > 9999) y = 9999;
    o[0] = (u8)('0' + (y / 1000) % 10);
    o[1] = (u8)('0' + (y / 100) % 10);
    o[2] = (u8)('0' + (y / 10) % 10);
    o[3] = (u8)('0' + y % 10);
    o[4] = '-';
    o[5] = (u8)('0' + m / 10);
    o[6] = (u8)('0' + m % 10);
    o[7] = '-';
    o[8] = (u8)('0' + d / 10);
    o[9] = (u8)('0' + d % 10);
}

internal void timefmt_init(void)
{
    for (int i = 0; i < 100; i++) {
        digit_pairs[2 * i] = (char)('0' + i / 10);
        digit_pairs[2 * i + 1] = (char)('0' + i % 10);
    }
    for (s64 i = 0; i < DAY_TABLE_DAYS; i++) format_date10(day_table[i], i);
}

// Writes exactly 24 bytes.
internal inline u8 *write_timestamp(u8 *o, s64 pg_us)
{
    s64 ms = pg_us >= 0 ? pg_us / 1000 : -((-pg_us + 999) / 1000); // floor = truncation toward the past
    s64 days = ms >= 0 ? ms / 86400000 : -((-ms + 86399999) / 86400000);
    u32 msday = (u32)(ms - days * 86400000);
    if (likely(days >= 0 && days < DAY_TABLE_DAYS)) memcpy(o, day_table[days], 10);
    else format_date10(o, days);
    u32 secs = msday / 1000, milli = msday % 1000;
    u32 hh = secs / 3600, mm = (secs / 60) % 60, ss = secs % 60;
    o[10] = 'T';
    memcpy(o + 11, digit_pairs + 2 * hh, 2);
    o[13] = ':';
    memcpy(o + 14, digit_pairs + 2 * mm, 2);
    o[16] = ':';
    memcpy(o + 17, digit_pairs + 2 * ss, 2);
    o[19] = '.';
    o[20] = (u8)('0' + milli / 100);
    memcpy(o + 21, digit_pairs + 2 * (milli % 100), 2);
    o[23] = 'Z';
    return o + 24;
}

internal inline u8 *write_u64(u8 *o, u64 v)
{
    u8 tmp[24];
    u8 *e = tmp + sizeof(tmp), *s = e;
    while (v >= 100) {
        u32 r = (u32)(v % 100);
        v /= 100;
        s -= 2;
        memcpy(s, digit_pairs + 2 * r, 2);
    }
    if (v >= 10) {
        s -= 2;
        memcpy(s, digit_pairs + 2 * v, 2);
    } else {
        *--s = (u8)('0' + v);
    }
    umm n = (umm)(e - s);
    memcpy(o, s, n);
    return o + n;
}

internal inline u8 *write_s64(u8 *o, s64 v)
{
    if (v < 0) {
        *o++ = '-';
        return write_u64(o, (u64)0 - (u64)v);
    }
    return write_u64(o, (u64)v);
}
