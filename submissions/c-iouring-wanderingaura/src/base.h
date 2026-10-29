// base.h: types, macros, arenas. Everything else includes this first (unity build: main.c includes all .c files).
#ifndef BASE_H
#define BASE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef s32 b32;
typedef size_t umm;
typedef double f64;

#define internal static
#define global static

#define ArrayCount(a) (sizeof(a) / sizeof((a)[0]))
#define Kilobytes(n) ((u64)(n) << 10)
#define Megabytes(n) ((u64)(n) << 20)
#define Min(a, b) ((a) < (b) ? (a) : (b))
#define Max(a, b) ((a) > (b) ? (a) : (b))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define AlignUp(x, a) (((x) + ((a) - 1)) & ~((u64)(a) - 1))

internal void assert_fail(const char *file, int line, const char *what)
{
    fprintf(stderr, "assert failed %s:%d: %s\n", file, line, what);
    abort();
}
#define Assert(c) do { if (unlikely(!(c))) assert_fail(__FILE__, __LINE__, #c); } while (0)

// The fast path is x86-64 with AVX-512BW/VL and PCLMUL (Cascade Lake, the benchmark box). Everything else
// (arm64, x86 without AVX-512, SIMD=scalar builds) takes the portable scalar path. Both produce identical bytes.
#if defined(__x86_64__) && defined(__AVX512BW__) && defined(__AVX512VL__) && defined(__PCLMUL__) && !defined(FORCE_SCALAR)
#define FAST_X86 1
#include <immintrin.h>
#else
#define FAST_X86 0
#endif

// Ring head/tail access. x86 is TSO: plain loads/stores plus a compiler barrier. arm64 needs acquire/release.
#if defined(__x86_64__)
#define CompilerBarrier() __asm__ __volatile__("" ::: "memory")
#define LoadAcquire32(p) ({ u32 v_ = *(volatile u32 *)(p); CompilerBarrier(); v_; })
#define StoreRelease32(p, v) do { CompilerBarrier(); *(volatile u32 *)(p) = (v); } while (0)
#define StoreRelease16(p, v) do { CompilerBarrier(); *(volatile u16 *)(p) = (v); } while (0)
#else
#define CompilerBarrier() __asm__ __volatile__("" ::: "memory")
#define LoadAcquire32(p) __atomic_load_n((u32 *)(p), __ATOMIC_ACQUIRE)
#define StoreRelease32(p, v) __atomic_store_n((u32 *)(p), (u32)(v), __ATOMIC_RELEASE)
#define StoreRelease16(p, v) __atomic_store_n((u16 *)(p), (u16)(v), __ATOMIC_RELEASE)
#endif

internal inline u16 load_u16(const void *p) { u16 v; memcpy(&v, p, 2); return v; }
internal inline u32 load_u32(const void *p) { u32 v; memcpy(&v, p, 4); return v; }
internal inline u64 load_u64(const void *p) { u64 v; memcpy(&v, p, 8); return v; }
internal inline void store_u16(void *p, u16 v) { memcpy(p, &v, 2); }
internal inline void store_u32(void *p, u32 v) { memcpy(p, &v, 4); }
internal inline void store_u64(void *p, u64 v) { memcpy(p, &v, 8); }
internal inline u16 load_be16(const void *p) { return __builtin_bswap16(load_u16(p)); }
internal inline u32 load_be32(const void *p) { return __builtin_bswap32(load_u32(p)); }
internal inline u64 load_be64(const void *p) { return __builtin_bswap64(load_u64(p)); }
internal inline void store_be16(void *p, u16 v) { store_u16(p, __builtin_bswap16(v)); }
internal inline void store_be32(void *p, u32 v) { store_u32(p, __builtin_bswap32(v)); }
internal inline void store_be64(void *p, u64 v) { store_u64(p, __builtin_bswap64(v)); }

typedef struct {
    u8 *data;
    umm count;
} Str;
#define S(lit) ((Str){(u8 *)(lit), sizeof(lit) - 1})

internal inline b32 str_eq(Str a, Str b) { return a.count == b.count && memcmp(a.data, b.data, a.count) == 0; }

// ---- arena: one big reservation, bump allocation, reset in O(1) ----
typedef struct {
    u8 *base;
    umm size;
    umm used;
} Arena;

internal inline void *arena_push(Arena *a, umm n)
{
    Assert(a->used + n <= a->size);
    void *p = a->base + a->used;
    a->used += n;
    return p;
}
internal inline void *arena_push_aligned(Arena *a, umm n, umm align)
{
    a->used = AlignUp(a->used, align);
    return arena_push(a, n);
}
internal inline umm arena_left(Arena *a) { return a->size - a->used; }
internal inline void arena_reset(Arena *a) { a->used = 0; }

#endif
