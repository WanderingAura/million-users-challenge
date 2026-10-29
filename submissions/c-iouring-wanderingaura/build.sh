#!/usr/bin/env bash
# Builds build/server from src/main.c (one translation unit). With PGO=1 the build is profile-guided: an
# instrumented binary runs `--train` (a mock Postgres and a synthetic request mix over loopback), the profile is
# merged, and the final binary is compiled with it. The default is a plain -O2 build: PGO measured no gain (README).
#   SIMD=scalar  force the portable path (what arm64 and non-AVX-512 machines get anyway)
#   MARCH=...    override -march (default: picked from /proc/cpuinfo feature flags)
set -euo pipefail
cd "$(dirname "$0")"

pick() { for c in "$@"; do command -v "$c" >/dev/null 2>&1 && { echo "$c"; return; }; done; }
CC="${CC:-$(pick clang-18 clang)}"
[ -n "$CC" ] || { echo "clang not found (run install.sh)"; exit 1; }
# llvm-profdata must match the compiler's profile format: same major version
CCMAJOR="$("$CC" -dumpversion | cut -d. -f1)"
if [ -z "${PROFDATA:-}" ]; then
  for c in "llvm-profdata-$CCMAJOR" "$(dirname "$(readlink -f "$(command -v "$CC")")")/llvm-profdata" llvm-profdata; do
    if command -v "$c" >/dev/null 2>&1 && "$c" --version 2>/dev/null | grep -q "version $CCMAJOR\."; then PROFDATA="$c"; break; fi
  done
fi
PROFDATA="${PROFDATA:-}"

# Target: chosen from the CPU's feature flags rather than -march=native's CPU-name detection (which can guess
# wrong under virtualisation). Cascade Lake (the benchmark box) gets x86-64-v4 (AVX-512 F/BW/CD/DQ/VL) + PCLMUL.
ARCH_FLAGS=()
if [ -n "${MARCH:-}" ]; then
  ARCH_FLAGS=("-march=$MARCH")
else
  case "$(uname -m)" in
    x86_64)
      CPUF=" $(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2) "
      has() { case "$CPUF" in *" $1 "*) return 0 ;; esac; return 1; }
      if has avx512f && has avx512bw && has avx512vl && has avx512dq && has avx512cd && has pclmulqdq; then
        ARCH_FLAGS=(-march=x86-64-v4 -mpclmul -mtune=cascadelake)
      elif has avx2 && has bmi2 && has fma && has movbe; then
        ARCH_FLAGS=(-march=x86-64-v3)
        has pclmulqdq && ARCH_FLAGS+=(-mpclmul)
      else
        ARCH_FLAGS=(-march=x86-64-v2)
      fi ;;
    aarch64) ARCH_FLAGS=(-march=armv8-a) ;;
  esac
fi
FLAGS=(-std=gnu11 -O2 -g0 "${ARCH_FLAGS[@]}" -fno-plt -fomit-frame-pointer -fno-strict-aliasing
       -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers)
case "$(uname -m)" in
  x86_64) FLAGS+=(-mprefer-vector-width=256) ;;
esac
echo "flags: ${ARCH_FLAGS[*]}"
[ "${SIMD:-}" = scalar ] && FLAGS+=(-DFORCE_SCALAR)
LIBS=(-pthread)

mkdir -p build
pgo_build() {
  rm -rf build/pgo && mkdir -p build/pgo
  "$CC" "${FLAGS[@]}" -DNO_ALLOC_GUARD -fprofile-instr-generate -o build/server-instr src/main.c "${LIBS[@]}" &&
  LLVM_PROFILE_FILE="build/pgo/train-%p.profraw" ./build/server-instr --train &&
  "$PROFDATA" merge -o build/pgo/train.profdata build/pgo/*.profraw &&
  "$CC" "${FLAGS[@]}" -fprofile-instr-use=build/pgo/train.profdata -Wno-profile-instr-unprofiled \
    -Wno-profile-instr-out-of-date -o build/server src/main.c "${LIBS[@]}"
}
USED_PGO=0
if [ "${PGO:-0}" = 1 ] && [ -n "$PROFDATA" ]; then
  if pgo_build; then USED_PGO=1; else echo "PGO build failed: falling back to a plain build"; fi
  rm -f build/server-instr
fi
[ "$USED_PGO" = 1 ] || "$CC" "${FLAGS[@]}" -o build/server src/main.c "${LIBS[@]}"
./build/server --selftest
echo "built build/server ($("$CC" --version | head -1), PGO=$USED_PGO)"
