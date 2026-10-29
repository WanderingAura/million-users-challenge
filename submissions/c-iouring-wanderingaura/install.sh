#!/usr/bin/env bash
# Ubuntu 24.04 (x86_64 or arm64), run as root. Idempotent. Installs what is needed to BUILD this server: clang 18,
# llvm 18 and libclang-rt-18-dev (llvm-profdata and the profile runtime for the profile-guided build) from Ubuntu's
# own archive, plus the kernel UAPI
# headers (linux-libc-dev, the 6.8 io_uring API). RUNNING it needs nothing extra: the binary links only glibc.
set -euo pipefail
need=()
command -v clang-18 >/dev/null 2>&1 || need+=(clang-18)
command -v llvm-profdata-18 >/dev/null 2>&1 || need+=(llvm-18)
# the profile runtime for -fprofile-instr-generate is packaged separately
ls /usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.profile-*.a >/dev/null 2>&1 || need+=(libclang-rt-18-dev)
[ -f /usr/include/linux/io_uring.h ] || need+=(linux-libc-dev)
[ -f /usr/include/stdio.h ] || need+=(libc6-dev)
if [ ${#need[@]} -gt 0 ]; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${need[@]}"
fi
clang-18 --version | head -1
