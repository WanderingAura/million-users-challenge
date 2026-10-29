# C + io_uring, one ring per core

| | |
|---|---|
| Language | C (gnu11), one translation unit (`src/main.c` includes every other file) |
| Compiler | clang 18 (`clang-18` from Ubuntu 24.04's archive), `-O2`, target picked from the CPU's feature flags (Cascade Lake: `-march=x86-64-v4 -mpclmul -mtune=cascadelake`) |
| Framework | None. Hand-written HTTP/1.1 server on raw io_uring syscalls (no liburing) |
| Postgres driver | None. A small v3 wire-protocol client on the same rings: prepared statements, binary results, pipelining, SCRAM-SHA-256 |
| JSON, gzip, JWT | Written for this server: an escaping writer, a strict parser, a gzip writer that knows the feed's layout, HS256 |
| Dependencies | glibc only. `install.sh` installs `clang-18`, `llvm-18` and `libclang-rt-18-dev` (the last two only for the optional PGO build) |
| Kernel | Ubuntu 24.04's 6.8. Every io_uring feature used was checked on `6.8.0-147-generic` (see "Checked on") |

```bash
sudo bash install.sh
bash build.sh            # build/server, then runs the self-test
DATABASE_URL=postgres://... JWT_SECRET=... HOST=0.0.0.0 PORT=80 EXTRA_PORT=81 bash start.sh
```

Optional environment: `THREADS` (default: CPUs in the affinity mask), `DB_READ_CONNS` (total read connections,
default 64 split over the cores with 6 to 16 per core), `BATCH_MIN` / `BATCH_US` (wake-up batching, default 128
completions or 4000 µs), `CPU_AFFINITY=1` (off by default, below). `build.sh` takes `PGO=1` and `SIMD=scalar`.

## Design

**One event loop per core, nothing shared.** Each core has its own io_uring, its own pair of `SO_REUSEPORT`
listeners (ports 80 and 81), its own client connections, its own Postgres connections and its own memory. After
startup no core reads or writes anything another core writes: no locks, atomics or queues.

**Rings.** Each ring is created with `SINGLE_ISSUER | DEFER_TASKRUN | SUBMIT_ALL | NO_SQARRAY`. There is no kernel
polling thread, because on 4 cores that would burn a quarter of the box. One `io_uring_enter` per loop iteration
submits everything and waits for at least `BATCH_MIN` completions or `BATCH_US`, whichever comes first. Bigger
batches cut kernel time per request, measured below. The p95 limit is 500 ms, and batching adds at most 4 ms.

**Direct descriptors.** Each ring registers a sparse file table of 1,048,576 slots, the 6.8 per-ring maximum.
Accepts are multishot into that table, and a client is known only by its slot number, which also indexes the
connection table. Slots 0 to 511 are reserved for Postgres sockets, which are registered too. A generation counter
per slot keeps a late reply from reaching a new connection that reuses the slot.

**Receive buffers.** A multishot `recv` per connection selects from a pool of 8,192 2 KB buffers per core, so an
idle connection owns no buffer. Ubuntu's 6.8 kernel rejects *every* ring-mapped buffer registration
(`IORING_REGISTER_PBUF_RING` returns `EINVAL`, user-memory or kernel-allocated; this is what stopped the Zig entry).
So the pool uses classic provided buffers (`IORING_OP_PROVIDE_BUFFERS`), which work there with multishot recv.
Buffers returned during an iteration are marked in a bitmap and handed back at the end of it as contiguous runs,
one SQE per run, with the success completion suppressed.

**Sends.** Each response goes out in one `send` with `MSG_DONTWAIT`. With `DEFER_TASKRUN` that send copies the
bytes into the socket while `io_uring_enter` submits it (checked on 6.8). So the response can live in a per-core
arena that is reset every iteration: two arenas alternate, and one is reset once every send pointing into it
has completed. If a send is short or would block, the rest is copied into a 64 KB block from a per-core pool and
sent with a normal, polled send. Later responses on that connection queue behind it, so order is kept.

**Memory.** All user-space memory is one `mmap` reserved at startup and carved into per-core regions. These hold
the connection table (40 bytes per slot), receive buffers, two 32 MB arenas, the send-block pool, Postgres send and
receive buffers, reply queues and write batches. The parts the request path touches every time are pre-faulted. A
`malloc` override reports any heap allocation on a serving thread after startup (`ALLOC_GUARD=abort` makes it
fatal). None happens: training runs and load tests ran with it set.

**Postgres.**
- **The SPEC's SQL, prepared once per connection** (rule 3). Results come back in binary. `created_at` arrives
  as microseconds since 2000 and is formatted from a day table built at startup, truncated to milliseconds.
- **Reads are pipelined**, each to the read connection with the fewest replies waiting. Each loop iteration adds
  one `Sync` per connection, which ends one implicit transaction per batch instead of one per query. The
  Bind/Execute bytes for feed, post and health come from templates; only the post id is patched in.
- **Writes use group commit** (rule 8 allows it), on one write connection per core. While a batch is
  committing, new likes and posts collect. When its `ReadyForQuery` arrives, everything collected goes out as one
  transaction: one `Sync`, one commit, one WAL flush. Every reply is sent only after its commit. A like's row count
  (`INSERT 0 1` / `INSERT 0 0`) gives 201 or 200, which also handles two likes for the same post in one batch.
  If one statement fails (a like on a missing post fails its foreign key and rolls back the whole batch), the
  batch is replayed one statement per transaction so each request gets its own answer.
- **Lost connections.** Requests waiting on a lost connection get a 500, or a 503 for `/health`. The core
  reconnects at most once per second, touching only its own state.

**Gzip, for the feed only.** The JSON writer records where the constant key fragments sit (`,"body":"`,
`","created_at":"`, `","author":"`, `","like_count":`, `},{"id":`). The gzip writer turns each into a
back-reference to the same fragment in the previous post, with no search. It extends each match into the
following value, which covers shared timestamp prefixes. Everything else goes through a small greedy LZ77 with
a 4-byte hash and one candidate.
- **One Huffman code for every response.** Each response is one dynamic-Huffman block, and the code and its header
  bits are built once at startup from a synthetic corpus generated in code (never from the database). So nothing is
  counted or built per response. Every symbol keeps a code, so any input can be encoded.
- **CRC32** uses PCLMUL folding.
- **Result.** The seed's feed (5,102 bytes) compresses to 2,061 bytes in about 2.8 µs. `gzip -1` gives 1,982 and
  `gzip -6` gives 1,886. All three are two TCP segments. Single posts and small replies go uncompressed.

**JWT.** Verified in full on every request (rule 9). The HMAC key's inner and outer SHA-256 states are computed
once, which is a key schedule, not a cache: each token still costs a full HMAC. Only HS256 is accepted, and `exp`
is required. The signature is compared in constant time after base64url-encoding our own MAC. The common header
is matched as a string; any other header is decoded and checked for `"alg":"HS256"`.

**SIMD.** Header-end search, the JSON escape scan and the UTF-8 fast path use AVX-512BW/VL mask compares on
**256-bit** vectors, with masked tail loads so nothing reads past a buffer. 256-bit width keeps Cascade Lake out of
its AVX-512 frequency drop, which would also slow the kernel's networking on that core. A scalar path covers arm64
and x86 machines without AVX-512 (CI runners). The self-test checks the two paths give identical results on
200,000 random inputs.

**HTTP.** The request line plus `Content-Length`, `Authorization`, `Connection`, `Accept-Encoding`,
`Transfer-Encoding` and `Expect` are parsed. Requests may be pipelined, and responses keep their order. Keep-alive
has no idle timeout. Each response is one `send`: status line, `Content-Type`, `Content-Encoding` when gzipped, and
`Content-Length`, with the header written into headroom just before the body.

**Opt-in: CPU steering (`CPU_AFFINITY=1`, off).** This pins loop *i* to the *i*-th CPU of the mask. It also
attaches a classic BPF program to each port's `SO_REUSEPORT` group that picks the listener by the CPU handling the
incoming SYN. A connection is then owned by the loop on the CPU where its packets are processed. It is off because
rule 13 says "no pinning of CPU", and whether that covers a process pinning its own threads is the organiser's
call. Its benefit can't be measured on loopback.

## Checked on

- **Ubuntu 24.04, kernel `6.8.0-147-generic`, x86-64.** A KVM guest with QEMU's Cascade Lake CPU model (AVX-512
  F/BW/VL and PCLMUL, no SHA-NI or VBMI). It ran `install.sh`, `build.sh` with clang 18 (both the plain and the PGO
  build), the self-test and `test/run.sh` (42/42) against Postgres 18. It also ran under the repo's
  `challenge.service` as user `challenge` on ports 80 and 81 after `box/setup-app-box.sh`. 200,000 mload users held
  with 0 errors in that VM until the load generator itself ran out of memory.
- **Ubuntu 24.04, kernel `6.8.0-147-generic`, arm64** (emulated). `install.sh`, `build.sh` (scalar path), the
  self-test and `test/run.sh` (42/42).
- **The developer's machine**, Linux 7.2 and clang 23. The self-test on both paths, also under
  AddressSanitizer/UBSan, and `test/run.sh` (42/42).

## Measurements (local, not the benchmark boxes)

Ryzen 7 7700X (Zen 4), Linux 7.2. Postgres 18 in Docker on 4 other CPUs, and mload on 4 more, all over loopback.
"CPU per request" is the server process's user + system time divided by requests, over the hold. Loopback puts
the receiving side's TCP work on the sender's CPU, so the kernel share differs from the benchmark's NIC path. The
numbers are for comparing settings, not for predicting scores.

| Setup | Users, think-scale | req/s (hold) | p95 / p99 | Server CPU per request |
|---|---|---|---|---|
| 4 cores, defaults (16 read connections each) | 40,000, 0.1 | ~42,000 | 13.6 / 18.3 ms | 6.7 µs (user 1.2 + kernel 5.5) |
| 1 core, defaults (16 read connections) | 60,000, 0.1 | ~63,000 | 12.6 / 28.7 ms | 4.9 µs (user 0.9 + kernel 3.9) |

On 4 cores each loop sees a quarter of the load, so its batches are smaller and the cost per request is higher;
neither run is anywhere near saturating the server (the database and the load generator, on 4 CPUs each, limit
these runs). The kernel is about 80% of the cost. The user-space hot paths, measured with `build/server --bench`:

| Operation | Time |
|---|---|
| Feed JSON, 20 posts, 4.4 KB | 0.33 µs |
| Gzip of that feed | 2.8 µs |
| JWT verify | 0.81 µs |
| HTTP request parse | 30 ns |
| Single post JSON | 14 ns |

The same benchmark in the 6.8 Cascade Lake-model VM, comparing the AVX-512 path with `SIMD=scalar`. The VM runs
on a Zen 4 host, so Cascade Lake's clock behaviour isn't reproduced.

| Operation | AVX-512 + PCLMUL | Scalar |
|---|---|---|
| Feed JSON | 326 ns | 1,669 ns |
| Gzip | 2.7 µs | 4.0 µs |
| CRC32 of 4.4 KB | 208 ns | 1,507 ns |

**Wake-up batching** (1 core, 60,000 users at think-scale 0.1, 64 read connections):

| `BATCH_MIN` / `BATCH_US` | CPU per request | p99 |
|---|---|---|
| 1 / 0 (no batching) | 7.7 µs | 32 ms |
| 32 / 2000 | 6.3 µs | 32 ms |
| **128 / 4000 (default)** | 6.0 µs | 38 ms |
| 256 / 8000 | 6.2 µs | 42 ms |

**Read connections per core** (same load, 128 / 4000): 64 connections 6.0 µs, 24 connections 5.2 µs,
8 connections 5.0 µs. Fewer, deeper pipelines mean fewer sends and receives per iteration. The database still
needs enough backends to run feeds in parallel, hence 64 in total, 6 to 16 per core.

**Memory per connection** (6.8 VM, 200,000 connections): the server's RSS grew about 230 bytes per connection.
The kernel's slab grew about 3.9 KB per socket, measured over both ends of loopback. At 3,000,000 connections
that is roughly 12 GB of kernel memory and under 1 GB in the server.

### Does PGO help? No

`PGO=1 bash build.sh` builds with `-fprofile-instr-generate`, runs `build/server --train` and rebuilds with the
profile. Training starts an in-process mock Postgres (wire protocol, canned binary rows, a foreign-key error on
some likes) and drives the real server over loopback with mload's request mix plus error paths. Nothing is
committed: the profile is made on the box at build time.

The plain and PGO builds were compared on the same commit, alternating runs, three of each:

| Measure | Plain | PGO |
|---|---|---|
| Server CPU per request, 1 core, ~63,000 req/s | 6.4, 6.4, 6.2 µs | 6.3, 6.3, 6.3 µs |
| p99 | 29.8, 29.5, 28.4 ms | 27.6, 27.8, 27.8 ms |
| `--bench`: gzip / feed JSON / JWT | 2.78–2.84 µs / 332–341 ns / 804–814 ns | 2.78–2.85 µs / 334–337 ns / 804–822 ns |

The CPU difference is within run-to-run noise. User space is only about 15% of the cost, and as a single
translation unit the compiler already sees all of it. **The default build is plain `-O2`;** PGO stays as an option.

## Not measured

- **The benchmark hardware.** Cascade Lake clocks, the VM's single-queue NIC with RPS, a real million
  connections, and 8- and 4-core runs with the kernel's network processing on those cores.
- **The effect of `CPU_AFFINITY=1`,** which only shows on a real NIC.

## License

MIT, under the repo's [license](../../LICENSE).
