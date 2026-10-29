#!/usr/bin/env bash
# Runs the server in the foreground (systemd ExecStart). Config from the environment: DATABASE_URL, JWT_SECRET,
# HOST, PORT, EXTRA_PORT. One event loop per CPU in the affinity mask (4, 8 or 16 cores need no setting).
# Optional: THREADS, DB_READ_CONNS (total; default 64 split over the cores, 6-16 per core),
# BATCH_MIN / BATCH_US (wake-up batching, default 128 completions / 4000 us).
set -euo pipefail
ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
exec "$(cd "$(dirname "$0")" && pwd)/build/server"
