#!/usr/bin/env bash
# Run Qdrant from the native arm64 binary. No Docker.
# Storage path is env-configured -- Qdrant has no --storage-dir flag.
set -euo pipefail
cd "$(dirname "$0")/.."
exec env \
  QDRANT__STORAGE__STORAGE_PATH=./qdrant_storage \
  QDRANT__SERVICE__HTTP_PORT=6333 \
  QDRANT__TELEMETRY_DISABLED=true \
  ./bin/qdrant "$@"
