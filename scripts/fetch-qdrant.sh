#!/usr/bin/env bash
# bin/ is gitignored (73MB binary), so fetch it on a fresh clone.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-v1.19.1}"
ARCH="$(uname -m)"; OS="$(uname -s)"
case "$OS-$ARCH" in
  Darwin-arm64) ASSET="qdrant-aarch64-apple-darwin.tar.gz" ;;
  Darwin-x86_64) ASSET="qdrant-x86_64-apple-darwin.tar.gz" ;;
  Linux-x86_64) ASSET="qdrant-x86_64-unknown-linux-musl.tar.gz" ;;
  Linux-aarch64) ASSET="qdrant-aarch64-unknown-linux-musl.tar.gz" ;;
  *) echo "unsupported platform: $OS-$ARCH" >&2; exit 1 ;;
esac
mkdir -p bin
curl -fsSL -o /tmp/qdrant.tar.gz \
  "https://github.com/qdrant/qdrant/releases/download/${VERSION}/${ASSET}"
tar -xzf /tmp/qdrant.tar.gz -C bin/
chmod +x bin/qdrant && rm -f /tmp/qdrant.tar.gz
echo "qdrant ${VERSION} -> bin/qdrant"
