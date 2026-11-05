#!/usr/bin/env bash
# Cross-compile static env-gen binaries into dist/. Only needs Go.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p dist
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags='-s -w' -o dist/env-gen-linux-$arch .
done
ls -lh dist
