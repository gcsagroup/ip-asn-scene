#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p dist

LOCAL_GOOS="$(go env GOOS)"
LOCAL_GOARCH="$(go env GOARCH)"

GOFLAGS="-trimpath"
LDFLAGS="-s -w"

CGO_ENABLED=0 go build $GOFLAGS -ldflags "$LDFLAGS" -o ./ipasn ./cmd/ipasn
CGO_ENABLED=0 GOOS="$LOCAL_GOOS" GOARCH="$LOCAL_GOARCH" go build $GOFLAGS -ldflags "$LDFLAGS" -o "dist/ipasn-$LOCAL_GOOS-$LOCAL_GOARCH" ./cmd/ipasn
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $GOFLAGS -ldflags "$LDFLAGS" -o dist/ipasn-linux-amd64 ./cmd/ipasn
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $GOFLAGS -ldflags "$LDFLAGS" -o dist/ipasn-windows-amd64.exe ./cmd/ipasn

printf '%s\n' "built ./ipasn"
printf '%s\n' "built dist/ipasn-$LOCAL_GOOS-$LOCAL_GOARCH"
printf '%s\n' "built dist/ipasn-linux-amd64"
printf '%s\n' "built dist/ipasn-windows-amd64.exe"
