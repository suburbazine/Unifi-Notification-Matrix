#!/usr/bin/env bash
# Builds notifymatrix for local use on Linux.
#
# The DEVELOPER path. Releases are built and signed by
# .github/workflows/release.yml; there is no local signing step here, because
# Linux artefacts are signed keylessly by that workflow's OIDC identity and
# there is no key on a developer machine that could do it.
#
#   ./build.sh                 build for this host
#   ./build.sh --all           cross-compile every shipping target
#   ./build.sh --skip-tests    skip the test gate (use sparingly)
set -euo pipefail
cd "$(dirname "$0")"

all=0
skip_tests=0
for arg in "$@"; do
  case "$arg" in
    --all) all=1 ;;
    --skip-tests) skip_tests=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# The shipping constraint. Static binaries that run anywhere including Alpine
# and containers, reproducible output, and no cgo-linked dependency creeping
# into the module graph.
export CGO_ENABLED=0

# A local build must never claim to be a release: if a support case arrives
# quoting a version, it has to be possible to tell which binary they ran.
if version=$(git describe --tags --exact-match HEAD 2>/dev/null); then
  version="${version#v}"
else
  version="$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0)"
  version="${version#v}-dev"
fi

ldflags="-s -w -buildid= -X main.version=${version}"

go vet ./...
if [ "$skip_tests" -eq 0 ]; then
  go test ./...
fi

build_one() {
  local goos="$1" goarch="$2" ext="${3:-}"
  local out="dist/notifymatrix-${goos}-${goarch}${ext}"
  mkdir -p dist
  GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "$ldflags" -o "$out" ./cmd/notifymatrix
  printf '  %s\n' "$(sha256sum "$out")"
}

if [ "$all" -eq 1 ]; then
  echo "building all shipping targets (version ${version})"
  build_one linux amd64
  build_one linux arm64
  build_one windows amd64 .exe
else
  go build -trimpath -ldflags "$ldflags" -o notifymatrix ./cmd/notifymatrix
  echo "built ./notifymatrix ${version}"
fi

cat <<'NOTE'

Local binaries are unsigned. Released binaries carry an Authenticode signature
(Windows) and a keyless cosign signature plus SLSA provenance (all platforms);
see docs/RELEASING.md for how to verify one, and for how to reproduce a release
build byte for byte and compare hashes.
NOTE
