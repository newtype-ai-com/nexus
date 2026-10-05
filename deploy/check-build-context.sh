#!/bin/sh
# Lists the exact Docker build context a Dockerfile sees (its own
# <Dockerfile>.dockerignore) and fails if any
# secret-shaped or repository-metadata file would enter it. No image is made:
# the context is exported to a temporary directory and deleted.
# Usage (repository root): deploy/check-build-context.sh [deploy/Dockerfile|deploy/selfhost/Dockerfile]
set -eu
dockerfile=${1:-deploy/Dockerfile}
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/probe" "$tmp/out"
printf 'FROM scratch\nCOPY . /\n' > "$tmp/probe/Dockerfile"
if [ ! -f "$dockerfile.dockerignore" ]; then
  echo "build context: $dockerfile.dockerignore missing" >&2
  exit 1
fi
cp "$dockerfile.dockerignore" "$tmp/probe/Dockerfile.dockerignore"
docker build -q -f "$tmp/probe/Dockerfile" --output "type=local,dest=$tmp/out" . >/dev/null
(cd "$tmp/out" && find . -type f | sed 's#^\./##' | sort) > "$tmp/list"
bad=$(grep -E '^docs/|^deploy/|(^|/)\.env|\.key$|\.pem$|\.age$|(^|/)\.git/' "$tmp/list" || true)
for need in go.mod go.sum cmd/nexus/main.go; do
  grep -qx "$need" "$tmp/list" || { echo "build context: missing $need" >&2; exit 1; }
done
if [ -n "$bad" ]; then
  echo "build context ($dockerfile): forbidden files present:" >&2
  echo "$bad" >&2
  exit 1
fi
echo "build context ($dockerfile): $(wc -l < "$tmp/list" | tr -d ' ') files, none forbidden"
