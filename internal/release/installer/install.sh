#!/bin/sh
# Newtype installer for macOS and Linux (arm64, amd64).
#
#   curl -fsSL https://lic.newtype-ai.com/install.sh | sh
#
# Reads /v1/releases/latest.txt (key=value lines from the signed release
# manifest; the server verified its Ed25519 signature), downloads
# /v1/releases/files/<sha256>, and checks the size and SHA-256 BEFORE
# installing to ~/.local/share/newtype/bin/newtype-<version>, linked from
# ~/.local/bin/newtype. No sudo, no eval of downloaded data, nothing outside
# those two folders is changed.
#
# Trust: this first install trusts HTTPS plus the SHA-256 from the signed
# manifest. Later updates (`newtype update`, TUI /update) are verified inside
# the newtype client by the Ed25519 release signature with its pinned key.
#
# NEWTYPE_INSTALL_ORIGIN overrides the origin (https://..., or http:// on
# 127.0.0.1/localhost for tests).
set -eu
umask 022

ORIGIN=${NEWTYPE_INSTALL_ORIGIN:-https://lic.newtype-ai.com}

say() { printf '%s\n' "$*"; }
die() {
	printf 'newtype install: %s\n' "$*" >&2
	exit 1
}

case $ORIGIN in
https://*) ;;
http://127.0.0.1:* | http://localhost:*) ;;
*) die "NEWTYPE_INSTALL_ORIGIN must be an https:// origin" ;;
esac
case $ORIGIN in
*[!A-Za-z0-9.:/-]* | */) die "invalid origin: $ORIGIN" ;;
esac

[ -n "${HOME:-}" ] && [ -d "$HOME" ] || die "HOME is not set to a directory"

os=$(uname -s)
case $os in
Darwin) os=darwin ;;
Linux) os=linux ;;
*) die "unsupported OS: $os (macOS and Linux only; on Windows use: irm https://lic.newtype-ai.com/install.ps1 | iex)" ;;
esac
arch=$(uname -m)
case $arch in
arm64 | aarch64) arch=arm64 ;;
x86_64 | amd64) arch=amd64 ;;
*) die "unsupported CPU: $arch (arm64 and amd64 only)" ;;
esac
# An x86_64 shell under Rosetta on Apple silicon still gets the arm64 build.
if [ "$os" = darwin ] && [ "$arch" = amd64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
	arch=arm64
fi

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --proto '=https,http' --retry 2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
elif command -v openssl >/dev/null 2>&1; then
	sha256() { openssl dgst -sha256 -r "$1" | cut -d ' ' -f 1; }
else
	die "sha256sum, shasum or openssl is required to check the download"
fi

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t newtype-install)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fetch "$ORIGIN/v1/releases/latest.txt" "$tmp/latest.txt" ||
	die "no published release found at $ORIGIN (none is published yet, or the service is unreachable)"

# Plain text only: values are matched against strict patterns, never evaluated.
version=$(sed -n 's/^version=//p' "$tmp/latest.txt" | head -n 1)
line=$(sed -n "s/^$os-$arch=//p" "$tmp/latest.txt" | head -n 1)
printf '%s\n' "$version" | grep -Eq '^[0-9][0-9A-Za-z.-]{0,63}$' || die "release information is malformed"
[ -n "$line" ] || die "release $version has no build for $os/$arch"
sum=${line%% *}
size=${line#* }
printf '%s\n' "$sum" | grep -Eq '^[0-9a-f]{64}$' || die "release information is malformed"
printf '%s\n' "$size" | grep -Eq '^[1-9][0-9]{0,9}$' || die "release information is malformed"

say "Newtype $version ($os/$arch): downloading and checking SHA-256 ..."
fetch "$ORIGIN/v1/releases/files/$sum" "$tmp/newtype" || die "download failed"
got_size=$(wc -c <"$tmp/newtype" | tr -d ' ')
[ "$got_size" = "$size" ] || die "download has $got_size bytes, the signed manifest says $size; nothing installed"
got_sum=$(sha256 "$tmp/newtype")
[ "$got_sum" = "$sum" ] || die "SHA-256 mismatch (got $got_sum, want $sum); nothing installed"

share="$HOME/.local/share/newtype/bin"
bindir="$HOME/.local/bin"
target="$share/newtype-$version"
link="$bindir/newtype"
mkdir -p "$share" "$bindir"

chmod 0755 "$tmp/newtype"
cp "$tmp/newtype" "$share/.newtype-install.$$"
mv -f "$share/.newtype-install.$$" "$target"

# A plain file at ~/.local/bin/newtype (a manual copy) is kept aside, never deleted.
if [ -e "$link" ] && [ ! -L "$link" ]; then
	kept="$link.prev-$(date +%Y%m%d%H%M%S)"
	mv "$link" "$kept"
	say "kept the existing $link as $kept"
fi
ln -s "$target" "$bindir/.newtype-link.$$"
mv -f "$bindir/.newtype-link.$$" "$link"

say "installed: $target"
say "linked:    $link -> $target"
if out=$("$link" --version 2>&1); then
	say "check:     $out"
else
	say "warning: '$link --version' did not run; the file is installed, see the message above"
fi

case ":${PATH:-}:" in
*":$bindir:"*) ;;
*)
	say ""
	say "$bindir is not on your PATH. Add it, e.g. for zsh:"
	say "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc && exec zsh"
	say "(bash: ~/.bashrc). PATH 에 ~/.local/bin 을 추가하세요."
	;;
esac

say ""
say "Next: run 'newtype' in a terminal. The first run needs you: e-mail enrolment approval,"
say "folder trust and model setup. An AI agent must stop here and hand over to the person."
say "다음: 터미널에서 newtype 을 실행하세요. 첫 실행(이메일 등록 승인·폴더 신뢰·모델 설정)은 사람이 직접 합니다."
