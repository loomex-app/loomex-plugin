#!/bin/sh

# The packaged release supports macOS and Linux, both of which provide
# /bin/sh. Keep this bootstrap dependency-free: it runs before Loomex can
# expose any MCP tools, so relying on a host Node/Python installation would
# turn an otherwise self-contained package into a multi-install experience.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
plugin_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
manifest="$plugin_root/packaging/runtime-manifest.json"

fail() {
  printf '%s\n' "Unable to start Loomex MCP: $*" >&2
  exit 1
}

assert_executable() {
  candidate=$1
  [ -f "$candidate" ] || fail "missing regular executable: $candidate"
  [ ! -L "$candidate" ] || fail "refusing symbolic-link executable: $candidate"
  [ -x "$candidate" ] || fail "bundled executable is not executable: $candidate"
}

# Source checkouts intentionally have no runtime manifest. Development
# overrides are accepted only there. An assembled release always has the
# manifest, so LOOMEX_MCP_BINARY cannot replace checksum-bound package bytes.
if [ ! -f "$manifest" ]; then
  [ "${LOOMEX_ALLOW_DEVELOPMENT_BINARY:-}" = "1" ] || \
    fail "source checkouts require LOOMEX_ALLOW_DEVELOPMENT_BINARY=1"
  case "${LOOMEX_MCP_BINARY:-}" in
    /*) ;;
    *) fail "LOOMEX_MCP_BINARY must be an absolute path" ;;
  esac
  assert_executable "$LOOMEX_MCP_BINARY"
  exec env LOOMEX_PLUGIN_ROOT="$plugin_root" "$LOOMEX_MCP_BINARY" "$@"
fi

case "$(uname -s 2>/dev/null || true)" in
  Darwin) platform=darwin ;;
  Linux)
    platform=linux
    glibc_report=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
    case "$glibc_report" in
      "glibc "*) glibc_version=${glibc_report#glibc } ;;
      *) fail "packaged Linux releases require GLIBC 2.35 or newer" ;;
    esac
    glibc_major=${glibc_version%%.*}
    glibc_minor=${glibc_version#*.}
    glibc_minor=${glibc_minor%%.*}
    case "$glibc_major:$glibc_minor" in
      *[!0-9:]*) fail "cannot determine the host GLIBC version" ;;
    esac
    if [ "$glibc_major" -lt 2 ] || { [ "$glibc_major" -eq 2 ] && [ "$glibc_minor" -lt 35 ]; }; then
      fail "packaged Linux releases require GLIBC 2.35 or newer; found $glibc_version"
    fi
    ;;
  *) fail "this package supports only macOS and Linux" ;;
esac
case "$(uname -m 2>/dev/null || true)" in
  arm64|aarch64) architecture=arm64 ;;
  x86_64|amd64) architecture=x64 ;;
  *) fail "unsupported processor architecture" ;;
esac

target="$platform-$architecture"
target_dir="$plugin_root/bin/$target"
mcp="$target_dir/loomex-mcp"
runtime="$target_dir/loomex"
assert_executable "$mcp"
assert_executable "$runtime"

# The assembler emits checksum sidecars from the same immutable manifest that
# the Rust bootstrap validates again before installing the durable runtime.
verify_checksum() {
  candidate=$1
  sidecar="$candidate.sha256"
  [ -f "$sidecar" ] && [ ! -L "$sidecar" ] || fail "missing checksum for $candidate"
  IFS= read -r expected < "$sidecar" || fail "cannot read checksum for $candidate"
  case "$expected" in
    *[!0-9a-f]*|'') fail "invalid checksum for $candidate" ;;
  esac
  [ "${#expected}" -eq 64 ] || fail "invalid checksum for $candidate"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$candidate" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$candidate" | awk '{print $1}')
  else
    fail "no SHA-256 verifier is available on this host"
  fi
  [ "$actual" = "$expected" ] || fail "integrity check failed for $candidate"
}

verify_checksum "$mcp"
verify_checksum "$runtime"

exec env \
  LOOMEX_PLUGIN_ROOT="$plugin_root" \
  LOOMEX_RUNNER_BINARY="$runtime" \
  LOOMEX_OFFICIAL_PACKAGE=1 \
  "$mcp" "$@"
