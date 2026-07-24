#!/bin/sh
set -eu

main() {

# This token is replaced with the immutable release version during assembly.
version="@LOOMEX_RELEASE_VERSION@"
repository="loomex-app/loomex-plugin"
workflow="codex-plugin-release.yml"
issuer="https://token.actions.githubusercontent.com"
base="https://github.com/$repository/releases/download/v$version"

cosign_version="3.1.2"
sigstore_root_commit="a394944ec0ec1dd5e8ba50471e9ded37d88b5daa"
sigstore_root_sha256="6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
sigstore_root_url="https://raw.githubusercontent.com/sigstore/root-signing/$sigstore_root_commit/targets/trusted_root.json"

fail() {
  echo "loomex installer: $*" >&2
  exit 1
}

step() {
  echo "loomex installer: $*" >&2
}

for dependency in curl codex git python3 uname mktemp chmod awk dirname rm mv mkdir; do
  command -v "$dependency" >/dev/null 2>&1 || fail "required command not found: $dependency"
done
python3 - "$version" <<'PY' || fail "release asset contains an invalid embedded version"
import re
import sys

if not re.fullmatch(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
    sys.argv[1],
):
    raise SystemExit(1)
PY

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Darwin) cosign_os=darwin ;;
  Linux) cosign_os=linux ;;
  *) fail "unsupported operating system: $os" ;;
esac
case "$arch" in
  arm64|aarch64) cosign_arch=arm64 ;;
  x86_64|amd64) cosign_arch=amd64 ;;
  *) fail "unsupported CPU architecture: $arch" ;;
esac

case "$cosign_os-$cosign_arch" in
  darwin-amd64) cosign_sha256="acd180f8b015be25240ca33abee8a1e564eb65cdf1a3cee4725456d2dceb7da6" ;;
  darwin-arm64) cosign_sha256="dec1c3f802320b19c2fbcf2dc7bcfb3f258e1c181a046c23a1a074bdf932f10a" ;;
  linux-amd64) cosign_sha256="f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf" ;;
  linux-arm64) cosign_sha256="90e7ae0b5dfd60f20816b52c012addf7fc055ebcc7bea4ce81c428ca8518c302" ;;
  *) fail "unsupported platform" ;;
esac

umask 077
temporary=$(mktemp -d "${TMPDIR:-/tmp}/loomex-codex-install.XXXXXX") || fail "could not create a temporary directory"
case "$temporary" in
  "${TMPDIR:-/tmp}"/loomex-codex-install.*) ;;
  *) fail "temporary directory has an unexpected path" ;;
esac
cleanup() {
  chmod -R u+w "$temporary" 2>/dev/null || true
  rm -rf -- "$temporary"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

download() {
  label=$1
  url=$2
  destination=$3
  partial=${4:-"$destination.partial"}
  preserve_partial=${5:-0}
  if test "$preserve_partial" -eq 1; then
    if test -L "$partial"; then
      rm -f -- "$partial"
    fi
  else
    rm -f -- "$partial" "$destination"
  fi
  step "Downloading $label"
  if test "$preserve_partial" -eq 1 && test -s "$partial"; then
    step "Resuming partial $label download"
  fi
  attempt=1
  while :; do
    if curl --fail --location --progress-bar \
      --http1.1 --proto '=https' --tlsv1.2 --connect-timeout 30 --max-time 1800 \
      --retry 2 --retry-delay 2 --retry-max-time 7200 --retry-all-errors --continue-at - \
      --output "$partial" "$url"; then
      break
    else
      status=$?
    fi
    if [ "$attempt" -ge 4 ]; then
      fail "could not download $label after $attempt attempts (curl exit $status)"
    fi
    step "Download of $label was interrupted; retrying (attempt $((attempt + 1))/4)"
    attempt=$((attempt + 1))
  done
  mv -- "$partial" "$destination"
  test -s "$destination" && test ! -L "$destination" || fail "downloaded file is missing or unsafe: $url"
}

sha256_file() {
  file=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

cosign_name="cosign-$cosign_os-$cosign_arch"
step "Preparing secure installer for $os/$arch"
cache_root=${XDG_CACHE_HOME:-${HOME:-$temporary/.cache}}
cosign_cache_dir="$cache_root/loomex/cosign/$cosign_version"
cosign_cached="$cosign_cache_dir/$cosign_name"
if test -f "$cosign_cached" && test ! -L "$cosign_cached" && test -x "$cosign_cached" \
  && test "$(sha256_file "$cosign_cached")" = "$cosign_sha256"; then
  cosign_bin="$cosign_cached"
  step "Reusing verified Cosign verifier from cache"
else
  if test -e "$cosign_cached" || test -L "$cosign_cached"; then
    step "Ignoring invalid or stale cached Cosign verifier"
    rm -f -- "$cosign_cached"
  fi
  cosign_download="$temporary/$cosign_name"
  mkdir -p "$cosign_cache_dir"
  cosign_partial="$cosign_cached.partial"
  download "Cosign verifier" "https://github.com/sigstore/cosign/releases/download/v$cosign_version/$cosign_name" "$cosign_download" "$cosign_partial" 1
  if test "$(sha256_file "$cosign_download")" != "$cosign_sha256"; then
    rm -f -- "$cosign_partial"
    fail "downloaded Cosign checksum did not match the pinned official release"
  fi
  chmod 700 "$cosign_download"
  mv -- "$cosign_download" "$cosign_cached"
  cosign_bin="$cosign_cached"
  step "Verified and cached Cosign checksum"
fi

trusted_root="$temporary/trusted_root.json"
download "Sigstore trusted root" "$sigstore_root_url" "$trusted_root"
test "$(sha256_file "$trusted_root")" = "$sigstore_root_sha256" || fail "Sigstore trusted-root checksum did not match the pinned official snapshot"
chmod 400 "$trusted_root"
step "Verified Sigstore trusted root"

installer="loomex-install-marketplace-$version.sh"
provenance="loomex-codex-marketplace-$version.provenance.json"
marketplace_archive="loomex-codex-marketplace-$version.zip"
for name in "$installer" "$installer.sigstore.json" "$provenance" "$provenance.sigstore.json" "$marketplace_archive" "$marketplace_archive.sigstore.json"; do
  download "$name" "$base/$name" "$temporary/$name"
done
chmod 500 "$temporary/$installer"
chmod 400 "$temporary/$installer.sigstore.json" "$temporary/$provenance" "$temporary/$provenance.sigstore.json" "$temporary/$marketplace_archive" "$temporary/$marketplace_archive.sigstore.json"

identity="https://github.com/$repository/.github/workflows/$workflow@refs/tags/v$version"
step "Verifying signed release assets"
"$cosign_bin" verify-blob \
  --bundle "$temporary/$installer.sigstore.json" \
  --trusted-root "$trusted_root" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$temporary/$installer" >/dev/null
"$cosign_bin" verify-blob \
  --bundle "$temporary/$provenance.sigstore.json" \
  --trusted-root "$trusted_root" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$temporary/$provenance" >/dev/null
"$cosign_bin" verify-blob \
  --bundle "$temporary/$marketplace_archive.sigstore.json" \
  --trusted-root "$trusted_root" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$temporary/$marketplace_archive" >/dev/null
step "Verified release signatures and provenance"

# The versioned installer performs the only Codex mutation. It snapshots the
# previous marketplace/plugin state and restores it if any install step fails.
(
  cd "$temporary"
  step "Installing the verified Loomex marketplace into Codex"
  PATH="$(dirname "$cosign_bin"):$PATH" \
    LOOMEX_COSIGN_TRUSTED_ROOT="$trusted_root" \
    "./$installer" "$version" "$temporary/$marketplace_archive"
)

step "Installation complete: Loomex Codex plugin $version is installed and enabled"
step "Restart Codex or open a new task, then ask for any Loomex workflow naturally"
}

# Keep this invocation as the final bytes of the file. When used through
# `curl ... | sh`, the shell must receive and parse the complete function body
# before any download or Codex mutation can begin.
main "$@"
