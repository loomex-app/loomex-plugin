#!/usr/bin/env bash
set -euo pipefail

cosign_version="3.1.2"
cosign_sha256="f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf"
install_dir="${RUNNER_TEMP:?RUNNER_TEMP is required}/loomex-cosign/v${cosign_version}"
cosign_bin="$install_dir/cosign"
download="$cosign_bin.download"

mkdir -p "$install_dir"
trap 'rm -f "$download"' EXIT

curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --output "$download" \
  "https://github.com/sigstore/cosign/releases/download/v${cosign_version}/cosign-linux-amd64"
printf '%s  %s\n' "$cosign_sha256" "$download" | sha256sum -c -
chmod 700 "$download"
mv "$download" "$cosign_bin"
"$cosign_bin" version

printf '%s\n' "$install_dir" >> "${GITHUB_PATH:?GITHUB_PATH is required}"
