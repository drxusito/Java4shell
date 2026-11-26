#!/usr/bin/env bash
# Download one affected and one fixed Eclipse Temurin 21 JRE (x64 Linux) from the official
# Adoptium GitHub releases and verify their SHA-256 checksums.
#   JDK_CACHE=<dir> bash sim/fetch-jdks.sh        (default: sim/.cache)
# Result: $JDK_CACHE/jdk-vuln (21.0.13+9, affected)  and  $JDK_CACHE/jdk-fixed (21.0.13.1+2, fixed)
set -euo pipefail
cd "$(dirname "$0")"
CACHE=${JDK_CACHE:-$PWD/.cache}
B=https://github.com/adoptium/temurin21-binaries/releases/download
mkdir -p "$CACHE/dl"

fetch() {  # <release-tag> <file> <target-dir>
  local tag=$1 file=$2 dir=$3
  if [ -x "$dir/bin/java" ]; then echo "[skip] $dir already present"; return; fi
  rm -rf "$dir"; mkdir -p "$dir"
  curl -fsSL -o "$CACHE/dl/$file"        "$B/$tag/$file"
  curl -fsSL -o "$CACHE/dl/$file.sha256" "$B/$tag/$file.sha256.txt"
  (cd "$CACHE/dl" && sha256sum -c "$file.sha256")
  tar -xzf "$CACHE/dl/$file" -C "$dir" --strip-components=1
  echo "[ok]   $dir  ($(sed -n 's/^JAVA_VERSION=//p' "$dir/release"))"
}
fetch "jdk-21.0.13%2B9"   OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz   "$CACHE/jdk-vuln"
fetch "jdk-21.0.13.1%2B2" OpenJDK21U-jre_x64_linux_hotspot_21.0.13.1_2.tar.gz "$CACHE/jdk-fixed"
