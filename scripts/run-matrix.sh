#!/usr/bin/env bash
# Compare what a metadata-only check predicts with what the container reports at runtime.
# Run on the host whose CPU you want to assess (the runtime verdict depends on it).
#   scripts/run-matrix.sh            # config metadata only
#   scripts/run-matrix.sh --deep     # + release file / entrypoint script content
set -euo pipefail
cd "$(dirname "$0")/.."
deep=""; [ "${1:-}" = "--deep" ] && deep="--deep"

echo "Host CPU AVX-512 VBMI/BW: $(grep -ow 'avx512vbmi\|avx512bw' /proc/cpuinfo 2>/dev/null | sort -u | tr '\n' ' ' || true)"
echo "Host arch: $(uname -m)   (arm64 hosts / emulated amd64 will not show AVX-512)"
echo
printf '%-20s | %-62s | %s\n' TARGET "METADATA VERDICT" "RUNTIME VERDICT"
printf '%s\n' "-----------------------------------------------------------------------------------------------------------------------------"
for t in vulnerable patched mitigated-env mitigated-avx2 mitigated-cmd hidden-mitigation decoy-javaopts mitigated-disableintrinsic; do
  img="j4s-lab:$t"
  meta=$(bash scripts/inspect-image-metadata.sh $deep "$img" | sed -n 's/^J4S_META_VERDICT=//p')
  run=$(docker run --rm --platform linux/amd64 "$img" 2>/dev/null | sed -n 's/^J4S_RUNTIME_VERDICT=//p')
  printf '%-20s | %-62.62s | %s\n' "$t" "$meta" "$run"
done
