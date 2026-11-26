#!/usr/bin/env bash
# Build every lab target as j4s-lab:<target>. Override base images if the default
# tags don't exist yet (vendors are still publishing fixed images):
#   VULN_IMAGE=eclipse-temurin:17.0.21_9-jre-noble FIXED_IMAGE=eclipse-temurin:17.0.21.1_2-jre-noble ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

TARGETS=(vulnerable patched mitigated-env mitigated-avx2 mitigated-cmd hidden-mitigation decoy-javaopts mitigated-disableintrinsic)
args=()
[ -n "${VULN_IMAGE:-}" ]  && args+=(--build-arg "VULN_IMAGE=$VULN_IMAGE")
[ -n "${FIXED_IMAGE:-}" ] && args+=(--build-arg "FIXED_IMAGE=$FIXED_IMAGE")

for t in "${TARGETS[@]}"; do
  echo ">>> building j4s-lab:$t"
  docker build --platform linux/amd64 --target "$t" ${args[@]+"${args[@]}"} -t "j4s-lab:$t" .
done
