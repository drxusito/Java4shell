#!/usr/bin/env bash
# Shows how a mitigation flag set in one place can be undone by another, on the REAL affected JVM.
# Prints the effective UseBASE64Intrinsics / UseAVX as the JVM resolves them, plus where the value came from.
#   bash sim/fetch-jdks.sh && bash sim/precedence-demo.sh        (JDK_CACHE=<dir> to relocate)
set -uo pipefail   # no -e: several lines are *expected* to fail or print nothing
here=$(cd "$(dirname "$0")" && pwd)
J=${JDK_CACHE:-$here/.cache}/jdk-vuln/bin/java
[ -x "$J" ] || { echo "run: bash sim/fetch-jdks.sh" >&2; exit 2; }

show() {  # <label> <ENV=VAL>... -- <java args>
  local label=$1; shift; local envs=()
  while [ "$1" != "--" ]; do envs+=("$1"); shift; done; shift
  printf '%-58s ' "$label"
  env -i PATH=/usr/bin:/bin ${envs[@]+"${envs[@]}"} "$J" "$@" -XX:+PrintFlagsFinal -version 2>/dev/null \
    | awk '$2=="UseBASE64Intrinsics"||$2=="UseAVX" {o=$0; sub(/.*\{/,"{",o); sub(/\}.*/,"}",o); printf "%s=%s %s  ", $2, $4, o}'
  echo
}
B=-XX:-UseBASE64Intrinsics; P=-XX:+UseBASE64Intrinsics
echo "== Where can the same flag be set, and who wins? (env -i: nothing inherited)"
show "baseline"                                          --
show "JAVA_TOOL_OPTIONS=-B64"                            "JAVA_TOOL_OPTIONS=$B" --
show "JAVA_TOOL_OPTIONS=-B64  + command line +B64"       "JAVA_TOOL_OPTIONS=$B" -- "$P"
show "JDK_JAVA_OPTIONS=-B64   + command line +B64"       "JDK_JAVA_OPTIONS=$B" -- "$P"
show "_JAVA_OPTIONS=-B64      + command line +B64"       "_JAVA_OPTIONS=$B" -- "$P"
show "JAVA_TOOL_OPTIONS=-B64  + JDK_JAVA_OPTIONS=+B64"   "JAVA_TOOL_OPTIONS=$B" "JDK_JAVA_OPTIONS=$P" --
show "JAVA_TOOL_OPTIONS=-B64  + _JAVA_OPTIONS=+B64"      "JAVA_TOOL_OPTIONS=$B" "_JAVA_OPTIONS=$P" --
show "JAVA_TOOL_OPTIONS='-B64 +B64' (same var, last wins)" "JAVA_TOOL_OPTIONS=$B $P" --
show "JAVA_OPTS=-B64 (not read by the JVM)"              "JAVA_OPTS=$B" --
echo
echo "== UseAVX"
for v in 0 1 2 3; do show "command line -XX:UseAVX=$v" -- "-XX:UseAVX=$v"; done
show "JAVA_TOOL_OPTIONS=UseAVX=2 + command line UseAVX=3" "JAVA_TOOL_OPTIONS=-XX:UseAVX=2" -- -XX:UseAVX=3
printf '%-58s ' "command line -XX:UseAVX=9 (out of range)"
env -i PATH=/usr/bin:/bin "$J" -XX:UseAVX=9 -version 2>&1 | head -1 || true   # the JVM refusing to start is the expected result
echo
echo "== What the JVM itself says about the CPU (clean env)"
printf '%-58s ' "default"
env -i PATH=/usr/bin:/bin "$J" -Xlog:os+cpu=info -version 2>&1 | grep 'CPU:' | grep -o -E 'avx512(_?vbmi|bw)\b' | sort -u | tr '\n' ' '; echo
printf '%-58s ' "-XX:UseAVX=2 (AVX-512 hidden from the JVM)"
env -i PATH=/usr/bin:/bin "$J" -XX:UseAVX=2 -Xlog:os+cpu=info -version 2>&1 | grep 'CPU:' | grep -o -E 'avx512(_?vbmi|bw)\b' | sort -u | tr '\n' ' '; echo
printf '%-58s ' "/proc/cpuinfo"
grep -ow -E 'avx512_?vbmi|avx512bw' /proc/cpuinfo 2>/dev/null | sort -u | tr '\n' ' '; echo
