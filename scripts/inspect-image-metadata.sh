#!/usr/bin/env bash
# Static (no-execution) check of a container image for CVE-2026-114938 exposure.
#
#   inspect-image-metadata.sh <image>                 # config metadata only
#   inspect-image-metadata.sh --deep <image>          # + read $JAVA_HOME/release and
#                                                     #   the entrypoint script (docker create/cp, nothing runs)
#   inspect-image-metadata.sh --json inspect.json     # offline: output of `docker image inspect`
#
# Emits human-readable findings and one machine-readable line:
#   J4S_META_VERDICT=<verdict>
#
# What metadata CAN decide : CPU architecture, JDK version (if JAVA_VERSION is set and honest),
#                            JVM flags set via ENV / ENTRYPOINT / CMD.
# What it CANNOT decide    : host CPU features (AVX-512 VBMI/BW), flags added at `docker run` /
#                            Kubernetes time, flags set inside launcher scripts (unless --deep),
#                            or whether a launcher actually forwards CMD / JAVA_OPTS to the JVM.
set -euo pipefail

deep=0; json_file=""; image=""
while [ $# -gt 0 ]; do
  case $1 in
    --deep) deep=1 ;;
    --json) json_file=${2:?--json needs a file}; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) image=$1 ;;
  esac; shift
done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

if [ -n "$json_file" ]; then meta=$(jq '.[0]' "$json_file")
elif [ -n "$image" ];   then meta=$(docker image inspect "$image" | jq '.[0]')
else echo "usage: $0 [--deep] <image> | --json file" >&2; exit 2; fi

ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }
version_state() {
  local v=$1 major=${1%%.*}
  case $major in
    1|8|9|10|11|12|13|14|15|16) echo NOT_AFFECTED ;;
    17) if   ver_lt "$v" 17.0.6;    then echo NOT_AFFECTED
        elif ver_lt "$v" 17.0.21.1; then echo VULNERABLE; else echo FIXED; fi ;;
    21) if ver_lt "$v" 21.0.13.1;   then echo VULNERABLE; else echo FIXED; fi ;;
    25) if ver_lt "$v" 25.0.5.1;    then echo VULNERABLE; else echo FIXED; fi ;;
    26) echo VULNERABLE ;;
    27) if ver_lt "$v" 27.0.1.1;    then echo VULNERABLE; else echo FIXED; fi ;;
    *)  echo UNKNOWN ;;
  esac
}

# ---------------------------------------------------------------- extraction
arch=$(jq -r '.Architecture // "unknown"' <<<"$meta")
os=$(jq -r '.Os // "unknown"' <<<"$meta")
env_lines=$(jq -r '.Config.Env[]?' <<<"$meta")
entrypoint=$(jq -r '(.Config.Entrypoint // []) | join(" ")' <<<"$meta")
cmd=$(jq -r '(.Config.Cmd // []) | join(" ")' <<<"$meta")
ep_first=$(jq -r '(.Config.Entrypoint // [])[0] // ""' <<<"$meta")
env_get() { printf '%s\n' "$env_lines" | sed -n "s/^$1=//p" | head -n1; }

java_version_raw=$(env_get JAVA_VERSION)
java_home=$(env_get JAVA_HOME)
jto=$(env_get JAVA_TOOL_OPTIONS); jdko=$(env_get JDK_JAVA_OPTIONS); uj=$(env_get _JAVA_OPTIONS)
jopts=$(env_get JAVA_OPTS)

# Temurin: jdk-21.0.13+9 | jdk-17.0.21+9 | jdk8u492-b09 ; others: 21.0.13
ver=$(printf '%s' "$java_version_raw" | sed -nE 's/^(jdk-?)?([0-9]+(\.[0-9]+)*).*/\2/p')
vstate=UNKNOWN; [ -n "$ver" ] && vstate=$(version_state "$ver")

# ------------------------------------------------------- optional deep reads
release_ver=""; ep_script_hits=""
if [ "$deep" = 1 ] && [ -z "$json_file" ]; then
  cid=$(docker create "$image" /bin/true 2>/dev/null || true)
  if [ -n "$cid" ]; then
    trap 'docker rm -f "$cid" >/dev/null 2>&1' EXIT
    tmp=$(mktemp -d)
    if [ -n "$java_home" ] && docker cp "$cid:$java_home/release" "$tmp/release" 2>/dev/null; then
      release_ver=$(sed -nE 's/^JAVA_VERSION="?([^"]+)"?$/\1/p' "$tmp/release" | head -n1)
    fi
    if [ "${ep_first#/}" != "$ep_first" ] && docker cp "$cid:$ep_first" "$tmp/ep" 2>/dev/null; then
      ep_script_hits=$(grep -nE -- '-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2]([^0-9]|$)|-XX:DisableIntrinsic=[^ ]*_base64_decodeBlock' "$tmp/ep" || true)
    fi
    rm -rf "$tmp"
  fi
  if [ -n "$release_ver" ]; then
    vstate_release=$(version_state "$release_ver")
    [ "$vstate_release" != "$vstate" ] && echo "!! ENV JAVA_VERSION ($java_version_raw) and release file ($release_ver) disagree - trusting release file" \
      && vstate=$vstate_release && ver=$release_ver
  fi
fi

# ------------------------------------------------------ mitigation detection
pat='-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2]([^0-9]|$)|-XX:DisableIntrinsic=[^ ]*_base64_decodeBlock'
mit_env=""; for kv in "JAVA_TOOL_OPTIONS=$jto" "JDK_JAVA_OPTIONS=$jdko" "_JAVA_OPTIONS=$uj"; do
  printf '%s' "$kv" | grep -qE -- "$pat" && mit_env="$mit_env ${kv%%=*}"; done
mit_args=""; printf '%s %s' "$entrypoint" "$cmd" | grep -qE -- "$pat" && mit_args=yes
mit_decoy=""; printf '%s' "$jopts" | grep -qE -- "$pat" && mit_decoy=yes
entry_is_java=no; case ${ep_first##*/} in java|"") entry_is_java=yes ;; esac
[ -z "$ep_first" ] && entry_is_java=unknown

# ------------------------------------------------------------------- verdict
notes=()
if   [ "$arch" != amd64 ];            then v="NOT_AFFECTED (image architecture: $arch)"
elif [ "$vstate" = NOT_AFFECTED ];    then v="NOT_AFFECTED (JDK line/version $ver)"
elif [ "$vstate" = FIXED ];           then v="PATCHED_VERSION ($ver)"
elif [ "$vstate" = UNKNOWN ];         then v="INDETERMINATE (no usable JAVA_VERSION; try --deep or a scanner/SBOM)"
elif [ -n "$mit_env" ];               then v="VULN_JDK_MITIGATION_IN_ENV (${mit_env# })"
elif [ -n "$mit_args" ];              then v="VULN_JDK_MITIGATION_IN_ARGS (only effective if launcher forwards it)"
elif [ -n "$ep_script_hits" ];        then v="VULN_JDK_MITIGATION_IN_ENTRYPOINT_SCRIPT (found by --deep)"
else
  v="VULN_JDK_NO_VISIBLE_MITIGATION"
  if [ "$entry_is_java" = no ]; then
    if [ "$deep" = 1 ]; then v="VULN_JDK_NO_VISIBLE_MITIGATION (entrypoint script scanned, no flag found)"
    else v="VULN_JDK_NO_VISIBLE_MITIGATION (entrypoint is a script: flags may be hidden; use --deep)"; fi
  fi
fi
[ -n "$mit_decoy" ] && notes+=("JAVA_OPTS carries a mitigation flag, but the JVM does not read JAVA_OPTS - treat as NOT mitigated unless the launcher expands it")
[ "$arch" = amd64 ] && [ "$vstate" = VULNERABLE ] && \
  notes+=("Exposure also needs a host CPU with AVX-512 VBMI+BW - not knowable from metadata (run the runtime check on the target host)")
[ "$vstate" = VULNERABLE ] && [ "$deep" = 0 ] && [ "$entry_is_java" = no ] && \
  notes+=("Launcher script contents were not inspected (re-run with --deep)")
notes+=("Flags added at 'docker run' / Kubernetes env/args are invisible to image metadata")

# -------------------------------------------------------------------- output
echo "== Image metadata findings =="
printf '%-26s %s\n' "image"              "${image:-$json_file}"
printf '%-26s %s/%s\n' "os/arch"          "$os" "$arch"
printf '%-26s %s  (parsed: %s -> %s)\n' "ENV JAVA_VERSION" "${java_version_raw:-<unset>}" "${ver:-?}" "$vstate"
[ "$deep" = 1 ] && printf '%-26s %s\n' "release file version" "${release_ver:-<not read>}"
printf '%-26s %s\n' "ENV JAVA_HOME"       "${java_home:-<unset>}"
printf '%-26s %s\n' "ENV JAVA_TOOL_OPTIONS" "${jto:-<unset>}"
printf '%-26s %s\n' "ENV JDK_JAVA_OPTIONS"  "${jdko:-<unset>}"
printf '%-26s %s\n' "ENV _JAVA_OPTIONS"     "${uj:-<unset>}"
printf '%-26s %s\n' "ENV JAVA_OPTS"         "${jopts:-<unset>}"
printf '%-26s %s\n' "Entrypoint"            "${entrypoint:-<none>}"
printf '%-26s %s\n' "Cmd"                   "${cmd:-<none>}"
[ -n "$ep_script_hits" ] && { echo "entrypoint script matches:"; printf '  %s\n' "$ep_script_hits"; }
echo "-- limits --"; for n in "${notes[@]}"; do echo "  * $n"; done
echo "J4S_META_VERDICT=$v"
