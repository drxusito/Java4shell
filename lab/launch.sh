#!/usr/bin/env bash
# Runtime state reporter for CVE-2026-114938 (Java4Shell). READ-ONLY: it asks the
# JVM what it is, what CPU it sees and which flags are effective. It never feeds
# the JVM any Base64 input.
#
# Arguments are forwarded to every `java` call as JVM flags, which models an
# image that passes tuning flags via CMD. JAVA_OPTS is deliberately NOT read.
set -u
JVM_ARGS=("$@")

# a < b in version order (sort -V)
ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }

# VULNERABLE | FIXED | NOT_AFFECTED | UNKNOWN   (java.version string as input)
version_state() {
  local v=$1 major=${1%%.*}
  case $major in
    1|8|9|10|11|12|13|14|15|16) echo NOT_AFFECTED ;;
    17) if   ver_lt "$v" 17.0.6;   then echo NOT_AFFECTED
        elif ver_lt "$v" 17.0.21.1; then echo VULNERABLE
        else echo FIXED; fi ;;
    21) if ver_lt "$v" 21.0.13.1; then echo VULNERABLE; else echo FIXED; fi ;;
    25) if ver_lt "$v" 25.0.5.1;  then echo VULNERABLE; else echo FIXED; fi ;;
    26) echo VULNERABLE ;;   # EOL, no fix released - move to 27.x
    27) if ver_lt "$v" 27.0.1.1;  then echo VULNERABLE; else echo FIXED; fi ;;
    *)  echo UNKNOWN ;;
  esac
}

flag_value() {  # effective value of a -XX flag as the JVM sees it
  java "${JVM_ARGS[@]}" -XX:+PrintFlagsFinal -version 2>/dev/null \
    | awk -v f="$1" '$2==f {print $4; exit}'
}

arch=$(uname -m)
cpu_vbmi=no; cpu_bw=no
grep -qwE "avx512_?vbmi" /proc/cpuinfo 2>/dev/null && cpu_vbmi=yes
grep -qw avx512bw   /proc/cpuinfo 2>/dev/null && cpu_bw=yes

props=$(java "${JVM_ARGS[@]}" -XshowSettings:properties -version 2>&1)
jver=$(printf '%s\n' "$props" | awk -F' = ' '/^ *java.version = /{print $2; exit}')
jvendor=$(printf '%s\n' "$props" | awk -F' = ' '/^ *java.vendor = /{print $2; exit}')
vstate=$(version_state "${jver:-0}")
b64=$(flag_value UseBASE64Intrinsics)
avx=$(flag_value UseAVX)
# DisableIntrinsic is a diagnostic list flag; it can switch the Base64 decode intrinsic off while
# UseBASE64Intrinsics still reads "true". Observed on real JVMs (and used by some environments).
dis=$(flag_value DisableIntrinsic)
dis_b64=no; case ",$dis," in *,_base64_decodeBlock,*) dis_b64=yes ;; esac

# ---- verdict (predicted exposure; see README for how to confirm definitively)
if   [ "$vstate" = NOT_AFFECTED ]; then verdict="NOT_AFFECTED (JDK line/version)"
elif [ "$arch" != x86_64 ];        then verdict="NOT_AFFECTED (architecture: $arch)"
elif [ "$vstate" = FIXED ];        then verdict="PATCHED (fixed JDK build)"
elif [ "$vstate" = UNKNOWN ];      then verdict="INDETERMINATE (unrecognised JDK version: ${jver:-none})"
elif [ "$b64" = false ];           then verdict="MITIGATED (UseBASE64Intrinsics=false)"
elif [ "$dis_b64" = yes ];         then verdict="MITIGATED_UNVERIFIED (DisableIntrinsic lists _base64_decodeBlock; not a vendor-documented workaround)"
elif [ "$cpu_vbmi" = no ] || [ "$cpu_bw" = no ]; then
                                        verdict="VULN_JDK_BUT_NOT_EXPOSED_ON_THIS_HOST (CPU lacks AVX-512 VBMI/BW)"
elif [ -n "$avx" ] && [ "$avx" -lt 3 ] 2>/dev/null; then
                                        verdict="MITIGATED (UseAVX=$avx)"
else                                    verdict="EXPOSED (vulnerable JDK + x86-64 + AVX-512 VBMI/BW + intrinsic active)"
fi

cat <<EOF
== Java4Shell runtime report ==
java.version            : ${jver:-?}
java.vendor             : ${jvendor:-?}
version state           : $vstate
arch                    : $arch
cpu avx512vbmi / bw     : $cpu_vbmi / $cpu_bw
UseBASE64Intrinsics     : ${b64:-n/a}
UseAVX                  : ${avx:-n/a}
DisableIntrinsic        : ${dis:-n/a}
JAVA_TOOL_OPTIONS      : ${JAVA_TOOL_OPTIONS:-<unset>}
JDK_JAVA_OPTIONS        : ${JDK_JAVA_OPTIONS:-<unset>}
_JAVA_OPTIONS           : ${_JAVA_OPTIONS:-<unset>}
JAVA_OPTS (JVM ignores) : ${JAVA_OPTS:-<unset>}
forwarded JVM args      : ${JVM_ARGS[*]:-<none>}
J4S_RUNTIME_VERDICT=$verdict
EOF
