# syntax=docker/dockerfile:1
#
# CVE-2026-114938 ("Java4Shell") detection lab - LAB USE ONLY, do not deploy.
#
# One Dockerfile, several build targets. Every target has the same launcher
# (/opt/lab/launch.sh), which only *reports* the JVM state - it contains no
# trigger input and never touches the vulnerable code path.
#
#   target               JDK        how the JVM is (or isn't) mitigated
#   -------------------  ---------  ---------------------------------------------
#   vulnerable           affected   nothing
#   patched              fixed      fixed JDK build
#   mitigated-env        affected   ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics
#   mitigated-avx2       affected   ENV JAVA_TOOL_OPTIONS=-XX:UseAVX=2
#   mitigated-cmd        affected   flag passed via CMD (launcher forwards it)
#   hidden-mitigation    affected   flag exported inside an entrypoint script
#                                   (NOT visible in image config metadata)
#   decoy-javaopts       affected   ENV JAVA_OPTS=<flag>, but nothing reads
#                                   JAVA_OPTS (looks mitigated, is not)
#   mitigated-disableintrinsic
#                        affected   _JAVA_OPTIONS=-XX:DisableIntrinsic=_base64_decodeBlock (UseBASE64Intrinsics
#                                   still reads true - flag-value checks miss it)
#
# Base image tags are build args because vendors are still re-publishing images.
# Verify the tags exist first:   docker manifest inspect <tag>
# For anything beyond a throwaway lab, pin by digest (image@sha256:...).
#
# Affected  : Temurin 17.0.6..17.0.21+9, 21.0.13+9, 25.0.5+8, 27.0.1.0.2+1 and earlier
# Fixed     : 17.0.21.1+2, 21.0.13.1+2, 25.0.5.1+2, 27.0.1.1+4
# Note: x86-64 only (the AVX-512 VBMI code path); arm64 is not affected.

ARG VULN_IMAGE=eclipse-temurin:21.0.13_9-jre-noble
ARG FIXED_IMAGE=eclipse-temurin:21.0.13.1_2-jre-noble

# ---------------------------------------------------------------- vulnerable
FROM --platform=linux/amd64 ${VULN_IMAGE} AS base-vulnerable
COPY lab/launch.sh lab/entrypoint-wrapper.sh /opt/lab/
RUN chmod 0755 /opt/lab/launch.sh /opt/lab/entrypoint-wrapper.sh
LABEL lab.cve="CVE-2026-114938" lab.purpose="detection-lab"

FROM base-vulnerable AS vulnerable
ENTRYPOINT ["/opt/lab/launch.sh"]

# ------------------------------------------------------------------- patched
FROM --platform=linux/amd64 ${FIXED_IMAGE} AS patched
COPY lab/launch.sh /opt/lab/launch.sh
RUN chmod 0755 /opt/lab/launch.sh
LABEL lab.cve="CVE-2026-114938" lab.purpose="detection-lab"
ENTRYPOINT ["/opt/lab/launch.sh"]

# -------------------------------------------------- mitigated: visible in ENV
FROM base-vulnerable AS mitigated-env
ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
ENTRYPOINT ["/opt/lab/launch.sh"]

FROM base-vulnerable AS mitigated-avx2
ENV JAVA_TOOL_OPTIONS="-XX:UseAVX=2"
ENTRYPOINT ["/opt/lab/launch.sh"]

# -------------------------------------------------- mitigated: visible in CMD
FROM base-vulnerable AS mitigated-cmd
ENTRYPOINT ["/opt/lab/launch.sh"]
CMD ["-XX:-UseBASE64Intrinsics"]

# ------------------- mitigated: hidden in a script (invisible to config check)
FROM base-vulnerable AS hidden-mitigation
ENTRYPOINT ["/opt/lab/entrypoint-wrapper.sh"]

# ------------------------------ decoy: looks mitigated, but nothing consumes it
# The JVM itself never reads JAVA_OPTS; only some launcher scripts expand it.
FROM base-vulnerable AS decoy-javaopts
ENV JAVA_OPTS="-XX:-UseBASE64Intrinsics"
ENTRYPOINT ["/opt/lab/launch.sh"]

# ----- mitigated via DisableIntrinsic: UseBASE64Intrinsics still reports "true"
# Diagnostic flag, needs UnlockDiagnosticVMOptions. Not a vendor-documented workaround
# (vendors recommend -XX:-UseBASE64Intrinsics); included because real environments use it
# and naive "UseBASE64Intrinsics == false" checks miss it.
FROM base-vulnerable AS mitigated-disableintrinsic
ENV _JAVA_OPTIONS="-XX:+UnlockDiagnosticVMOptions -XX:DisableIntrinsic=_base64_encodeBlock,_base64_decodeBlock"
ENTRYPOINT ["/opt/lab/launch.sh"]
