# syntax=docker/dockerfile:1
#
# CVE-2026-114938 ("Java4Shell") detection lab - LAB USE ONLY, do not deploy.
#
# Every target runs the same read-only launcher (/opt/lab/launch.sh), which only REPORTS
# the JVM state. Nothing here sends the JVM any Base64 input or exploit data.
#
# =====================================================================================
#  THREE OUTCOMES - the target name always starts with the real outcome
# =====================================================================================
#
#  FIXED       The JDK is a corrected build. The bug is gone. Nothing to keep configured.
#              This is the only permanent remediation.
#
#  MITIGATED   The JDK is still a vulnerable build, BUT a JVM flag stops the faulty code
#              from running. The container is NOT exploitable while the flag is in effect.
#              It is temporary: the flag can be overridden, lost on redeploy, and scanners
#              still report the vulnerable version. Upgrade the JDK when you can.
#
#  VULNERABLE  Vulnerable JDK and nothing stops the faulty code from running.
#              (Exposed on an x86-64 host whose CPU has AVX-512 VBMI + BW.)
#
#   target                       outcome      JDK          what protects it
#   ---------------------------  -----------  -----------  ------------------------------------------
#   fixed                        FIXED        21.0.13.1+2  corrected JDK build
#   mitigated-env                MITIGATED    21.0.13+9    ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics
#   mitigated-avx2               MITIGATED    21.0.13+9    ENV JAVA_TOOL_OPTIONS=-XX:UseAVX=2
#   mitigated-cmd                MITIGATED    21.0.13+9    flag passed in CMD (the launcher forwards it)
#   mitigated-hidden             MITIGATED    21.0.13+9    flag set inside an entrypoint script
#                                                          (invisible to `docker inspect`)
#   mitigated-disableintrinsic   MITIGATED *  21.0.13+9    _JAVA_OPTIONS=-XX:DisableIntrinsic=_base64_decodeBlock
#   vulnerable                   VULNERABLE   21.0.13+9    nothing
#   vulnerable-fake-mitigation   VULNERABLE   21.0.13+9    nothing - JAVA_OPTS carries the flag, but the
#                                                          JVM never reads JAVA_OPTS (looks protected, isn't)
#
#   * not a vendor-documented workaround; its effect on this overflow is unverified.
#
# Each image also carries LABELs (lab.outcome, lab.jdk, lab.protection) so you can see
# the intended answer with `docker inspect`. The metadata analyzer deliberately IGNORES
# these labels: it must reach its verdict from the evidence, as it would on a real image.
#
# -------------------------------------------------------------------------------------
# Base image tags are build args because vendors are still re-publishing images.
# Verify the tags exist first:   docker manifest inspect <tag>
# For anything beyond a throwaway lab, pin by digest (image@sha256:...).
#
# Affected : Temurin 17.0.6..17.0.21+9, 21.0.13+9, 25.0.5+8, 27.0.1.0.2+1 and earlier
# Fixed    : 17.0.21.1+2, 21.0.13.1+2, 25.0.5.1+2, 27.0.1.1+4
# x86-64 only (the AVX-512 VBMI code path); arm64 JVMs are not affected.

ARG VULN_IMAGE=eclipse-temurin:21.0.13_9-jre-noble
ARG FIXED_IMAGE=eclipse-temurin:21.0.13.1_2-jre-noble

# =====================================================================================
#  Shared bases (not meant to be built on their own)
# =====================================================================================
FROM --platform=linux/amd64 ${VULN_IMAGE} AS base-vulnerable-jdk
COPY lab/launch.sh lab/entrypoint-wrapper.sh /opt/lab/
RUN chmod 0755 /opt/lab/launch.sh /opt/lab/entrypoint-wrapper.sh
LABEL lab.cve="CVE-2026-114938" lab.purpose="detection-lab" lab.jdk="vulnerable (21.0.13+9)"
ENTRYPOINT ["/opt/lab/launch.sh"]

FROM --platform=linux/amd64 ${FIXED_IMAGE} AS base-fixed-jdk
COPY lab/launch.sh /opt/lab/
RUN chmod 0755 /opt/lab/launch.sh
LABEL lab.cve="CVE-2026-114938" lab.purpose="detection-lab" lab.jdk="fixed (21.0.13.1+2)"
ENTRYPOINT ["/opt/lab/launch.sh"]

# =====================================================================================
#  FIXED - the JDK upgrade is the remediation
# =====================================================================================
FROM base-fixed-jdk AS fixed
LABEL lab.outcome="FIXED" lab.protection="corrected JDK build"

# =====================================================================================
#  MITIGATED - vulnerable JDK, protected by a JVM flag (temporary, until upgraded)
# =====================================================================================

# The recommended flag: decode Base64 in plain Java instead of the faulty AVX-512 routine.
# Read by every JVM because it is in JAVA_TOOL_OPTIONS; visible in image metadata.
FROM base-vulnerable-jdk AS mitigated-env
ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
LABEL lab.outcome="MITIGATED" lab.protection="JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics"

# Alternative: stop the JVM using AVX-512 at all. x86-64 ONLY - an arm64 JVM refuses to
# start with this flag. Note UseBASE64Intrinsics still reads "true" here.
FROM base-vulnerable-jdk AS mitigated-avx2
ENV JAVA_TOOL_OPTIONS="-XX:UseAVX=2"
LABEL lab.outcome="MITIGATED" lab.protection="JAVA_TOOL_OPTIONS=-XX:UseAVX=2 (x86-64 only)"

# Same flag, passed as a command-line argument. Only protects because this launcher
# forwards its arguments to java; many real launchers would not.
FROM base-vulnerable-jdk AS mitigated-cmd
CMD ["-XX:-UseBASE64Intrinsics"]
LABEL lab.outcome="MITIGATED" lab.protection="CMD -XX:-UseBASE64Intrinsics (forwarded by launcher)"

# Same flag, set inside an entrypoint script. Fully protected at runtime, but invisible in
# `docker inspect` - only a file scan (analyzer --deep) or a runtime check finds it.
FROM base-vulnerable-jdk AS mitigated-hidden
ENTRYPOINT ["/opt/lab/entrypoint-wrapper.sh"]
LABEL lab.outcome="MITIGATED" lab.protection="entrypoint script exports JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics"

# Diagnostic flag that skips the decode intrinsic while UseBASE64Intrinsics still reads
# "true", so naive flag checks miss it. Seen in real environments; NOT a vendor-documented
# workaround and its effect on this overflow is unverified.
FROM base-vulnerable-jdk AS mitigated-disableintrinsic
ENV _JAVA_OPTIONS="-XX:+UnlockDiagnosticVMOptions -XX:DisableIntrinsic=_base64_encodeBlock,_base64_decodeBlock"
LABEL lab.outcome="MITIGATED (unverified)" lab.protection="_JAVA_OPTIONS DisableIntrinsic=_base64_decodeBlock"

# =====================================================================================
#  VULNERABLE - nothing stops the faulty code
# =====================================================================================
FROM base-vulnerable-jdk AS vulnerable
LABEL lab.outcome="VULNERABLE" lab.protection="none"

# Looks protected, is not: JAVA_OPTS is only read by some launcher scripts, never by the
# JVM itself, and this launcher does not expand it.
FROM base-vulnerable-jdk AS vulnerable-fake-mitigation
ENV JAVA_OPTS="-XX:-UseBASE64Intrinsics"
LABEL lab.outcome="VULNERABLE" lab.protection="none (JAVA_OPTS is ignored by the JVM)"
