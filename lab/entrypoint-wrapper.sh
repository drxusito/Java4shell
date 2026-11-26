#!/bin/sh
# Used only by the "hidden-mitigation" target. The mitigation lives here, in a
# layer file, so `docker inspect` shows a vulnerable JDK and NO JVM options.
# Only a content scan (--deep) or a runtime check reveals it.
JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }-XX:-UseBASE64Intrinsics"
export JAVA_TOOL_OPTIONS
exec /opt/lab/launch.sh "$@"
