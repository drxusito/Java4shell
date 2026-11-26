#!/usr/bin/env bash
# End-to-end demo WITHOUT Docker: real affected/fixed JVMs + the real lab scripts.
#   bash sim/fetch-jdks.sh        # once (needs internet to github.com)
#   bash sim/run-sim.sh           # prints the metadata-vs-runtime matrix, without and with --deep
# Env: JDK_CACHE=<dir> where fetch-jdks.sh put the JDKs (default sim/.cache)
# Run it on the machine whose CPU you want to demonstrate; the runtime verdict depends on AVX-512 VBMI/BW.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); lab=$(dirname "$here")
cache=${JDK_CACHE:-$here/.cache}
for d in jdk-vuln jdk-fixed; do
  [ -x "$cache/$d/bin/java" ] || { echo "missing $cache/$d - run: bash sim/fetch-jdks.sh" >&2; exit 2; }
done
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/inspect"
ln -s "$cache/jdk-vuln" "$work/jdk-vuln"; ln -s "$cache/jdk-fixed" "$work/jdk-fixed"
cp "$here/scenarios.tsv" "$work/scenarios.tsv"
cp "$here/docker-shim.sh" "$work/bin/docker"; chmod +x "$work/bin/docker"

# Emulated `docker image inspect` documents. JAVA_VERSION uses Temurin's image convention (jdk-<ver>+<build>).
python3 - "$work" <<'EOF'
import csv, json, re, sys
w = sys.argv[1]
for row in csv.reader(open(f"{w}/scenarios.tsv"), delimiter="\t"):
    if not row:
        continue
    name, jdk, ep, envs, cmd = (row + [""] * 5)[:5]   # trailing empty cmd column may be missing
    rel = open(f"{w}/{jdk}/release").read()
    ver = re.search(r'^JAVA_RUNTIME_VERSION="([^"]+)"', rel, re.M).group(1).replace("-LTS", "")
    env = ["PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/bin", "JAVA_HOME=/opt/java/openjdk", f"JAVA_VERSION=jdk-{ver}"]
    env += [e for e in envs.split(";") if e and e != "X=1"]
    entry = ["/opt/lab/entrypoint-wrapper.sh"] if ep == "wrapper" else ["/opt/lab/launch.sh"]
    json.dump([{"Architecture": "amd64", "Os": "linux",
                "Config": {"Env": env, "Entrypoint": entry, "Cmd": cmd.split() or None}}],
              open(f"{w}/inspect/{name}.json", "w"), indent=1)
EOF

export PATH="$work/bin:$PATH" SIM_WORK="$work" LAB_DIR="$lab/lab"
cd "$lab"
echo "################ metadata only ################"
bash scripts/run-matrix.sh
echo; echo "################ --deep (release file + entrypoint script) ################"
bash scripts/run-matrix.sh --deep
