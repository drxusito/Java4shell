#!/usr/bin/env bash
# SIMULATION SHIM - NOT Docker. Installed as "docker" on PATH by run-sim.sh.
# Emulates only the calls the lab scripts make (image inspect / create / cp / rm / run) using
# real Temurin JDK trees on disk, so the *unmodified* scripts/run-matrix.sh and
# scripts/inspect-image-metadata.sh can be exercised on a machine with no Docker daemon.
#
# What is real   : the JVM binaries, their `release` files, lab/launch.sh, lab/entrypoint-wrapper.sh,
#                  the host CPU, and every analyzer code path including --deep.
# What is emulated: the image config JSON (built from scenarios.tsv, using Temurin's ENV conventions)
#                  and container isolation (`env -i` plus the scenario's env).
# Columns of scenarios.tsv: name | jdk-dir | entrypoint(launch|wrapper) | env (k=v;k=v) | cmd args
set -u
W=${SIM_WORK:?}; LAB=${LAB_DIR:?}
row() { awk -F'\t' -v n="$1" '$1==n' "$W/scenarios.tsv"; }
nm()  { echo "${1#j4s-lab:}"; }

case "${1:-}" in
  image)   # docker image inspect <img>
    n=$(nm "$3"); [ -f "$W/inspect/$n.json" ] || { echo "Error: No such image: $3" >&2; exit 1; }
    cat "$W/inspect/$n.json" ;;
  create)  # docker create <img> /bin/true
    n=$(nm "$2"); [ -n "$(row "$n")" ] && echo "$n" || exit 1 ;;
  cp)      # docker cp <cid>:<path> <dest>
    cid=${2%%:*}; p=${2#*:}; jdk=$(row "$cid" | cut -f2)
    case "$p" in
      /opt/java/openjdk/release)       cp "$W/$jdk/release" "$3" ;;
      /opt/lab/launch.sh)              cp "$LAB/launch.sh" "$3" ;;
      /opt/lab/entrypoint-wrapper.sh)  cp "$LAB/entrypoint-wrapper.sh" "$3" ;;
      *) exit 1 ;;
    esac ;;
  rm)      exit 0 ;;
  run)     # docker run --rm --platform linux/amd64 <img>
    n=$(nm "${*: -1}"); r=$(row "$n"); [ -n "$r" ] || exit 1
    jdk=$(echo "$r" | cut -f2); ep=$(echo "$r" | cut -f3); envs=$(echo "$r" | cut -f4); cmd=$(echo "$r" | cut -f5)
    envarr=(); IFS=';' read -ra kv <<<"$envs"; for e in "${kv[@]}"; do [ -n "$e" ] && envarr+=("$e"); done
    if [ "$ep" = wrapper ]; then   # the real wrapper, with its hard-coded launcher path redirected
      sed "s#exec /opt/lab/launch.sh#exec bash $LAB/launch.sh#" "$LAB/entrypoint-wrapper.sh" > "$W/.wrapper.sh"; script="$W/.wrapper.sh"
    else script="$LAB/launch.sh"; fi
    # shellcheck disable=SC2086
    exec env -i PATH="$W/$jdk/bin:/usr/bin:/bin" "${envarr[@]}" bash "$script" $cmd ;;
  *) echo "docker-shim: unsupported call: $*" >&2; exit 1 ;;
esac
