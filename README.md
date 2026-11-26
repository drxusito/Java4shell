<<<<<<< HEAD
# Java4Shell (CVE-2026-114938) detection lab

Lab-only images for studying how well *static image metadata* predicts exposure to the
OpenJDK x86-64 AVX-512 Base64 decoder heap overflow. Nothing here contains trigger input;
the in-image launcher only reports JVM state.

Full write-up (metadata verification, exploitability, mitigation parameters): [docs/Java4Shell_CVE-2026-114938_Technical_Guide.pdf](docs/Java4Shell_CVE-2026-114938_Technical_Guide.pdf)

## Quick start

```bash
bash build.sh                       # builds j4s-lab:<target> for 8 targets
bash scripts/run-matrix.sh          # metadata verdict vs runtime verdict
bash scripts/run-matrix.sh --deep   # adds release-file + entrypoint-script reads
bash scripts/inspect-image-metadata.sh j4s-lab:hidden-mitigation
bash scripts/inspect-image-metadata.sh --json testdata/vulnerable.json   # offline
```

If a default base tag doesn't exist, check with `docker manifest inspect <tag>` and override
`VULN_IMAGE` / `FIXED_IMAGE` (see `build.sh`). Pin by digest for anything lasting.
Tag spellings (e.g. `21.0.13.1_2`) were taken from vendor version numbers and are **unverified**.

## Simulate without Docker (sim/)

No Docker daemon needed. `sim/` runs the unmodified lab scripts against **real** Temurin JDKs
(affected 21.0.13+9, fixed 21.0.13.1+2) using a small `docker` shim:

```bash
bash sim/fetch-jdks.sh     # once: downloads both JREs from GitHub, verifies SHA-256 (needs jq, curl)
bash sim/run-sim.sh        # metadata-vs-runtime matrix, without and with --deep
bash sim/precedence-demo.sh  # which flag source wins; UseAVX values; JVM-reported CPU features
```

Real: JVMs, `release` files, launcher, host CPU, every analyzer path. Emulated: the image-config JSON
and container isolation. It does **not** prove the Dockerfile builds or that Docker tags exist - run
`bash build.sh` on a Docker host for that. It also does not reproduce the memory corruption.

## Findings from running real JVMs

- Fixed and vulnerable JDKs report identical `UseBASE64Intrinsics`/`UseAVX`: flags cannot show a build is
  patched, only the version string can.
- `-XX:+UnlockDiagnosticVMOptions -XX:DisableIntrinsic=_base64_decodeBlock` leaves `UseBASE64Intrinsics = true`.
  A check that only reads that flag reports EXPOSED. Both scripts now detect it and report
  `MITIGATED_UNVERIFIED` (not a vendor-documented workaround; effectiveness not tested here).
- `JDK_JAVA_OPTIONS`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` all take effect; `JAVA_OPTS` does not.
- Watch for inherited environment: a shell or CI runner with `_JAVA_OPTIONS`/`JAVA_TOOL_OPTIONS` set silently
  changes results. The simulation runs each scenario under `env -i` for that reason.
- **Flag precedence** (lowest to highest): `JAVA_TOOL_OPTIONS` < command line (incl. `JDK_JAVA_OPTIONS`) < `_JAVA_OPTIONS`;
  last occurrence wins within a value. A command-line `-XX:+UseBASE64Intrinsics` defeats a `JAVA_TOOL_OPTIONS` mitigation.
  **The static analyzer checks only that a mitigation flag is present; it does not model this order.** Confirm at runtime
  (`jcmd <pid> VM.flags -all`, origin shown in braces).
- `-Xlog:os+cpu=info` shows the JVM own CPU view (`avx512_vbmi`, with underscore); under `-XX:UseAVX=2` it lists no AVX-512.
- Files may lose their exec bit when copied; run scripts with `bash <script>` as shown above.

## Exposure needs all of these

1. Affected JDK build: 17.0.6 – before 17.0.21.1, 21 < 21.0.13.1, 25 < 25.0.5.1, 27 < 27.0.1.1 (26 is EOL, no fix). JDK 8/11 unaffected.
2. x86-64 (arm64 unaffected).
3. CPU with AVX-512 **VBMI and BW** (Ice Lake+/Zen 4+). Containers share the host CPU.
4. Base64 intrinsic active (no `-XX:-UseBASE64Intrinsics`, and `UseAVX` not capped below 3).

To confirm a build+CPU combo actually corrupts memory, use Calif's published checker (calif.io/java4shell)
rather than a home-made trigger.

## What image metadata can and cannot tell you

| Signal | In image config metadata? | Notes |
|---|---|---|
| Architecture (amd64/arm64) | Yes | arm64 images are not affected |
| JDK version | Usually (`ENV JAVA_VERSION`) | Can be stale/wrong if JDK replaced in a later layer; `--deep` reads `$JAVA_HOME/release` |
| Flags in `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS` | Yes | Strong signal; the JVM reads these itself |
| Flags in `ENTRYPOINT`/`CMD` | Yes | Only effective if the launcher forwards them to the JVM |
| `JAVA_OPTS` | Yes | **Not read by the JVM**; only some launch scripts expand it (decoy risk) |
| Flags set inside an entrypoint script | No (content scan only) | `hidden-mitigation` target |
| Flags added at `docker run` / K8s `env`/`args` | No | Check the workload spec, not the image |
| Host CPU AVX-512 VBMI/BW | No | Runtime/host property |
| Effective `UseBASE64Intrinsics` / `UseAVX` | No | `java -XX:+PrintFlagsFinal -version` or `jcmd <pid> VM.flags` |

Conclusion: metadata gives a reliable **upper bound** (not-affected by arch/version, or patched) and a
useful but fallible mitigation hint. Confirming exposure requires runtime state plus host CPU.

## Targets

| Target | Expected metadata verdict | Expected runtime verdict (AVX-512 VBMI/BW host) |
|---|---|---|
| vulnerable | VULN_JDK_NO_VISIBLE_MITIGATION | EXPOSED |
| patched | PATCHED_VERSION | PATCHED |
| mitigated-env | VULN_JDK_MITIGATION_IN_ENV | MITIGATED |
| mitigated-avx2 | VULN_JDK_MITIGATION_IN_ENV | MITIGATED |
| mitigated-cmd | VULN_JDK_MITIGATION_IN_ARGS | MITIGATED |
| hidden-mitigation | VULN_JDK_NO_VISIBLE_MITIGATION (false positive; `--deep` fixes it) | MITIGATED |
| decoy-javaopts | VULN_JDK_NO_VISIBLE_MITIGATION (correct) | EXPOSED |
| mitigated-disableintrinsic | VULN_JDK_MITIGATION_IN_ENV (_JAVA_OPTIONS) | MITIGATED_UNVERIFIED |

On a host without AVX-512 VBMI/BW, the runtime verdict for non-mitigated vulnerable images becomes
`VULN_JDK_BUT_NOT_EXPOSED_ON_THIS_HOST`.

## Files

- `Dockerfile` – multi-target
- `lab/launch.sh` – in-container read-only reporter
- `lab/entrypoint-wrapper.sh` – hides the flag for `hidden-mitigation`
- `scripts/inspect-image-metadata.sh` – static analyzer (`--deep`, `--json`)
- `scripts/run-matrix.sh` – side-by-side comparison
- `sim/` – Docker-free simulation: `fetch-jdks.sh`, `run-sim.sh`, `precedence-demo.sh`, `docker-shim.sh`, `scenarios.tsv`
- `testdata/*.json` – synthetic `docker image inspect` outputs for offline tests
=======
# Java4shell
This GitHub repository has been created and is maintained solely for educational and learning purposes. The content, code, and examples provided are intended to help users understand and explore the concepts demonstrated.
>>>>>>> acc829c990c26e7fbcd7119dea4525665f0cc26d
