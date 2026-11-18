#!/bin/bash
# TUN-path benchmark for a throwaway macOS VM.
#
# Compares segue-kernel, sing-box 1.15.0-alpha.13 and mihomo (system and
# mixed) through VLESS+REALITY+Vision and VLESS+gRPC. The engine owns the
# default route. The workload dials 198.51.100.20:5001; Xray-core's freedom
# outbound redirects that flow to a sink on 127.0.0.1:5001. dummynet on lo0
# impairs only the engine-to-Xray carrier port.
#
# Refuses unless SEGUE_VM_BENCH=throwaway. A real run also requires
# kern.hv_vmm_present=1 and root. --dry-run prints every command and does
# not run it. This script never reboots and never calls shutdown.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TUN_DIR="${ROOT}/scripts/bench/tun"
REPORT="${TUN_DIR}/report.py"
CONFIGS="${TUN_DIR}/configs.py"
WORKLOAD="${TUN_DIR}/workload.py"
# shellcheck source=tun/lib.sh
source "${TUN_DIR}/lib.sh"

XRAY_COMMIT="676eaf66f8f05d4d558ee7a74b4736623d3feeb9"
XRAY_TAG="v26.11.9"
SINGBOX_COMMIT="824dbcfb4dd0a95921840b1737b950cde590241e"
SINGBOX_TAG="v1.15.0-alpha.13"
MIHOMO_COMMIT="3c0d10a503f7b2fde3fe167d4d91dd05725d5268"

usage() {
  cat <<EOF
usage: SEGUE_VM_BENCH=throwaway $0 [--dry-run]
       [--work-dir DIR] [--json PATH] [--skip-build]
       [--engines LIST] [--protocols LIST]
       [--impairments LIST] [--workloads LIST]
       [--full-bytes N] [--lossy-bytes N] [--streams N]
       [--rr-count N] [--ttfb-count N]
       [--cell-timeout SEC] [--sample-interval-ms N]
       [--xray-src DIR] [--sing-box-src DIR] [--mihomo-src DIR]
       [--xray-bin PATH] [--sing-box-bin PATH] [--mihomo-bin PATH]
       [--kernel-bin PATH]

--dry-run prints the plan and exits 0. It still requires
SEGUE_VM_BENCH=throwaway. A real run also requires a VM
(sysctl kern.hv_vmm_present = 1) and root.

Engines: segue-kernel,sing-box,mihomo-system,mihomo-mixed
Protocols: reality,grpc
Impairments: clean,rtt50,rtt50-loss1,rtt150-loss3
Workloads: bulk-1,bulk-8,tcp-rr,ttfb

Pins (the 2026-11-18 SOCKS rerun): Xray-core ${XRAY_TAG}
${XRAY_COMMIT}, sing-box ${SINGBOX_TAG} ${SINGBOX_COMMIT},
mihomo ${MIHOMO_COMMIT}. mihomo is built with -tags with_gvisor so
the mixed tun stack links; the SOCKS binary was not.

Default work dir: /var/tmp/segue-tun-bench
Loss profiles transfer --lossy-bytes (default 8 MiB), not 1 GiB.
EOF
}

DRY_RUN=0
WORK=/var/tmp/segue-tun-bench
JSON=
SKIP_BUILD=0
ENGINES="segue-kernel,sing-box,mihomo-system,mihomo-mixed"
PROTOCOLS="reality,grpc"
IMPAIRMENTS="clean,rtt50,rtt50-loss1,rtt150-loss3"
WORKLOADS="bulk-1,bulk-8,tcp-rr,ttfb"
FULL_BYTES=1073741824
LOSSY_BYTES=8388608
STREAMS=8
RR_COUNT=200
TTFB_COUNT=20
CELL_TIMEOUT=240
SAMPLE_MS=100
XRAY_SRC_OPT=
SING_SRC_OPT=
MIHOMO_SRC_OPT=
XRAY_BIN_OPT=
SING_BIN_OPT=
MIHOMO_BIN_OPT=
KERNEL_BIN_OPT=

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --work-dir) WORK="${2:?}"; shift 2 ;;
    --json) JSON="${2:?}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --engines) ENGINES="${2:?}"; shift 2 ;;
    --protocols) PROTOCOLS="${2:?}"; shift 2 ;;
    --impairments) IMPAIRMENTS="${2:?}"; shift 2 ;;
    --workloads) WORKLOADS="${2:?}"; shift 2 ;;
    --full-bytes) FULL_BYTES="${2:?}"; shift 2 ;;
    --lossy-bytes) LOSSY_BYTES="${2:?}"; shift 2 ;;
    --streams) STREAMS="${2:?}"; shift 2 ;;
    --rr-count) RR_COUNT="${2:?}"; shift 2 ;;
    --ttfb-count) TTFB_COUNT="${2:?}"; shift 2 ;;
    --cell-timeout) CELL_TIMEOUT="${2:?}"; shift 2 ;;
    --sample-interval-ms) SAMPLE_MS="${2:?}"; shift 2 ;;
    --xray-src) XRAY_SRC_OPT="${2:?}"; shift 2 ;;
    --sing-box-src) SING_SRC_OPT="${2:?}"; shift 2 ;;
    --mihomo-src) MIHOMO_SRC_OPT="${2:?}"; shift 2 ;;
    --xray-bin) XRAY_BIN_OPT="${2:?}"; shift 2 ;;
    --sing-box-bin) SING_BIN_OPT="${2:?}"; shift 2 ;;
    --mihomo-bin) MIHOMO_BIN_OPT="${2:?}"; shift 2 ;;
    --kernel-bin) KERNEL_BIN_OPT="${2:?}"; shift 2 ;;
    -h | --help) usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$JSON" ]]; then
  JSON="${WORK}/tun-bench.json"
fi

PYTHON="/usr/bin/python3"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="$(command -v python3 || true)"
fi
if [[ -z "$PYTHON" || ! -x "$PYTHON" ]]; then
  echo "python3 is required" >&2
  exit 1
fi

HV_PRESENT="$(/usr/sbin/sysctl -n kern.hv_vmm_present 2>/dev/null || true)"
if [[ -z "$HV_PRESENT" ]]; then
  HV_PRESENT=unavailable
fi

if [[ "${SEGUE_VM_BENCH:-}" != "throwaway" ]]; then
  cat >&2 <<EOF
refusing: SEGUE_VM_BENCH is not set to throwaway.
This script installs a utun default route and PF dummynet rules.
Set SEGUE_VM_BENCH=throwaway only on a throwaway VM. --dry-run still
requires that variable; it prints the commands and does not run them.
EOF
  exit 2
fi

if [[ "$DRY_RUN" != 1 ]]; then
  if [[ "$HV_PRESENT" != "1" ]]; then
    cat >&2 <<EOF
refusing: this host is not a VM (sysctl kern.hv_vmm_present is ${HV_PRESENT}, need 1).
The benchmark takes the default route. On this Mac, re-run with --dry-run.
Inside the throwaway VM, export SEGUE_VM_BENCH=throwaway and run as root.
EOF
    exit 2
  fi
  if [[ "$(/usr/bin/id -u)" != "0" ]]; then
    echo "refusing: a real run must be root." >&2
    exit 2
  fi
else
  printf 'dry-run: not executing privileged commands (kern.hv_vmm_present=%s)\n' "$HV_PRESENT"
fi

# Validate the matrix before creating anything that looks like a run.
if ! "$PYTHON" "$REPORT" bulk-bytes --impairment clean --full-bytes "$FULL_BYTES" --lossy-bytes "$LOSSY_BYTES" >/dev/null; then
  exit 2
fi
if ! "$PYTHON" -c '
import sys
sys.path.insert(0, sys.argv[1])
import report
try:
    report._tokens(sys.argv[2], report.ENGINES, "engines")
    report._tokens(sys.argv[3], report.PROTOCOLS, "protocols")
    report._tokens(sys.argv[4], report.IMPAIRMENT_ORDER, "impairments")
    report._tokens(sys.argv[5], report.WORKLOAD_ORDER, "workloads")
except report.ReportError as exc:
    print("tun-bench: {0}".format(exc), file=sys.stderr)
    sys.exit(2)
' "$TUN_DIR" "$ENGINES" "$PROTOCOLS" "$IMPAIRMENTS" "$WORKLOADS"; then
  exit 2
fi

mkdir -p "$WORK/bin" "$WORK/cfg" "$WORK/cells" "$WORK/src" "$WORK/logs" "$WORK/mihomo-home" || exit 1

PIPE=7
SINK_PORT=5001
REALITY_PORT=24443
GRPC_PORT=24444
FAKE_IP=198.51.100.20
FAKE_PORT=5001
TARGET="${FAKE_IP}:${FAKE_PORT}"
KERNEL_LISTEN="127.0.0.1:10808"
PF_ANCHOR="com.apple/segue.tunbench"
PF_TOKEN=
PF_RELOAD=0
ENGINE_PID=
XRAY_PID=
SINK_PID=
WORKLOAD_PID=
ENGINE_TAG=
FAILED=0
CLEANED=0
SRC_XRAY=
SRC_SING=
SRC_MIHOMO=
XRAY_BIN=
SING_BIN=
MIHOMO_BIN=
KERNEL_BIN=

cd "$ROOT"

on_exit() {
  local status=$?
  cleanup
  exit "$status"
}
trap on_exit EXIT

git_head() {
  git -C "$1" rev-parse HEAD 2>/dev/null || true
}

require_src() {
  local label="$1" path="$2" want="$3"
  local head
  head="$(git_head "$path")"
  if [[ "$head" != "$want" ]]; then
    echo "${label}: ${path} is ${head:-missing}, want ${want}" >&2
    return 1
  fi
  note "${label}: ${path} (${want})"
}

locate_checkout() {
  # $1 label, $2 want, $3 varname, $4 dest, remaining candidates.
  local label="$1" want="$2" varname="$3" dest="$4"
  shift 4
  local cand head
  for cand in "$@"; do
    [[ -n "$cand" && -d "$cand" ]] || continue
    head="$(git_head "$cand")"
    if [[ "$head" == "$want" ]]; then
      printf -v "$varname" '%s' "$cand"
      note "${label}: ${cand}"
      return 0
    fi
    note "${label}: ${cand} is ${head:-not a git checkout}, want ${want}"
  done
  printf -v "$varname" '%s' "$dest"
  return 1
}

prepare_toolchain() {
  note "toolchain: cargo -j 4, GOMAXPROCS=4. Go engines are the 2026-11-18 pins."
  if [[ -d /Volumes/dev/ci/cargo ]]; then
    plan_raw "export CARGO_HOME=/Volumes/dev/ci/cargo RUSTUP_HOME=/Volumes/dev/ci/rustup PATH=/Volumes/dev/ci/cargo/bin:\$PATH"
    # shellcheck disable=SC1090
    export CARGO_HOME=/Volumes/dev/ci/cargo
    export RUSTUP_HOME=/Volumes/dev/ci/rustup
    export PATH="/Volumes/dev/ci/cargo/bin:${PATH}"
  else
    note "cargo from PATH (no /Volumes/dev/ci/cargo)"
  fi
  export CARGO_TARGET_DIR="${WORK}/cargo-target"
  plan_raw "export CARGO_TARGET_DIR=$(printf '%q' "$CARGO_TARGET_DIR")"
  if [[ -x /Volumes/dev/ci/go-sdk-1.27.4/go/bin/go ]]; then
    plan_raw "export PATH=/Volumes/dev/ci/go-sdk-1.27.4/go/bin:\$PATH GOPATH=/Volumes/dev/ci/go GOCACHE=/Volumes/dev/ci/go-cache GOTOOLCHAIN=local"
    export PATH="/Volumes/dev/ci/go-sdk-1.27.4/go/bin:${PATH}"
    export GOPATH=/Volumes/dev/ci/go
    export GOCACHE=/Volumes/dev/ci/go-cache
    export GOTOOLCHAIN=local
  else
    note "go from PATH; GOTOOLCHAIN is not forced"
  fi
  CARGO=(cargo)
  if [[ -d /Volumes/dev/ci/rustup/toolchains ]] && compgen -G "/Volumes/dev/ci/rustup/toolchains/1.96.0-*" >/dev/null; then
    CARGO=(cargo +1.96.0)
  fi
  plan "${CARGO[@]}" version
  plan go version
  if [[ "$DRY_RUN" != 1 ]]; then
    command -v go >/dev/null 2>&1 || {
      echo "go is required" >&2
      return 1
    }
    command -v cargo >/dev/null 2>&1 || {
      echo "cargo is required" >&2
      return 1
    }
    "${CARGO[@]}" version
    go version
  fi
}

clone_pinned() {
  local dest="$1" url="$2" ref="$3" want="$4"
  if [[ -d "$dest/.git" ]]; then
    plan git -C "$dest" fetch --depth 1 origin "$ref"
    plan git -C "$dest" checkout --detach FETCH_HEAD
    if [[ "$DRY_RUN" == 1 ]]; then
      return 0
    fi
    git -C "$dest" fetch --depth 1 origin "$ref"
    git -C "$dest" checkout --detach FETCH_HEAD
  else
    plan git init "$dest"
    plan git -C "$dest" remote add origin "$url"
    plan git -C "$dest" fetch --depth 1 origin "$ref"
    plan git -C "$dest" checkout --detach FETCH_HEAD
    if [[ "$DRY_RUN" == 1 ]]; then
      return 0
    fi
    git init "$dest"
    git -C "$dest" remote add origin "$url"
    git -C "$dest" fetch --depth 1 origin "$ref"
    git -C "$dest" checkout --detach FETCH_HEAD
  fi
  local head
  head="$(git_head "$dest")"
  if [[ "$head" != "$want" ]]; then
    echo "cloned ${dest} is ${head}, want ${want}" >&2
    return 1
  fi
}

prepare_sources() {
  if [[ -n "$XRAY_SRC_OPT" ]]; then
    require_src "xray-core" "$XRAY_SRC_OPT" "$XRAY_COMMIT" || return 1
    SRC_XRAY="$XRAY_SRC_OPT"
  elif ! locate_checkout "xray-core" "$XRAY_COMMIT" SRC_XRAY "$WORK/src/Xray-core" \
    "${XRAY_CORE_CHECKOUT:-}" /Volumes/dev/ci/xray/Xray-core; then
    clone_pinned "$SRC_XRAY" https://github.com/XTLS/Xray-core.git "$XRAY_TAG" "$XRAY_COMMIT" || return 1
  fi
  if [[ -n "$SING_SRC_OPT" ]]; then
    require_src "sing-box" "$SING_SRC_OPT" "$SINGBOX_COMMIT" || return 1
    SRC_SING="$SING_SRC_OPT"
  elif ! locate_checkout "sing-box" "$SINGBOX_COMMIT" SRC_SING "$WORK/src/sing-box" \
    /Volumes/dev/ci/tmp/sing-box-1.15a13 /Volumes/dev/ref/sing-box; then
    clone_pinned "$SRC_SING" https://github.com/SagerNet/sing-box.git "$SINGBOX_TAG" "$SINGBOX_COMMIT" || return 1
  fi
  if [[ -n "$MIHOMO_SRC_OPT" ]]; then
    require_src "mihomo" "$MIHOMO_SRC_OPT" "$MIHOMO_COMMIT" || return 1
    SRC_MIHOMO="$MIHOMO_SRC_OPT"
  elif ! locate_checkout "mihomo" "$MIHOMO_COMMIT" SRC_MIHOMO "$WORK/src/mihomo" \
    /Volumes/dev/ref/mihomo; then
    clone_pinned "$SRC_MIHOMO" https://github.com/MetaCubeX/mihomo.git "$MIHOMO_COMMIT" "$MIHOMO_COMMIT" || return 1
  fi
}

build_one() {
  local dest="$1"
  shift
  if [[ "$SKIP_BUILD" == 1 && -x "$dest" ]]; then
    note "skip-build: ${dest}"
    return 0
  fi
  "$@" || return 1
}

prepare_bins() {
  if [[ -n "$XRAY_BIN_OPT" ]]; then
    XRAY_BIN="$XRAY_BIN_OPT"
    note "xray binary: ${XRAY_BIN}"
  else
    XRAY_BIN="${WORK}/bin/xray"
    build_one "$XRAY_BIN" build_in "$SRC_XRAY" env CGO_ENABLED=0 GOMAXPROCS=4 go build -o "$XRAY_BIN" ./main || return 1
  fi
  if [[ -n "$SING_BIN_OPT" ]]; then
    SING_BIN="$SING_BIN_OPT"
    note "sing-box binary: ${SING_BIN}"
  else
    SING_BIN="${WORK}/bin/sing-box"
    # Tags match docs/benchmarks/results/2026-11-17-singbox-1.15a13-mihomo
    # (no with_grpc, so the grpc transport is v2raygrpclite). -checklinkname=0
    # is only the Go 1.27 linker check the README calls out.
    build_one "$SING_BIN" build_in "$SRC_SING" env CGO_ENABLED=1 GOMAXPROCS=4 \
      go build -tags 'with_gvisor,with_utls,badlinkname,tfogo_checklinkname0' \
      -ldflags '-checklinkname=0' -trimpath -o "$SING_BIN" ./cmd/sing-box || return 1
  fi
  if [[ -n "$MIHOMO_BIN_OPT" ]]; then
    MIHOMO_BIN="$MIHOMO_BIN_OPT"
    note "mihomo binary: ${MIHOMO_BIN}"
  else
    MIHOMO_BIN="${WORK}/bin/mihomo"
    note "mihomo is built with -tags with_gvisor (the SOCKS binary was not) so stack mixed links"
    build_one "$MIHOMO_BIN" build_in "$SRC_MIHOMO" env CGO_ENABLED=1 GOMAXPROCS=4 \
      go build -tags with_gvisor -trimpath -o "$MIHOMO_BIN" . || return 1
  fi
  if [[ -n "$KERNEL_BIN_OPT" ]]; then
    KERNEL_BIN="$KERNEL_BIN_OPT"
    note "segue-kernel binary: ${KERNEL_BIN}"
  else
    KERNEL_BIN="${CARGO_TARGET_DIR}/release/segue-kernel"
    build_one "$KERNEL_BIN" run "${CARGO[@]}" build -j 4 --release -p segue-kernel --bin segue-kernel || return 1
  fi
  if [[ "$DRY_RUN" != 1 ]]; then
    [[ -x "$XRAY_BIN" && -x "$SING_BIN" && -x "$MIHOMO_BIN" && -x "$KERNEL_BIN" ]] || {
      echo "a binary is missing after build" >&2
      return 1
    }
  fi
}

port_of() {
  if [[ "$1" == "reality" ]]; then
    printf '%s\n' "$REALITY_PORT"
  else
    printf '%s\n' "$GRPC_PORT"
  fi
}

start_engine() {
  local engine="$1" proto="$2" port="$3"
  local log="$WORK/logs/${engine}-${proto}.log"
  ENGINE_TAG="${engine}-${proto}"
  case "$engine" in
    segue-kernel)
      write_cfg "$WORK/cfg/kernel-${proto}.json" kernel --protocol "$proto" --port "$port" --listen "$KERNEL_LISTEN" || return 1
      snapshot_routes
      start_bg "$log" ENGINE_PID "$KERNEL_BIN" run --log "$WORK/logs/kernel-${proto}.detail" "$WORK/cfg/kernel-${proto}.json"
      ;;
    sing-box)
      write_cfg "$WORK/cfg/sing-box-${proto}.json" sing-box --protocol "$proto" --port "$port" || return 1
      snapshot_routes
      start_bg "$log" ENGINE_PID "$SING_BIN" run -c "$WORK/cfg/sing-box-${proto}.json"
      ;;
    mihomo-system | mihomo-mixed)
      local stack="system"
      if [[ "$engine" == "mihomo-mixed" ]]; then
        stack="mixed"
      fi
      write_cfg "$WORK/cfg/${engine}-${proto}.yaml" mihomo --protocol "$proto" --stack "$stack" --port "$port" || return 1
      snapshot_routes
      start_bg "$log" ENGINE_PID "$MIHOMO_BIN" -f "$WORK/cfg/${engine}-${proto}.yaml" -d "$WORK/mihomo-home"
      ;;
    *)
      echo "unknown engine ${engine}" >&2
      return 1
      ;;
  esac
  if [[ "$DRY_RUN" == 1 ]]; then
    note "sampler --engine-pid is 0 in this plan; a real run passes the live engine pid"
  fi
}

engine_up() {
  local engine="$1" proto="$2"
  if [[ "$DRY_RUN" != 1 ]]; then
    sleep 1
    if [[ -z "${ENGINE_PID:-}" || "$ENGINE_PID" == "0" ]] || ! kill -0 "$ENGINE_PID" 2>/dev/null; then
      return 1
    fi
  fi
  wait_for_tun || return 1
  local probe="$WORK/logs/probe-${engine}-${proto}.json"
  # Not a scored cell. engine-pid 0 keeps the probe out of the RSS sample.
  run_py probe --target "$TARGET" --timeout 20 --out "$probe" \
    --engine "$engine" --protocol "$proto" --impairment clean --workload probe \
    --engine-pid 0 || return 1
}

prepare() {
  prepare_toolchain || return 1
  prepare_sources || return 1
  prepare_bins || return 1
  enable_pf || return 1
  write_cfg "$WORK/cfg/xray.json" xray-server \
    --reality-port "$REALITY_PORT" --grpc-port "$GRPC_PORT" \
    --sink "127.0.0.1:${SINK_PORT}" || return 1
  start_bg "$WORK/logs/sink.log" SINK_PID "$PYTHON" "$WORKLOAD" sink --listen "127.0.0.1:${SINK_PORT}"
  start_bg "$WORK/logs/xray.log" XRAY_PID "$XRAY_BIN" run -c "$WORK/cfg/xray.json"
  # Same one-liner in the plan and in the run: both carrier ports accept.
  local ready=("$PYTHON" -c 'import socket,sys
[socket.create_connection(("127.0.0.1", int(p)), 5).close() for p in sys.argv[1:]]' "$REALITY_PORT" "$GRPC_PORT")
  plan "${ready[@]}"
  if [[ "$DRY_RUN" == 1 ]]; then
    return 0
  fi
  sleep 1
  "${ready[@]}" || {
    echo "xray did not accept on the carrier ports; see ${WORK}/logs/xray.log" >&2
    return 1
  }
}

matrix() {
  local engine proto port imp wl
  while IFS= read -r engine; do
    [[ -z "$engine" ]] && continue
    while IFS= read -r proto; do
      [[ -z "$proto" ]] && continue
      port="$(port_of "$proto")"
      note "engine ${engine} protocol ${proto} carrier 127.0.0.1:${port}"
      if ! start_engine "$engine" "$proto" "$port"; then
        fail_block "$engine" "$proto" "could not write config or start the engine"
        stop_engine
        continue
      fi
      if ! engine_up "$engine" "$proto"; then
        local tail=""
        if [[ -f "$WORK/logs/${engine}-${proto}.log" ]]; then
          tail="$(tail -n 15 "$WORK/logs/${engine}-${proto}.log" | tr '\n' ' ')"
        fi
        fail_block "$engine" "$proto" "tun did not capture ${FAKE_IP} or the probe failed ${tail}"
        clear_impairment || true
        stop_engine
        continue
      fi
      while IFS= read -r imp; do
        [[ -z "$imp" ]] && continue
        if ! apply_impairment "$imp" "$port"; then
          while IFS= read -r wl; do
            [[ -z "$wl" ]] && continue
            record_error "$engine" "$proto" "$imp" "$wl" "could not install dummynet"
          done < <(split_csv "$WORKLOADS")
          continue
        fi
        while IFS= read -r wl; do
          [[ -z "$wl" ]] && continue
          note "cell ${engine} ${proto} ${imp} ${wl}"
          run_workload "$engine" "$proto" "$imp" "$wl"
        done < <(split_csv "$WORKLOADS")
      done < <(split_csv "$IMPAIRMENTS")
      clear_impairment || true
      stop_engine
    done < <(split_csv "$PROTOCOLS")
  done < <(split_csv "$ENGINES")
}

write_meta() {
  GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  export GENERATED_AT HV_PRESENT DRY_RUN FULL_BYTES LOSSY_BYTES RR_COUNT TTFB_COUNT
  export SAMPLE_MS CELL_TIMEOUT WORK JSON XRAY_COMMIT SINGBOX_COMMIT MIHOMO_COMMIT
  export XRAY_TAG SINGBOX_TAG TARGET
  "$PYTHON" - "$WORK/meta.json" <<'PY'
import json, os, sys
meta = {
    "generated_at": os.environ["GENERATED_AT"],
    "dry_run": os.environ["DRY_RUN"] == "1",
    "hv_vmm_present": os.environ["HV_PRESENT"],
    "target": os.environ["TARGET"],
    "sink": "127.0.0.1:5001",
    "carrier_ports": {"reality": 24443, "grpc": 24444},
    "full_bytes": int(os.environ["FULL_BYTES"]),
    "lossy_bytes": int(os.environ["LOSSY_BYTES"]),
    "rr_count": int(os.environ["RR_COUNT"]),
    "ttfb_count": int(os.environ["TTFB_COUNT"]),
    "sample_interval_ms": int(os.environ["SAMPLE_MS"]),
    "cell_timeout_s": int(os.environ["CELL_TIMEOUT"]),
    "work_dir": os.environ["WORK"],
    "json_path": os.environ["JSON"],
    "pins": {
        "xray_core": os.environ["XRAY_COMMIT"],
        "xray_tag": os.environ["XRAY_TAG"],
        "sing_box": os.environ["SINGBOX_COMMIT"],
        "sing_box_tag": os.environ["SINGBOX_TAG"],
        "mihomo": os.environ["MIHOMO_COMMIT"],
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(meta, fh, indent=2)
    fh.write("\n")
PY
}

render() {
  write_meta || return 1
  if [[ "$DRY_RUN" == 1 ]]; then
    "$PYTHON" "$REPORT" plan \
      --engines "$ENGINES" --protocols "$PROTOCOLS" \
      --impairments "$IMPAIRMENTS" --workloads "$WORKLOADS" \
      --full-bytes "$FULL_BYTES" --lossy-bytes "$LOSSY_BYTES" \
      --rr-count "$RR_COUNT" --ttfb-count "$TTFB_COUNT" \
      --json "$JSON" --meta "$WORK/meta.json"
  else
    "$PYTHON" "$REPORT" render --cells "$WORK/cells" --meta "$WORK/meta.json" --json "$JSON"
  fi
}

rc=0
if ! prepare; then
  rc=1
else
  matrix || rc=$?
fi
cleanup
if ! render; then
  rc=1
fi
if [[ "$FAILED" == 1 ]]; then
  rc=1
fi
printf 'SUMMARY failed=%s json=%s\n' "$FAILED" "$JSON"
exit "$rc"
