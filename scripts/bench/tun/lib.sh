# Helpers for tun-bench-macos.sh. Sourced, not executed.
# shellcheck shell=bash

split_csv() {
  local item old noglob=0
  old="$IFS"
  case $- in
    *f*) ;;
    *) set -f; noglob=1 ;;
  esac
  IFS=','
  # shellcheck disable=SC2086
  set -- $1
  IFS="$old"
  if [[ "$noglob" == 1 ]]; then
    set +f
  fi
  for item in "$@"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [[ -n "$item" ]] && printf '%s\n' "$item"
  done
}

plan() {
  printf '+'
  local arg
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n'
}

plan_raw() {
  printf '+ %s\n' "$1"
}

note() {
  printf '# %s\n' "$1"
}

run() {
  plan "$@"
  if [[ "$DRY_RUN" == 1 ]]; then
    return 0
  fi
  "$@"
}

build_in() {
  local dir="$1"
  shift
  plan_raw "( cd $(printf '%q' "$dir") && $(printf '%q ' "$@"))"
  if [[ "$DRY_RUN" == 1 ]]; then
    return 0
  fi
  (cd "$dir" && "$@")
}

start_bg() {
  local log="$1"
  local varname="$2"
  shift 2
  plan_raw "$(printf '%q ' "$@")>$(printf '%q' "$log") 2>&1 &"
  if [[ "$DRY_RUN" == 1 ]]; then
    printf -v "$varname" '%s' "0"
    return 0
  fi
  "$@" >"$log" 2>&1 &
  printf -v "$varname" '%s' "$!"
}

stop_pid() {
  local pid="${1:-}"
  if [[ "$DRY_RUN" == 1 || -z "$pid" || "$pid" == "0" ]]; then
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  local i
  for i in 1 2 3 4 5; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    sleep 1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

snapshot_routes() {
  plan /usr/sbin/netstat -rn -f inet
  plan /usr/sbin/netstat -rn -f inet6
  if [[ "$DRY_RUN" == 1 ]]; then
    return 0
  fi
  /usr/sbin/netstat -rn -f inet >"$WORK/routes.v4.before" || true
  /usr/sbin/netstat -rn -f inet6 >"$WORK/routes.v6.before" || true
}

restore_routes() {
  if [[ "$DRY_RUN" == 1 || ! -f "$WORK/routes.v4.before" ]]; then
    return 0
  fi
  /usr/sbin/netstat -rn -f inet >"$WORK/routes.v4.after" || true
  /usr/sbin/netstat -rn -f inet6 >"$WORK/routes.v6.after" || true
  local fam dest gw
  while IFS=$'\t' read -r fam dest gw; do
    [[ -z "${fam:-}" ]] && continue
    if [[ "$fam" == "v4" && "$dest" == "default" ]]; then
      /sbin/route -n delete default "$gw" >/dev/null 2>&1 || true
    elif [[ "$fam" == "v4" ]]; then
      /sbin/route -n delete -net "$dest" "$gw" >/dev/null 2>&1 || true
    elif [[ "$dest" == "default" ]]; then
      /sbin/route -n delete -inet6 default "$gw" >/dev/null 2>&1 || true
    else
      /sbin/route -n delete -inet6 -net "$dest" "$gw" >/dev/null 2>&1 || true
    fi
  done < <("$PYTHON" "$REPORT" leftover-routes \
    --before-v4 "$WORK/routes.v4.before" \
    --after-v4 "$WORK/routes.v4.after" \
    --before-v6 "$WORK/routes.v6.before" \
    --after-v6 "$WORK/routes.v6.after")
}

stop_engine() {
  note "stop engine and delete utun routes it added"
  if [[ "$DRY_RUN" == 1 ]]; then
    plan_raw "kill -TERM <engine pid> (SIGKILL after 5s) && diff netstat and route -n delete new utun routes"
    ENGINE_PID=
    return 0
  fi
  stop_pid "${ENGINE_PID:-}"
  ENGINE_PID=
  restore_routes || true
}

enable_pf() {
  note "pf: dummynet anchor for the loopback carrier only"
  plan /sbin/pfctl -E
  plan /sbin/pfctl -sr
  if [[ "$DRY_RUN" == 1 ]]; then
    note "if the ruleset has dummynet-anchor \"com.apple/*\", load com.apple/segue.tunbench and do not reload pf.conf"
    plan_raw "/sbin/pfctl -a com.apple/segue.tunbench -f <rules for the active carrier port>"
    note "otherwise comment 'set skip on lo0' if present, append anchor segue.tunbench, then:"
    plan_raw "/usr/bin/python3 $(printf '%q' "$REPORT") pf-patch --anchor segue.tunbench < /etc/pf.conf > $(printf '%q' "$WORK/pf.conf.bench")"
    plan_raw "cp /etc/pf.conf $(printf '%q' "$WORK/pf.conf.orig")"
    plan_raw "/sbin/pfctl -f $(printf '%q' "$WORK/pf.conf.bench")"
    plan_raw "/sbin/pfctl -a segue.tunbench -f <rules for the active carrier port>"
    PF_ANCHOR="com.apple/segue.tunbench"
    return 0
  fi
  local out
  out=$(/sbin/pfctl -E 2>&1) || true
  PF_TOKEN=$(printf '%s\n' "$out" | awk '/[Tt]oken/ { print $NF; exit }')
  if /sbin/pfctl -sr 2>/dev/null | grep -F 'dummynet-anchor "com.apple/*"' >/dev/null; then
    PF_ANCHOR="com.apple/segue.tunbench"
    PF_RELOAD=0
    note "pf anchor ${PF_ANCHOR} (main ruleset already evaluates com.apple/*)"
  else
    PF_ANCHOR="segue.tunbench"
    PF_RELOAD=1
    note "pf anchor ${PF_ANCHOR} (reloading a patched main ruleset)"
    cp /etc/pf.conf "$WORK/pf.conf.orig"
    "$PYTHON" "$REPORT" pf-patch --anchor segue.tunbench <"$WORK/pf.conf.orig" >"$WORK/pf.conf.bench"
    /sbin/pfctl -f "$WORK/pf.conf.bench"
  fi
}

apply_impairment() {
  local imp="$1"
  local port="$2"
  local line
  local args=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && args+=("$line")
  done < <("$PYTHON" "$REPORT" dnctl-args --impairment "$imp" --pipe "$PIPE")
  local anchor="${PF_ANCHOR:-com.apple/segue.tunbench}"
  if [[ ${#args[@]} -eq 0 ]]; then
    note "impairment ${imp}: remove the carrier pipe"
    plan /usr/sbin/dnctl pipe delete "$PIPE"
    plan /sbin/pfctl -a "$anchor" -F all
    if [[ "$DRY_RUN" != 1 ]]; then
      /usr/sbin/dnctl pipe delete "$PIPE" >/dev/null 2>&1 || true
      /sbin/pfctl -a "$anchor" -F all >/dev/null 2>&1 || true
    fi
    return 0
  fi
  note "impairment ${imp}: dummynet out on lo0 port ${port} (RTT ~= 2 * delay; plr is per direction)"
  run /usr/sbin/dnctl "${args[@]}" || return 1
  local rules="$WORK/cfg/dummynet-${port}.conf"
  plan_raw "$(printf '%q' "$PYTHON") $(printf '%q' "$REPORT") pf-rules --port ${port} --pipe ${PIPE} > $(printf '%q' "$rules")"
  "$PYTHON" "$REPORT" pf-rules --port "$port" --pipe "$PIPE" >"$rules" || return 1
  plan /sbin/pfctl -a "$anchor" -f "$rules"
  if [[ "$DRY_RUN" != 1 ]]; then
    /sbin/pfctl -a "$anchor" -f "$rules" || return 1
  fi
}

clear_impairment() {
  apply_impairment clean "$REALITY_PORT"
}

write_cfg() {
  local out="$1"
  shift
  plan_raw "$(printf '%q ' "$PYTHON" "$CONFIGS" "$@")>$(printf '%q' "$out")"
  if [[ "$DRY_RUN" == 1 ]]; then
    "$PYTHON" "$CONFIGS" "$@" | sed 's/^/| /'
    return 0
  fi
  "$PYTHON" "$CONFIGS" "$@" >"$out"
}

run_py() {
  if [[ "$DRY_RUN" == 1 ]]; then
    plan "$PYTHON" "$WORKLOAD" "$@"
    return 0
  fi
  "$PYTHON" "$WORKLOAD" "$@" &
  WORKLOAD_PID=$!
  local waited=0 limit
  limit=$((CELL_TIMEOUT + 30))
  while kill -0 "$WORKLOAD_PID" 2>/dev/null; do
    if [[ "$waited" -ge "$limit" ]]; then
      kill -TERM "$WORKLOAD_PID" 2>/dev/null || true
      sleep 1
      kill -KILL "$WORKLOAD_PID" 2>/dev/null || true
      wait "$WORKLOAD_PID" 2>/dev/null || true
      WORKLOAD_PID=
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  local rc=0
  wait "$WORKLOAD_PID" || rc=$?
  WORKLOAD_PID=
  return "$rc"
}

wait_for_tun() {
  plan_raw "route -n get ${FAKE_IP}  # repeat until interface: utun (15s)"
  if [[ "$DRY_RUN" == 1 ]]; then
    return 0
  fi
  local i out
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    out=$(/sbin/route -n get "$FAKE_IP" 2>&1 || true)
    if printf '%s\n' "$out" | grep -E 'interface: utun[0-9]+' >/dev/null; then
      printf '%s\n' "$out" >"$WORK/logs/route-${ENGINE_TAG}.txt"
      return 0
    fi
    if [[ -n "${ENGINE_PID:-}" && "$ENGINE_PID" != "0" ]] && ! kill -0 "$ENGINE_PID" 2>/dev/null; then
      return 1
    fi
    sleep 1
  done
  return 1
}

cell_path() {
  printf '%s/cells/%s__%s__%s__%s.json\n' "$WORK" "$1" "$2" "$3" "$4"
}

record_error() {
  local engine="$1" proto="$2" imp="$3" wl="$4" message="$5"
  local cell extra=() bytes
  cell=$(cell_path "$engine" "$proto" "$imp" "$wl")
  case "$wl" in
    bulk-1 | bulk-8)
      bytes=$("$PYTHON" "$REPORT" bulk-bytes --impairment "$imp" --full-bytes "$FULL_BYTES" --lossy-bytes "$LOSSY_BYTES")
      extra=(--bytes-requested "$bytes")
      ;;
    tcp-rr) extra=(--iterations "$RR_COUNT") ;;
    ttfb) extra=(--iterations "$TTFB_COUNT") ;;
  esac
  if [[ "$DRY_RUN" == 1 ]]; then
    note "FAIL ${engine} ${proto} ${imp} ${wl}: ${message}"
    return 0
  fi
  "$PYTHON" "$REPORT" error-cell --out "$cell" \
    --engine "$engine" --protocol "$proto" --impairment "$imp" --workload "$wl" \
    --error "$message" "${extra[@]}"
  FAILED=1
}

fail_block() {
  local engine="$1" proto="$2" message="$3"
  local imp wl
  while IFS= read -r imp; do
    [[ -z "$imp" ]] && continue
    while IFS= read -r wl; do
      [[ -z "$wl" ]] && continue
      record_error "$engine" "$proto" "$imp" "$wl" "$message"
    done < <(split_csv "$WORKLOADS")
  done < <(split_csv "$IMPAIRMENTS")
}

run_workload() {
  local engine="$1" proto="$2" imp="$3" wl="$4"
  local cell bytes
  cell=$(cell_path "$engine" "$proto" "$imp" "$wl")
  local common=(
    --target "$TARGET" --timeout "$CELL_TIMEOUT" --engine-pid "${ENGINE_PID:-0}"
    --interval-ms "$SAMPLE_MS" --out "$cell"
    --engine "$engine" --protocol "$proto" --impairment "$imp" --workload "$wl"
  )
  local rc=0
  case "$wl" in
    bulk-1 | bulk-8)
      bytes=$("$PYTHON" "$REPORT" bulk-bytes --impairment "$imp" --full-bytes "$FULL_BYTES" --lossy-bytes "$LOSSY_BYTES")
      local streams=1
      if [[ "$wl" == "bulk-8" ]]; then
        streams="$STREAMS"
      fi
      run_py bulk "${common[@]}" --bytes "$bytes" --streams "$streams" || rc=$?
      ;;
    tcp-rr)
      run_py tcp-rr "${common[@]}" --count "$RR_COUNT" || rc=$?
      ;;
    ttfb)
      run_py ttfb "${common[@]}" --count "$TTFB_COUNT" || rc=$?
      ;;
    *)
      record_error "$engine" "$proto" "$imp" "$wl" "unknown workload"
      return 0
      ;;
  esac
  if [[ "$DRY_RUN" == 1 ]]; then
    return 0
  fi
  if [[ "$rc" != 0 ]]; then
    FAILED=1
    if [[ ! -s "$cell" ]] || ! "$PYTHON" -c 'import json,sys; json.load(open(sys.argv[1]))' "$cell" 2>/dev/null; then
      record_error "$engine" "$proto" "$imp" "$wl" "workload failed or hit the cell timeout"
    fi
  fi
}

cleanup() {
  if [[ "${CLEANED:-0}" == "1" ]]; then
    return 0
  fi
  CLEANED=1
  note "cleanup: stop leftover processes, delete new utun routes, flush the bench anchor and pipe"
  if [[ "$DRY_RUN" == 1 ]]; then
    plan_raw "kill -TERM <workload> <engine> <xray> <sink> (SIGKILL after 5s)"
    plan_raw "diff netstat against the pre-engine snapshot; route -n delete each new utun route"
    plan /usr/sbin/dnctl pipe delete "$PIPE"
    plan /sbin/pfctl -a "com.apple/segue.tunbench" -F all
    plan /sbin/pfctl -a "segue.tunbench" -F all
    plan_raw "pfctl -f $(printf '%q' "$WORK/pf.conf.orig")   # only if the main ruleset was reloaded"
    plan_raw "pfctl -X <token printed by pfctl -E>"
    return 0
  fi
  stop_pid "${WORKLOAD_PID:-}"
  WORKLOAD_PID=
  stop_pid "${ENGINE_PID:-}"
  ENGINE_PID=
  stop_pid "${XRAY_PID:-}"
  XRAY_PID=
  stop_pid "${SINK_PID:-}"
  SINK_PID=
  restore_routes || true
  /usr/sbin/dnctl pipe delete "$PIPE" >/dev/null 2>&1 || true
  /sbin/pfctl -a "com.apple/segue.tunbench" -F all >/dev/null 2>&1 || true
  /sbin/pfctl -a "segue.tunbench" -F all >/dev/null 2>&1 || true
  if [[ "${PF_RELOAD:-0}" == "1" && -f "$WORK/pf.conf.orig" ]]; then
    /sbin/pfctl -f "$WORK/pf.conf.orig" >/dev/null 2>&1 || true
  fi
  if [[ -n "${PF_TOKEN:-}" ]]; then
    /sbin/pfctl -X "$PF_TOKEN" >/dev/null 2>&1 || true
    PF_TOKEN=
  fi
}
