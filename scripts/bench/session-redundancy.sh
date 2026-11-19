#!/usr/bin/env bash
# Token-stream and conversation baselines.
#
# The token stream is one 30-byte event every 20 ms. The conversation is
# several upload / silence / token turns on one app connection, with optional
# impair faults during turn 2. Both are ignored cargo tests. Loopback only.
#
#   SEGUE_SCENARIO        token, convo, or both (default both)
#   SEGUE_EXIT_CLASS      ai or overseas (default ai). ai pins the exit and
#                         dials through a loopback home line. overseas is the
#                         old one-carrier, 30 s give-up path.
#   SEGUE_TOKEN_SECONDS   token-stream length in seconds (default 30)
#   SEGUE_STANDBY         0 or 1 (default 1, the product default). Printed as
#                         the standby column. Ignored for an overseas route.
#   SEGUE_CONVO_TURNS     conversation turns (default 3)
#   SEGUE_CONVO_UPLOAD    upload bytes per turn (default 1 MiB)
#   SEGUE_CONVO_SILENCE_MS
#                         silence after each upload (default 5000)
#   SEGUE_CONVO_TOKENS    30-byte events per turn (default 500)
#   SEGUE_BENCH_OUT       if set, the test also writes JSON. When both
#                         scenarios run, the token JSON is moved to
#                         <path>.token.json and the conversation JSON to
#                         <path>.convo.json.
#
# The long conversation is 4 MiB / 45 s / 3000 tokens:
#   SEGUE_CONVO_UPLOAD=$((4 * 1024 * 1024)) SEGUE_CONVO_SILENCE_MS=45000 \
#     SEGUE_CONVO_TOKENS=3000 SEGUE_SCENARIO=convo bash scripts/bench/session-redundancy.sh

set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

export CARGO_HOME="${CARGO_HOME:-/Volumes/dev/ci/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/Volumes/dev/ci/rustup}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/dev/ci/bee-target.noindex}"
export PATH="${CARGO_HOME}/bin:${PATH}"

seconds="${SEGUE_TOKEN_SECONDS:-30}"
export SEGUE_TOKEN_SECONDS="$seconds"

scenario="${SEGUE_SCENARIO:-both}"

run_token() {
    cargo +1.96.0 test -j 4 -p segue-kernel --test redundancy_e2e -- \
        --ignored --nocapture token_stream_baseline
}

run_convo() {
    cargo +1.96.0 test -j 4 -p segue-kernel --test redundancy_e2e -- \
        --ignored --nocapture conversation_baseline
}

stash_json() {
    local suffix="$1"
    if [[ -n "${SEGUE_BENCH_OUT:-}" && -f "$SEGUE_BENCH_OUT" ]]; then
        mv "$SEGUE_BENCH_OUT" "${SEGUE_BENCH_OUT}.${suffix}.json"
    fi
}

case "$scenario" in
    token | tokens | stream)
        run_token
        ;;
    convo | conversation)
        run_convo
        ;;
    both | all)
        run_token
        stash_json token
        run_convo
        stash_json convo
        ;;
    *)
        echo "SEGUE_SCENARIO must be token, convo or both (got ${scenario})" >&2
        exit 2
        ;;
esac
