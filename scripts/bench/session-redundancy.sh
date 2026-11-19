#!/usr/bin/env bash
# Stage 0 token-stream baseline.
#
# Runs the ignored kernel test that drives an SSE-like origin through the
# session stack and the impairment relay (TCP loss-recovery emulation).
# Prints one Markdown table for the token stream and one for new flows.
#
#   SEGUE_TOKEN_SECONDS   origin length in seconds (default 30)
#   SEGUE_STANDBY         0 or 1 (default 1, the product default). Printed as
#                         the standby column. The harness route is overseas,
#                         so the AI standby does not dial in either mode.
#   SEGUE_BENCH_OUT       if set, the test also writes the same numbers as JSON
#
# Loopback only. No root, no fixed ports.

set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

export CARGO_HOME="${CARGO_HOME:-/Volumes/dev/ci/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/Volumes/dev/ci/rustup}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/dev/ci/bee-target.noindex}"
export PATH="${CARGO_HOME}/bin:${PATH}"

seconds="${SEGUE_TOKEN_SECONDS:-30}"
export SEGUE_TOKEN_SECONDS="$seconds"

cargo +1.96.0 test -j 4 -p segue-kernel --test redundancy_e2e -- \
    --ignored --nocapture token_stream_baseline
