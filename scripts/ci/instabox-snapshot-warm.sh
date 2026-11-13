#!/usr/bin/env bash
# Runs inside a fresh Instabox `ci` machine, from the repository checkout at
# ~/work/segue-core/segue-core, to fill the toolchains and build caches that the
# rust, go-oracles and android CI jobs start from. scripts/ci/refresh-instabox-snapshot.sh
# drives it; see that script for how the snapshot is saved and named.
#
# Everything here mirrors .github/workflows/ci.yml. A cache that drifts from
# the workflow only costs time: each job still installs and builds what it
# needs, and cargo, Go and Gradle rebuild whatever the snapshot lacks.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo"

rust_toolchain=1.96.0
go_version=1.27.3
xray_core_rev=676eaf66f8f05d4d558ee7a74b4736623d3feeb9
hysteria_rev=619a6f856b69fb7ee6a7a379e810e68b84004605
android_ndk=26.3.11579264

log() { printf '\n==> %s\n' "$*"; }

log "Rust $rust_toolchain"
rustup toolchain install "$rust_toolchain" --profile minimal --component clippy,rustfmt
rustup default "$rust_toolchain"
rustup target add --toolchain "$rust_toolchain" \
  aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

log "Go $go_version in the runner tool cache (actions/setup-go finds it there)"
go_dir="${RUNNER_TOOL_CACHE:-/opt/hostedtoolcache}/go/$go_version/x64"
if [[ ! -x "$go_dir/bin/go" ]]; then
  archive="$(mktemp)"
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --retry 3 \
    --output "$archive" "https://go.dev/dl/go${go_version}.linux-amd64.tar.gz"
  sudo install -d -o "$(id -u)" -g "$(id -g)" "$go_dir"
  tar -xzf "$archive" -C "$go_dir" --strip-components=1
  rm -f "$archive"
fi
[[ -e "$go_dir.complete" ]] || sudo install -m 0644 -o "$(id -u)" -g "$(id -g)" /dev/null "$go_dir.complete"
export PATH="$go_dir/bin:$PATH"
go version

log "Android SDK components"
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --install \
  "platforms;android-35" "build-tools;36.0.0" "ndk;$android_ndk" "cmake;3.22.1" >/dev/null
export JAVA_HOME="$JAVA_HOME_17_X64" PATH="$JAVA_HOME_17_X64/bin:$PATH"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$android_ndk" ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/$android_ndk"

# The jobs bind-mount this directory over target/ after checkout (whose clean
# would delete a target/ inside the workspace). It lives on /data, which
# refresh-instabox-snapshot.sh grows; the 79 GiB root disk is too small for it.
target_dir="$HOME/.cache/segue-target"
log "Build outputs in $target_dir, as the CI jobs mount them"
mkdir -p "$target_dir" target
mountpoint -q target || sudo mount --bind "$target_dir" target

log "rust job"
cargo fetch --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings -W clippy::perf -W clippy::suspicious
cargo test --workspace --exclude segue-fuzz --all-targets --locked --no-run
cargo test --locked -p segue-engine --test tproxy_tests --no-run
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

log "android job"
bash scripts/build-android-adapter.sh
for task in :xraymobile:testDebugUnitTest :xraymobile:lintDebug; do
  GRADLE_USER_HOME="$repo/target/mobile/android-gradle-home" \
    XRAY_FFI_ANDROID_DIR="$repo/target/mobile/android" \
    platform/android/gradlew -p platform/android "$task" --dependency-verification strict --no-daemon
done

log "go-oracles job (builds every oracle and interop binary once)"
rm -rf Xray-core
git clone --quiet https://github.com/XTLS/Xray-core Xray-core
git -C Xray-core checkout --quiet --detach "$xray_core_rev"
mkdir -p target/references
rm -rf target/references/hysteria-2.12.2
git clone --quiet https://github.com/apernet/hysteria target/references/hysteria-2.12.2
git -C target/references/hysteria-2.12.2 checkout --quiet --detach "$hysteria_rev"
for module in . tools/reality-oracle/masquerade tools/reality-oracle/grpc tools/wireguard-reference; do
  (cd "$module" && go mod download)
done
# The same profile the job sets; the interop steps run in workflow order. A
# step that fails here still leaves its build outputs, so only report it.
mapfile -t steps < <(awk '/^  go-oracles:/,/^  rc-interop:/' .github/workflows/ci.yml |
  sed -n 's/^ *\(run: \)\{0,1\}\(bash scripts\/[^ ]*\.sh\)$/\2/p')
failed=0
for step in "${steps[@]}"; do
  log "$step"
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only bash -c "$step" || {
    echo "warm: '$step' failed; its caches are kept" >&2
    failed=$((failed + 1))
  }
done

log "Clean up"
# The job's own checkout replaces Xray-core and the hysteria reference.
rm -rf Xray-core
git checkout --quiet --force --detach HEAD
git clean -ffdxq -e target
sudo umount target
rmdir target
rm -f ~/.bash_history ~/.git-credentials
df -h / /data
du -sh "$target_dir" ~/.cargo ~/.cache/go-build ~/go/pkg/mod 2>/dev/null || true
echo "warm: done ($failed go-oracles steps failed)"
