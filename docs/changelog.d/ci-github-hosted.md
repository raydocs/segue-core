- CI Linux jobs run on GitHub-hosted `ubuntu-24.04` instead of Instabox.
  The root-disk bind mount is a free-disk step that drops preinstalled
  SDKs; the Android job keeps `/usr/local/lib/android`. Rust jobs cache
  builds with Swatinem/rust-cache v2.9.3, keyed per job. `tproxy-linux`
  enables KVM instead of TCG. The release-evidence workflows move with them.
- The `rust` required check is an aggregate of `rust-checks` (fmt, clippy,
  docs and the script checks) and four test shards: `rust-test-engine`,
  `rust-test-transport`, `rust-test-config`, and `rust-test-support` for
  every other workspace member. Each shard uses `--all-targets --locked`.
  `segue-fuzz` is still excluded, so `--all-targets` cannot launch its
  libFuzzer mains. The aggregate fails unless every shard succeeded.
  Stable tag pushes still skip the gate.
- The Apple job stays on the self-hosted Mac mini. Hosted macos-26 has
  Xcode 26.x, not the Xcode 27 the adapter build needs. Fork pull requests
  skip that job. `quick-check` uses the same Ubuntu runner and Rust cache.
