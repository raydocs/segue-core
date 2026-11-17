- Test harness: `scripts/tests/check-mobile-toolchains.test.sh` and
  `scripts/tests/check-mobile-device-evidence.test.sh` pass on macOS (the
  self-hosted Mac mini runner) as well as Linux. The Android build test now
  stubs `cargo` on `PATH` instead of assuming the host running the test suite
  has a Rust toolchain installed — `build-android-libs.sh` probes for `cargo`
  before it rejects a mismatched `ANDROID_API_LEVEL`, so on a machine without
  cargo the expected diagnostic never fired. The device-evidence validator
  (`scripts/check-mobile-device-evidence.py`) now normalizes RFC 3339
  fractional seconds to six digits before `datetime.fromisoformat`: Python
  releases before 3.11 (macOS ships 3.9 with the Xcode CLT) only accept 3- or
  6-digit fractions, so a timestamp like `06:00:00.5Z` was rejected as
  unparseable instead of reaching the `durationSeconds` cross-check. The
  accepted timestamp format and every verdict are unchanged on Python 3.11+.
