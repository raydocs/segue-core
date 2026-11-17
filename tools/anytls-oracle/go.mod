// A module of its own: the root module is Rust, and the oracle only needs the
// sing-anytls padding package to pin the scheme's digest and record sizes.
//
// Run it from the directory: `go mod tidy && go run . out.json`.
module segue-core/tools/anytls-oracle

go 1.24

require github.com/anytls/sing-anytls v0.0.0-20260928104022-580984e4d8cb
