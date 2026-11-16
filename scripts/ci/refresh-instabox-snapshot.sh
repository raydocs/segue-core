#!/usr/bin/env bash
# Rebuilds the Instabox snapshot that the rust, tproxy-linux, go-oracles and android CI jobs
# start from (runs-on: instabox-large-snapshot-segue-warm).
#
# Refresh it at least every 30 days: a snapshot keeps the GitHub Actions
# runner it was saved with, and GitHub stops sending jobs to a runner more
# than 30 days behind its latest release. Refresh it sooner when the pinned
# Rust, Go, Android or Xray-core versions in ci.yml change, or when CI builds
# start taking much longer, because the warm build outputs have drifted.
#
# Needs the instabox CLI (npx instabox@latest) and INSTABOX_API_KEY for the
# workspace that the raydocs GitHub App is linked to. The repository must stay
# private with "Run workflows from fork pull requests" off, or Instabox
# refuses jobs that name a snapshot.
#
# The snapshot holds no credentials: the repository comes in as a git bundle,
# origin points at the public URL with no token, and each job brings its own.
#
# Usage: scripts/ci/refresh-instabox-snapshot.sh [git-ref]   (default origin/main)
set -euo pipefail

ref="${1:-origin/main}"
name="${SNAPSHOT_NAME:-segue-warm}"
machine="${name}-src-$(date -u +%Y%m%d%H%M)"
ib="${INSTABOX:-instabox}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
remote_dir=/data/home/work/segue-core/segue-core
: "${INSTABOX_API_KEY:?set INSTABOX_API_KEY to the raydocs CI workspace key}"

bundle="$(mktemp -d)/segue.bundle"
git -C "$repo" fetch --quiet origin
git -C "$repo" bundle create "$bundle" "$ref" >/dev/null
commit="$(git -C "$repo" rev-parse "$ref^{commit}")"

echo "creating $machine (ci template, 8 vCPU / 16 GiB, the instabox-large size)"
"$ib" create --name "$machine" --template ci --vcpus 8 --mem-mib 16384 --auto-suspend 0 >/dev/null
# The warm target (~80 GiB) lives on /data; jobs from the snapshot get at
# least this disk size.
"$ib" resize "$machine" --disk 160 >/dev/null
trap 'echo "machine $machine kept for inspection; remove it with: $ib rm $machine" >&2' ERR

"$ib" push "$machine" "$bundle" /data/home/segue.bundle >/dev/null
"$ib" push "$machine" "$repo/scripts/ci/instabox-snapshot-warm.sh" /data/home/instabox-snapshot-warm.sh >/dev/null
"$ib" exec "$machine" --timeout 600 -- bash -c "
  set -e
  rm -rf $remote_dir && mkdir -p $remote_dir && cd $remote_dir
  git init --quiet && git remote add origin https://github.com/raydocs/segue-core
  git fetch --quiet /data/home/segue.bundle '+refs/remotes/origin/*:refs/remotes/origin/*'
  git checkout --quiet --detach $commit
  rm /data/home/segue.bundle
  install -D -m 0755 /data/home/instabox-snapshot-warm.sh scripts/ci/instabox-snapshot-warm.sh"

job="$("$ib" exec --background "$machine" --cwd "$remote_dir" --json -- bash scripts/ci/instabox-snapshot-warm.sh |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["jobId"])')"
echo "warming in job $job (about an hour); follow with: $ib jobs logs $machine $job -f"
"$ib" jobs logs "$machine" "$job" -f

"$ib" exec "$machine" -- bash -c 'rm -f /data/home/instabox-snapshot-warm.sh; git config --global --list 2>/dev/null | grep -i credential && exit 1 || true'
"$ib" stop "$machine"
# Jobs that name the snapshot are refused between this delete and the save
# below (a few minutes), so refresh when no CI run is starting.
if "$ib" snapshot ls --json | python3 -c 'import json,sys; sys.exit(0 if any(s["name"]==sys.argv[1] for s in json.load(sys.stdin)) else 1)' "$name"; then
  echo "removing the previous $name snapshot"
  "$ib" snapshot rm "$name" --yes
fi
"$ib" snapshot save "$machine" --name "$name" --description "segue-core CI warm caches at $commit"
"$ib" rm "$machine" --yes
trap - ERR
echo "saved snapshot $name from $commit"
