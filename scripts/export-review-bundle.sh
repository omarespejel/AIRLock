#!/usr/bin/env bash
# Export an internally verifiable reviewer archive.
#
# A reviewer must be able to establish that the files they read are exactly the
# named commit. A source tarball cannot do that: it carries no object database,
# so `git rev-parse HEAD` is unavailable and the published commit id is an
# unverifiable assertion. This exports a real `git bundle` plus a manifest over
# its reconstruction inputs and a `VERIFY.sh` that checks both. The outer
# archive hash must still be shared through a trusted channel.
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-}"
if [[ -z "$OUT" ]]; then
  printf 'usage: %s <output.tar.gz>\n' "$0" >&2
  exit 1
fi
CALLER_ROOT="$PWD"
case "$OUT" in
  /*) ;;
  *) OUT="$CALLER_ROOT/$OUT" ;;
esac
OUT_PARENT="$(dirname "$OUT")"
OUT_NAME="$(basename "$OUT")"
if [[ ! -d "$OUT_PARENT" ]]; then
  printf 'FAIL: output directory does not exist: %s\n' "$OUT_PARENT" >&2
  exit 1
fi
OUT_PARENT="$(cd "$OUT_PARENT" && pwd -P)"
OUT="$OUT_PARENT/$OUT_NAME"
if [[ -e "$OUT" || -L "$OUT" ]]; then
  printf 'FAIL: refusing to overwrite existing path %s\n' "$OUT" >&2
  exit 1
fi

cd "$ROOT"

# Git exports repository-local variables to hooks. Clear them before operating
# on the isolated bare repository so a pre-push export cannot resolve refs in
# the source checkout instead.
if ! GIT_LOCAL_ENV="$(git rev-parse --local-env-vars)"; then
  printf 'FAIL: could not discover repository-local Git environment variables\n' >&2
  exit 1
fi
while IFS= read -r variable; do
  [[ -n "$variable" ]] && unset "$variable"
done <<<"$GIT_LOCAL_ENV"
unset GIT_LOCAL_ENV

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  printf 'FAIL: refusing to export a dirty working tree\n' >&2
  git status --short >&2
  exit 1
fi
if [[ "$(git rev-parse --is-shallow-repository)" == "true" ]]; then
  printf 'FAIL: refusing to export an incomplete shallow repository\n' >&2
  exit 1
fi

HEAD_SHA="$(git rev-parse HEAD)"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/airlock-review.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
PAYLOAD="$STAGE/airlock-review"
mkdir -p "$PAYLOAD"

if command -v sha256sum >/dev/null 2>&1; then
  SHA256=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SHA256=(shasum -a 256)
else
  printf 'FAIL: need sha256sum or shasum for SHA-256 verification\n' >&2
  exit 1
fi

# Parallel delta selection can choose a different valid pack for identical
# objects. One pack thread keeps repeated exports byte-identical. A bundle
# requires a named ref, so construct one in an isolated bare repository rather
# than resolving mutable HEAD again after capturing HEAD_SHA.
BUNDLE_REPO="$STAGE/bundle-repository.git"
git init --quiet --bare "$BUNDLE_REPO"
SOURCE_OBJECTS="$(git rev-parse --git-path objects)"
SOURCE_OBJECTS="$(cd "$SOURCE_OBJECTS" && pwd -P)"
printf '%s\n' "$SOURCE_OBJECTS" >"$BUNDLE_REPO/objects/info/alternates"
git -C "$BUNDLE_REPO" update-ref refs/heads/review "$HEAD_SHA"
git -C "$BUNDLE_REPO" symbolic-ref HEAD refs/heads/review
git -C "$BUNDLE_REPO" -c pack.threads=1 bundle create \
  "$PAYLOAD/airlock.bundle" HEAD refs/heads/review >/dev/null
printf '%s\n' "$HEAD_SHA" >"$PAYLOAD/SOURCE_COMMIT.txt"
chmod 0644 "$PAYLOAD/airlock.bundle" "$PAYLOAD/SOURCE_COMMIT.txt"

cat >"$PAYLOAD/VERIFY.sh" <<'VERIFY'
#!/usr/bin/env bash
# Verify this archive against the commit it claims to be, then reconstruct it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${1:-$HERE/review-worktree}"
CALLER_ROOT="$PWD"
case "$WORK" in
  /*) ;;
  *) WORK="$CALLER_ROOT/$WORK" ;;
esac
WORK_PARENT="$(dirname "$WORK")"
WORK_NAME="$(basename "$WORK")"
if [[ ! -d "$WORK_PARENT" ]]; then
  printf 'FAIL: worktree parent does not exist: %s\n' "$WORK_PARENT" >&2
  exit 1
fi
WORK_PARENT="$(cd "$WORK_PARENT" && pwd -P)"
WORK="$WORK_PARENT/$WORK_NAME"

if command -v sha256sum >/dev/null 2>&1; then
  SHA256=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SHA256=(shasum -a 256)
else
  printf 'FAIL: need sha256sum or shasum for SHA-256 verification\n' >&2
  exit 1
fi

cd "$HERE"
# Every reconstruction input, including this script, is covered by the
# manifest. The manifest itself is checked by the outer archive hash.
if ! "${SHA256[@]}" -c MANIFEST.sha256; then
  printf 'FAIL: payload manifest verification failed\n' >&2
  exit 1
fi

EXPECTED="$(cat SOURCE_COMMIT.txt)"

# `git bundle verify` requires an enclosing repository, which this archive is
# not. Cloning is the stronger check anyway: it fails on a corrupt bundle, and
# the fsck plus HEAD comparison below cover integrity and identity.
if [[ -e "$WORK" || -L "$WORK" ]]; then
  printf 'FAIL: refusing to replace existing path %s\n' "$WORK" >&2
  exit 1
fi
if ! mkdir -m 0700 "$WORK"; then
  printf 'FAIL: refusing to replace path created during verification: %s\n' "$WORK" >&2
  exit 1
fi
WORK_CREATED=1
cleanup_worktree() {
  if [[ "$WORK_CREATED" == "1" && -d "$WORK" && ! -L "$WORK" ]]; then
    rm -rf -- "$WORK"
  fi
}
trap cleanup_worktree EXIT
if ! git clone --quiet airlock.bundle "$WORK"; then
  printf 'FAIL: could not reconstruct the reviewer worktree: %s\n' "$WORK" >&2
  exit 1
fi
ACTUAL="$(git -C "$WORK" rev-parse HEAD)"
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  printf 'FAIL: bundle HEAD %s does not match SOURCE_COMMIT.txt %s\n' "$ACTUAL" "$EXPECTED" >&2
  exit 1
fi
if ! git -C "$WORK" fsck --full --strict >/dev/null; then
  printf 'FAIL: reconstructed worktree failed strict Git integrity checks\n' >&2
  exit 1
fi
WORK_CREATED=0
trap - EXIT

printf 'PASS: reviewer bundle verifies\n'
printf '  commit:   %s\n' "$ACTUAL"
printf '  worktree: %s\n' "$WORK"
printf '\nNext: install the pinned sibling Stwo checkout and run the gate:\n'
printf '  cd %s && scripts/setup-stwo.sh && scripts/verify-local.sh\n' "$WORK"
VERIFY
chmod 0755 "$PAYLOAD/VERIFY.sh"

# The payload has a fixed file set, so manifest construction does not depend on
# whitespace-unsafe path parsing.
(cd "$PAYLOAD" &&
  "${SHA256[@]}" airlock.bundle SOURCE_COMMIT.txt VERIFY.sh >MANIFEST.sha256)
chmod 0644 "$PAYLOAD/MANIFEST.sha256"

# Deterministic archive. Timestamps are normalized by touching the payload rather
# than with `tar --mtime`, which GNU tar and bsdtar spell differently; ownership
# flags are selected per implementation for the same reason.
COMMIT_STAMP="$(TZ=UTC git show -s --format=%cd --date=format:%Y%m%d%H%M.%S "$HEAD_SHA")"
TZ=UTC find "$PAYLOAD" -exec touch -t "$COMMIT_STAMP" {} +

tar_args=(--format=ustar)
if tar --format=ustar --numeric-owner --owner=0 --group=0 \
  -C "$STAGE" -cf "$STAGE/tar-capability-probe.tar" \
  airlock-review/SOURCE_COMMIT.txt 2>/dev/null; then
  tar_args+=(--numeric-owner --owner=0 --group=0)
elif tar --format=ustar --uid 0 --gid 0 --uname "" --gname "" \
  -C "$STAGE" -cf "$STAGE/tar-capability-probe.tar" \
  airlock-review/SOURCE_COMMIT.txt 2>/dev/null; then
  tar_args+=(--uid 0 --gid 0 --uname "" --gname "")
else
  printf 'FAIL: tar must support GNU or bsdtar ownership-normalization flags\n' >&2
  exit 1
fi
rm -f "$STAGE/tar-capability-probe.tar"

# The fixed member list gives the archive a canonical order. `gzip -n` removes
# the output name and current time from the compression header.
archive_members=(
  airlock-review/MANIFEST.sha256
  airlock-review/SOURCE_COMMIT.txt
  airlock-review/VERIFY.sh
  airlock-review/airlock.bundle
)
LC_ALL=C tar "${tar_args[@]}" -C "$STAGE" \
  -cf "$STAGE/airlock-review.tar" "${archive_members[@]}"
if ! (
  OUT_TMP="$(mktemp "$OUT_PARENT/.${OUT_NAME}.tmp.XXXXXX")"
  trap 'rm -f "$OUT_TMP"' EXIT
  gzip -n -c "$STAGE/airlock-review.tar" >"$OUT_TMP"
  chmod 0644 "$OUT_TMP"
  if ! ln "$OUT_TMP" "$OUT"; then
    printf 'FAIL: refusing to replace output path created during export: %s\n' "$OUT" >&2
    exit 1
  fi
); then
  exit 1
fi

printf 'PASS: exported internally verifiable reviewer bundle\n'
printf '  commit:  %s\n' "$HEAD_SHA"
printf '  archive: %s\n' "$OUT"
printf '  sha256:  %s\n' "$("${SHA256[@]}" "$OUT" | cut -d" " -f1)"
printf 'Share the archive SHA-256 through a trusted channel.\n'
