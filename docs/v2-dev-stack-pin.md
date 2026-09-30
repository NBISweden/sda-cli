# SDA v2 dev-stack pin

Integration tests for `--api-version v2` boot the SDA v2 dev stack from
`neicnordic/sensitive-data-archive` at the commit below. Bump when the v2
server contract changes or when features we depend on land in main.

**Current pin:** `13022b02beee72108d159345a1bfe2b75e6db8cd`
**Updated:** 2026-09-30
**Why this commit:** Pinned to v4.0.2 of SDA since it now uses Ceph instead of Minio.

## Bumping

1. Read the diff: `git log <old>..<new> -- sda/cmd/download/ dev-tools/download-v2-dev/`
2. Run the pinned commit locally: `git checkout <new> && make dev-download-v2-up && go test -tags integration ./...`
3. If tests pass, update `.github/workflows/integration-v2.yml` and this file in the same commit.
