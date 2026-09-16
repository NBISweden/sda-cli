# SDA v2 dev-stack pin

Integration tests for `--api-version v2` boot the SDA v2 dev stack from
`neicnordic/sensitive-data-archive` at the commit below. Bump when the v2
server contract changes or when features we depend on land in main.

**Current pin:** `bb2a098fbf466b3346cbfa0e9fee38b9a12f24de`
**Updated:** 2026-09-16
**Why this commit:** Pinned to include upstream fix migrating MinIO container
images to `quay.io/minio/*`, resolving image pull failures during integration
tests.

## Bumping

1. Read the diff: `git log <old>..<new> -- sda/cmd/download/ dev-tools/download-v2-dev/`
2. Run the pinned commit locally: `git checkout <new> && make dev-download-v2-up && go test -tags integration ./...`
3. If tests pass, update `.github/workflows/integration-v2.yml` and this file in the same commit.
