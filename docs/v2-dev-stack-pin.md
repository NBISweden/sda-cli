# SDA v2 dev-stack pin

Integration tests for `--api-version v2` boot the SDA v2 dev stack from
`neicnordic/sensitive-data-archive` at the commit below. Bump when the v2
server contract changes or when features we depend on land in main.

**Current pin:** `608878fa453770fcb3962bf0239366905c125982`
**Updated:** 2026-04-22
**Why this commit:** Latest `origin/main` commit that directly touched
`dev-tools/download-v2-dev/` — specifically, the final round of Copilot
review fixes on the dev-compose that was introduced in
neicnordic/sensitive-data-archive#2368
(`feat(download): add lightweight dev compose for v2 API`). Pinning here
gives us the dev stack in its reviewed-and-stabilized shape; later
`origin/main` commits change unrelated areas (e.g. readiness probes,
s3inbox) that could shift CI behavior without touching the file we depend
on.

## Bumping

1. Read the diff: `git log <old>..<new> -- sda/cmd/download/ dev-tools/download-v2-dev/`
2. Run the pinned commit locally: `git checkout <new> && make dev-download-v2-up && go test -tags integration ./...`
3. If tests pass, update `.github/workflows/integration-v2.yml` and this file in the same commit.
