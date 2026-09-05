# Prebuilt Personal Server image review fixes

## Commits

- `12ede32 chore: safely load prebuilt image metadata`
- `0237180 ci: publish every branch image revision`
- `2662042 chore: ignore downloaded image metadata`
- `ea809d1 chore: retry personal server image pull`
- `46a9d6b docs: clarify image metadata loading`
- `a8bd2eb chore: cover inline update metadata isolation`

## Fixed findings

- `load_images_env` parses only strictly valid `PS_IMAGE` and `PS_IMAGE_REF`
  lines and fills only unset variables (`scripts/tee/common.sh:10`). It never
  evaluates the file, so the file cannot supply `GIT_REF`, `AGENT_IMAGE`, or
  `DIND_IMAGE`.
- Production compose paths load and verify the metadata; inline provision and
  update paths instead default to and validate a local image tag
  (`scripts/tee/provision.sh:79`, `scripts/tee/update.sh:91`).
- Manual Docker workflow dispatch builds GitHub's selected ref without a dead
  input. All configured branch pushes build regardless of changed paths.
- `deploy/dstack/images.env` is ignored.
- Boot validates `PS_IMAGE` and retries its serial pull three times with a
  10-second delay, exiting after the final failure
  (`deploy/dstack/docker-compose.enclave.yml:64`).
- The job summary uses a fenced block, workflow values enter shell steps via
  `env`, tag generation has no empty entry, and the README now describes the
  two-key-only precedence behavior.

## Regression proof

`npm test -- scripts/tee-images-env.test.ts` initially failed both focused
tests: the metadata file executed a `touch` command, and `provision --inline`
rejected the injected digest before reaching the stubbed deploy. After the
fix, three tests pass, including a stubbed `update.sh` default-inline path
(`scripts/tee-images-env.test.ts:34`, `scripts/tee-images-env.test.ts:82`,
`scripts/tee-images-env.test.ts:146`). Neither script has a built-in dry-run
flag; the tests replace external commands and stop before any deployment or
network mutation.

## Gate summary

- `npm ci`: not needed; `node_modules` was present.
- `npm run build`: passed.
- `npm run lint`: passed.
- `npm test`: passed outside the restricted listener sandbox: 145 files and
  1,888 tests passed.
- `bash -n scripts/tee/*.sh`: passed.
- `docker compose -f deploy/dstack/docker-compose.enclave.yml config` with
  dummy digest values: passed.
- `docker compose -f deploy/dstack/docker-compose.enclave.inline.yml config`
  with dummy base-image digests and `PS_IMAGE=personal-server:local`: passed.
- `git diff --check de4d9f6..HEAD`: passed before this result file was added.

## Constraints and verification limits

- No files under `packages/` or inline compose files changed, and the compose
  environment/allowed variables were not expanded.
- No constraint contradiction was found. The review's requirement to build
  every branch commit supersedes the original branch `paths-ignore` request;
  path filtering was removed for the shared push trigger.
- Docker Compose 5.5.1 re-serializes escaped dollars as `$$` in `config`
  output; both files parse successfully, but the output intentionally retains
  the reusable Compose escape.
- The GitHub-hosted publish, registry pull retry against a live registry, and
  real Phala deployment were not executed locally.
