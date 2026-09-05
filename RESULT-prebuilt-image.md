# Prebuilt Personal Server image result

## Commits

- `a2f5fa0 ci: publish digest-pinned branch images`
- `e6c01a4 chore: pre-pull personal server image on boot`
- `dedeb1e chore: verify personal server image provenance`
- `4a4ba56 docs: explain digest-pinned image workflow`

## Gate summary

- `npm ci`: passed; installed 671 packages. Husky printed a non-fatal warning
  because the sandbox could not lock the parent worktree's Git config.
- `npm run build`: passed.
- `npm run lint`: passed.
- `npm test`: passed outside the restricted listener sandbox: 144 files and
  1,885 tests passed. The sandboxed attempt timed out in tests that open local
  listeners.
- `bash -n scripts/tee/*.sh`: passed.
- `docker compose -f deploy/dstack/docker-compose.enclave.yml config` with
  dummy digest-pinned `AGENT_IMAGE`, `DIND_IMAGE`, and `PS_IMAGE` values:
  passed using Docker Compose 5.5.1 exposed through a temporary CLI-plugin
  directory.
- `git diff --check ab07d8c..HEAD`: passed before this result file was added.

## Verification notes

- Docker Compose 5.5.1's `config` output re-serializes the command as
  `docker pull "$$PS_IMAGE"`, rather than displaying it as
  `docker pull "$PS_IMAGE"`. The YAML parses successfully and retains the
  required Compose escape, but the requested single-dollar rendered form could
  not be observed with the installed Compose version.
- No files under `packages/` or inline compose files changed, and no compose
  `allowed_envs`/environment entries were added.
- The GitHub-hosted Docker build and artifact upload were not run locally.
