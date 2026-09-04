# fix(deploy): update.sh review findings — result

## Summary

Updated `scripts/tee/update.sh` to address both pass-2 deployment review findings:

- The update now fetches the selected 40-hex commit directly from `origin` and exits before secret generation or deployment when the commit is unavailable.
- The post-deploy grace loop now keeps polling through curl failures, non-2xx responses, malformed health bodies, and responses from the old node. It proceeds only after health reports the requested new `NODE_ID`, and otherwise fails after the configured attempt limit with agent logs.

## Regression proof

A temporary command-stub harness exercised the public script behavior without contacting Phala:

- Before the fix, a `502 -> old node ID -> new node ID` health sequence failed on the old node ID.
- Before the fix, a ref unavailable from `origin` still reached the mocked `phala deploy` command.
- After the fix, the same health sequence succeeds and the unavailable ref exits before the mocked deploy command.

The temporary harness was removed after the checks and is not part of the commit.

## Validation

- `bash -n scripts/tee/update.sh` — passed.
- `npm run lint` — passed.
- `npm run format:check` — the task-owned files pass, but the repository-wide command reports three pre-existing untracked files outside this change: `HANDOFF-sandbox-env.md`, `HANDOFF-storage.md`, and `HANDOFF-update-script.md`.
- `./node_modules/.bin/prettier --check HANDOFF-update-script-p2-RESULT.md` — passed; Prettier has no parser for shell files, which are covered by `bash -n`.

## Commit

`fix(deploy): verify the update ref on origin and wait for the new node id`

No push, pull request, or autoreview was performed.
