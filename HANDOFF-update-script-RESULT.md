# In-place fleet update result

## Change

- Added `scripts/tee/update.sh` for updating an existing CVM with a new compose,
  Git ref, Gateway node ID, and freshly generated node secret.
- Added stopped-CVM recovery, refreshed registration metadata, agent identity
  verification across the restart, and secret-safe registration output.
- Documented the compose rollout sequence and Phala operational notes in
  `scripts/tee/README.md`.

## Gate results

- `bash -n scripts/tee/update.sh`: passed.
- `npm run format:check`: passed. The pre-existing untracked
  `HANDOFF-sandbox-env.md`, `HANDOFF-storage.md`, and
  `HANDOFF-update-script.md` were temporarily moved out of the worktree for
  this gate and restored unchanged afterward.
- `npm run lint`: passed (`tsc --noEmit`).

## Commit

`feat(deploy): in-place fleet update script`
