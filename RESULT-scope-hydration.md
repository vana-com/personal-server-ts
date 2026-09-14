# Scope hydration result

No design or code contradiction was found.

## Commits

- `369aeba perf(core): hydrate requested scopes before full sync`
- `7319dfe perf(enclave): gate readiness on requested scope`
- `06dca7e perf(server): hydrate job scopes on read misses`
- `b3358ee test(e2e): cover decoy scope hydration`
- `5a96677 fix(enclave): preserve unscoped probe calls`
- `73efa2d test(server): expect hydrated scopes in sync status`
- `b3d1b44 test(core): keep hydration behind sync gate`

## Gate summary

- `npm ci`: passed; installed 671 packages. The Husky prepare step warned that it could not lock the shared parent worktree Git config in the restricted environment, but installation completed with exit code 0.
- `npm run build`: passed, including all workspace project references and `scripts`.
- `npm run lint`: passed.
- `npm run lint:eslint`: passed (additional repository-required check).
- `npm run format:check`: passed; all matched files use Prettier formatting.
- `npm test`: passed; 144 test files and 1,898 tests.

The final combined gate was run on Node `v24.19.0` with npm `11.17.0`.

## Log lines added

- Personal Server: context `{ scope }`, message `Hydrated requested scope` (one line after each exact scope lookup/download completes).
- Agent: context `{ jobId, stage: "sandbox-acquire", event: "synced", elapsedMs, hydratedScopes }`, message `Sandbox acquisition progress`.

## Verification notes

- `downloadScopes` uses the exact `(ownerAddress, scope)` feed lookup, handles tombstones through local reconciliation and deletion memory, and never reads or writes the incremental cursor.
- Startup hydration remains behind the existing `canSync()` registration gate. With no configured scopes, startup still gates readiness on the full sync predicate.
- `/v1/sync/status` remains additive: `hydratedScopes` is passed through the existing API contract, and disabled sync returns `hydratedScopes: []`. No gateway or SDK contract changed.
- `PS_HYDRATE_SCOPES` is allowlisted as a normal sandbox environment value and is excluded from the secret env file.
- The job worker makes at most one read-path hydration attempt per execution, then re-runs the existing missing-scope, tombstone, result-size, and pinned-version checks.
- `E2E_EXTRA_SCOPES=<n>` adds `e2e.jobs.decoy.1` through `.n` to the same owner grant and seed pass. Existing step 9 remains the cold-job assertion; new step `9s` submits and decrypts a different decoy scope as a warm follow-up.
- `packages/core/src/api/index.ts` already delegates sync status directly to `getSyncStatusContract`, so no extra projection change was needed there.

## Not verified locally

- The live remote `scripts/e2e-job.ts` flow was not run because this worktree does not have a Gateway URL, operator secret, admitted enclave node IDs, or remote storage credentials. The script was covered by the root TypeScript build.
- The CI Node 20 and Node 22 matrix was not run separately; the full local gate passed on Node 24.
- A real Docker/gVisor sandbox was not launched; runtime environment, secret-file, readiness, and logging behavior were exercised by the repository tests.
