# Scope hydration review fixes result

No contradiction was found between `REVIEW-scope-hydration.md`, the handoff, and the implementation constraints. All four required findings and five recommendations were addressed.

## Commits

- `89945c8 perf(jobs): preserve failures when hydration fails`
- `37812ce perf(sync): degrade scope hydration failures safely`
- `6e3a70a test(enclave): cover scope hydration readiness fallback`
- `60587f1 test(e2e): seed warm hydration scopes after cold job`

## Fix summary

- Job read-path hydration failures now warn and preserve the existing `SCOPE_NOT_FOUND` or `VERSION_MISMATCH` result instead of becoming retryable `INTERNAL` failures. Both paths make at most one attempt.
- Startup hydration failures no longer populate sync status errors or skip the full sync cycle. The requested scope remains unhydrated and readiness falls back to the pre-existing full-sync predicate.
- Exact-scope downloads classify failures and share the manager's retry memory. Non-retryable corrupt or missing blobs are quarantined and skipped; retryable failures still reach the startup/read-path fallback.
- Public `hydrateScopes()` calls now check `canSync()` inside the exclusive mutation queue and make no gateway request when blocked.
- Comments document that `hydratedScopes` means remotely resolved (including absent scopes and tombstones) and that the per-scope loop preserves earlier successes.
- Probe tests cover requested scopes absent from `hydratedScopes` and old Personal Server responses where the additive field is missing.
- The optional e2e decoy flow is silent when `E2E_EXTRA_SCOPES` is unset. When enabled, the cold job completes before decoys are seeded, then step `9s` submits a warm job for a late decoy scope.

## Gate summary

- `npm run build`: passed for all workspaces and `scripts`.
- `npm run lint`: passed (`tsc --build --force`).
- `npm run lint:eslint`: passed.
- `npm run format:check`: passed; all matched files use Prettier formatting.
- `npm test`: passed outside the restricted network sandbox; 144 test files and 1,905 tests passed.

The first sandboxed full-test attempt was stopped after localhost HTTP test suites timed out. The two affected files passed 19/19 in an isolated run with loopback access, followed by the successful full-suite run above.

## Exact log messages added or changed by the fixes

- Personal Server job worker warning: `Job scope hydration failed`, with `{ jobId, scope, error }`.
- Sync manager startup warning: `Scope hydration failed; continuing with full sync`, with `{ error }`.
- Sync manager read-path gate warning: `Scope hydration blocked`, with `{ reason, message }`.

The feature's existing evidence logs remain unchanged:

- Personal Server info: `Hydrated requested scope`, with `{ scope }`.
- Agent info: `Sandbox acquisition progress`, whose synced event includes `hydratedScopes`.

## Not verified locally

- The live `scripts/e2e-job.ts` flow was not run because this worktree does not have the required Gateway/operator/node/storage environment. The script passed the root TypeScript build and formatting checks.
- A real Docker/gVisor sandbox was not launched.
- The CI Node 20 and Node 22 matrix was not run separately.

No sealing/streaming code, Docker flags, compose files, sandbox resource limits, registration-gate contract, gateway/SDK contract, or dependency pin was changed.
