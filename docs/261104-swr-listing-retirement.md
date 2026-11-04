# Retiring the SWR listing bridge

This checklist applies when replacing continuous legacy comparison with the one-time migration gate. The bridge keeps inventory available during re-evaluation; direct reads still validate current data. It is not the migration proof.

The temporary tables are:

- `legacy_scope_revalidation_instances`: mutation revisions, including before the first takeover;
- `legacy_scope_revalidation_scopes`: persisted first-stale timestamps, configured ceiling, confirmed revision and failure diagnostics;
- `legacy_scope_revalidation_policy`: the saved semantic/configuration fingerprint.

Recreating empty tables cannot restore lost first-stale history. Keep that history through the supported downgrade window. A database that reopens successfully is not evidence that an older binary enforces the migration gate or the stale-inventory ceiling.

A tracker boot invalidates every surviving witness and advances its mutation revision, even if the stored policy fingerprint is unchanged. This covers an older process or a PDPP-disabled process writing without the tracker. Existing dirty timestamps are retained. Evaluation Worker connections in the same process do not perform a second boot invalidation.

## Removal checklist

- [ ] Inventory the temporary seams before removal: the SQL mutation proxy and policy/dirty state in `legacy-scope-revalidation-state.ts`; the serialized polling/sweep queue in `legacy-scope-revalidator.ts`; Worker deadline/epoch and comparison lifecycle in `legacy-scope-evaluation.ts`; bootstrap configuration/start/stop; the worker-mode guard in `index.ts`; and authority/view witness admission and dirty clearing. Remove lifecycle, packaging assumptions and tests together.
- [ ] Replace continuous comparison with the one-time migration gate. Its durable proof must bind account, scope, instance/generation, exact legacy head, evidence and comparison version, and commit atomically from a fenced snapshot. Recover interrupted initial proofs with a bounded queue/checkpoint. A prior covered verdict or clean dirty marker is not that proof. After gating, preserve live authorization, selection, tombstones, replica visibility and body correctness without periodic legacy comparisons.
- [ ] Introduce and observe the gate alongside the bridge, compare decisions, and recover unproven identities before switching readers. Document compatible versions and rollback. Quiesce scheduling, await Worker termination, and close older database owners before removing the proxy/lifecycle. Keep all three bridge tables through the supported downgrade window.
- [ ] Prove downgrade safety using an actual supported older binary and a copied migrated database. Either provide a gate-aware compatibility binary that restores conservative dirty markers before reads, or block incompatible downgrades using enforcement the older binary actually honors, or restore a compatible snapshot. `CREATE TABLE IF NOT EXISTS` does not restore lost first-stale history.
- [ ] After that window closes and exclusive ownership/version checks pass, disable startup table creation and transactionally drop only `legacy_scope_revalidation_policy`, `legacy_scope_revalidation_scopes` and `legacy_scope_revalidation_instances`, together with the schema-version update. Make the migration idempotent and crash-safe. Preserve the new gate and existing takeover, verdict and reset tables.
- [ ] Before removal, require real-database tests for proof identity/equality and atomic commit; crash before/during/after proof and migration; restart/recovery; head and generation replacement; concurrent writes, reimport and retry; failed/timed-out initial proof; deletion without resurrection; missing blobs/quarantine; authorization and cache invalidation; list/read consistency after gating; absence of periodic comparisons; mixed-version processes and actual downgrade; and artifact Worker shutdown where still applicable.
