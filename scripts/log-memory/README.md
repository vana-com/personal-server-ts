# Bounded log storage reproduction

Set `STREAM_SYNC_MEMORY_DIR` to a disk-backed scratch directory. Run the opt-in test file alone with Node 22 and the installed workspace dependencies:

```sh
mkdir -p "$STREAM_SYNC_MEMORY_DIR"
STREAM_SYNC_MEMORY=1 \
  nice -n 19 ionice -c3 npm test -- log-bounded-memory --maxWorkers=4
```

The harness checks available memory before each subprocess (12 GiB minimum), uses file SQLite with an 8 MiB page cache and file temporary storage, and stores blobs on disk. Every GET returns fresh bytes. It removes databases and bundles in `finally` and retains `baseline-receipts.json`. Do not run other memory experiments concurrently. Normal tests skip this file's measurements.

The bundle transforms only test adapters, compaction eligibility, decoded-result observation boundaries, and the return of the retained operation map. It invokes the existing planner, publication cycle, progressive cycle and rebase implementation. No workspace implementation or live storage is involved. Decode probes hold only WeakRefs; GC at commit barriers detects reachable decoded graphs. The planner's returned ciphertext lengths and SQL result/request encoded lengths are structural retention evidence. They are not measurements of future byte leases. Identity encryption excludes real crypto; RSS is sampled externally at 100 ms and at in-process boundaries, and is supporting evidence rather than a portable threshold.

Each receipt includes a resource ledger template: Bdb (database cache allocation), P (cursor page budget), H0 (protocol head bound), R (record budget), C (resident unit target), T (encoded transport frame), Bcrypto (crypto scratch) and simultaneous-copy coefficients bR/bC/bT. Null means unmeasured, never zero. C is a target in this reproduction; accepting existing 16 MiB wire units requires a separate admission bound. P and R are declared fixture budgets, not achieved bounds. A red result must not be presented as a bounded implementation.

The capability contract requires these atomic steps before consumers migrate: append with ordered-offset receipt; immutable seal after length/digest validation; verified input and fold receipt in one commit; sealed output; upload confirmation; registry outcome reconciliation; seed and cursor promotion in one transaction; accepted publication finish; indexed cleanup. Disk-full, admission, corruption and stale-authority failures cannot advance the durable cursor. Process-loss recovery and native/browser adapter conformance belong to subsequent implementation slices.
