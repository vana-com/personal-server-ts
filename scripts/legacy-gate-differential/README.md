# Legacy write shutdown gate: differential harness

Executable evidence that a gate build behaves like its parent while the gate is
off, and that its schema stamp and enrollment interoperate with older runtime
lines. It runs real compiled `createServer`, storage, sync workers and policy
code from each supplied tree, in separate processes.

## Claim, and its boundary

The claim is finite: **for the operations listed below, run in this order with
these inputs, the candidate's observable state equals the baseline's after the
listed normalization and the listed authorized differences.** It is not a proof
of equivalence for every write path or every input, and the normalization
controls prove only the edits they exercise (see "Normalizer controls").
Anything not in the scenario is not covered.

Trees are supplied by the caller. The harness reports each tree's git commit
and a digest of its compiled output, and fails when a source file is newer than
its emitted `.js` (a stale `dist`). That is a heuristic, not proof that the
build matches the commit; use `--baseline-commit` / `--candidate-commit` to
assert the commit, and compare the printed build digests across runs.

## Files

| file                   | role                                                                            |
| ---------------------- | ------------------------------------------------------------------------------- |
| `scenario.mjs`         | one tree, one process: runs the operations, writes `raw-transcript.json`        |
| `normalize.mjs`        | pure raw → normalized transcript, plus mutant/equivalence controls              |
| `compare.mjs`          | runs baseline, candidate, repeat, journal-failure; sanity, controls, comparison |
| `schema-crossline.mjs` | opens roots across runtime lines; real candidate enrollment                     |
| `tree-identity.mjs`    | commit, build digest, staleness of a supplied tree                              |
| `normalize.test.mjs`   | `node --test`: normalizer controls on a synthetic capture                       |

## Commands

```sh
# differential (baseline = pre-gate parent; candidate = gate build)
nice -n10 node scripts/legacy-gate-differential/compare.mjs \
  --baseline <parent tree> --candidate <candidate tree> --work <dir>
# negative control: the reviewed-bad first gate build must differ beyond its stamp
... compare.mjs --baseline <parent> --candidate <original fca tree> --work <dir> --expect-different
# cross-line schema stamps and real enrollment
nice -n10 node scripts/legacy-gate-differential/schema-crossline.mjs \
  --conformance <parent> --convergence <#475 tree> --experimental <first gate tree> \
  --candidate <candidate tree> --work <dir>
# normalizer controls
node --test scripts/legacy-gate-differential/normalize.test.mjs
```

Each tree needs `tsc --build packages/core packages/server`. The scenario takes
about 10 seconds per run (it waits past one-second boundaries on purpose).

## What the scenario exercises

Inbound HTTP and sync, in order, against a fake world whose storage keeps and
serves every ciphertext and whose registry lists every registration:

- JSON, binary and single-chunk writes; a durable owner import; local grant
  signing; the policy route; an outbound sync cycle.
- **Incoming replica**: a remote writer's data point (valid owner, scope,
  version key and commitments) arrives through the download worker, feed and
  storage. Asserted: ingest succeeded with the right data point id, then, after
  the data file and block sidecars are lost, (1) a sync at the same registered
  version leaves them missing (recorded characterization), (2) a re-registration
  at version 2 makes the real replica commit restore the same bytes and the
  same index identity, adopting version 2.
- **Interrupted chunked import**: begin, restart, chunk, chunk replay, restart,
  a finalize that fails in the index transaction (injected, then removed),
  restart, finalize, finalize replay, restart, finalize replay. Asserted: one
  receipt, identical on every replay; one version; one file; nothing left by the
  failed finalize.
- Direct storage append with and without a projector producer; boot recovery of
  a prepared journal row; recovery of a leftover stage.
- **Preservation guards** around the replica repair, the interrupted import and
  boot recovery: every existing `data_files.created_at` and every existing
  receipt file is unchanged afterward. `created_at` is a SQLite wall-clock
  default, so only equality is recorded, never its value.

## Normalization (exactly)

See the header of `normalize.mjs`. In short, only these are normalized:

1. SQLite wall-clock default columns: a value inside this run's real wall-clock
   window becomes `<sqlite-clock:auto>`; explicit timestamps and NULLs stay.
2. Random UUIDs: one global, bijective first-appearance map over the whole
   transcript, applied before file and blob hashes.
3. Header values in `VOLATILE_HEADERS` (`date`, `x-request-id`,
   `x-correlation-id`); presence is still compared.

Not normalized, compared verbatim: all other row values, schema SQL, HTTP
status, body and all other response headers (type, CORS, source, cursor, cache,
auth), gateway call arguments and signatures, queues, config, file contents.
Uploaded ciphertext is never compared (it is random); instead each upload is
decrypted with the tree's own derived scope key and the decrypted envelope
(payload and metadata), the AddData commitments over it, and a fingerprint of
each derived scope key are compared. A same-length wrong plaintext, a changed
`collectedAt`, a commitment that no longer matches, or a different key
derivation therefore differ.

Authorized differences, each checked before removal: schema stamp 16 → 17, the
default-off config key, and empty additive gate tables. Rows in any gate table
are a failure.

## Normalizer controls

`normalize.mjs` exports `MUTANTS` and `EQUIVALENCES`. Mutants edit a RAW
capture the way a regression would (explicit timestamp changed, explicit value
or NULL in a clock-default column changed, same-length payload, metadata,
commitment, key derivation, swapped receipt references, removed or changed
header); the normalized transcript must differ. Equivalences edit only what is
declared volatile (every UUID renamed, wall-clock values shifted within the
window, volatile headers); it must not differ. `normalize.test.mjs` also runs a
copy of the first harness's lossy normalization to show the controls fail it,
and checks that each mutant differs only where it edited.

Limits of these controls: they check the listed edits only. A NULL in a
clock-default column exists only in the synthetic fixture (real tables declare
those columns NOT NULL), so that control is skipped on real captures and run by
`normalize.test.mjs`. Rewrites of an existing default timestamp are caught by
the scenario's preservation guards, not by the normalizer; `compare.mjs` reruns
the candidate with a simulated rewrite (`--self-test`) and requires detection.

## Schema cross-line cases

Two kinds, labelled in the output.

- **migration fixture**: roots written by SQL that imitate the first gate
  build. They test that the candidate migrates such roots and that older lines
  refuse the result. They do not test what the candidate writes.
- **actual enrollment**: the candidate's own code runs real storage
  (`commitVersion`) and the real `policy.stop`, which persists policy,
  transition and retained rows and raises the stamp to 18 itself. Started from a
  never-enrolled 17 root created by the candidate, by the #475 convergence line,
  and from a 16 root created by the conformance line. Asserted: stamp 18,
  stopped epoch 2, every history row retained, the real index and storage refuse
  a later write and a history delete for that scope, a sibling scope still
  writes, the candidate reopens it, and the conformance and convergence lines
  refuse it (convergence leaves the files byte-identical). Controls rerun the
  case with a broken candidate simulated (stamp left at 17; retained rows
  dropped) and require failure.

**Trusted test inputs, not production authority.** `stop` needs a shutdown
qualification port (grant inventory plus global issuance fence) and a native
canonical coverage port. No production implementation exists. The harness
supplies fixed doubles that return complete, well-formed answers. Passing
shows the candidate persists enrollment correctly when such authority exists.
It does not show, and the harness never claims, a real grant inventory, a real
global fence, or a reopen after rollback.
