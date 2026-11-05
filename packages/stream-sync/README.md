# @opendatalabs/personal-server-ts-stream-sync

An I/O-free core for whole-file stream sync. One logical file per stream per
connection. A device builds its next upload from the latest synced copy,
overlays this run's records by the stream's primary key, and publishes. A
reader reassembles the stream from a head file and verified parts.

The package has no runtime dependencies and no Node-only APIs. Hashing goes
through an injected `Sha256` port (Web Crypto by default). Every surface (Node,
browser, phone JS runtime) can run it. It does no storage, network or registry
calls: hosts supply those through ports.

This is version 0.0.1 and marked `private`. It is not wired into the release
workflows yet.

## API

| Function                                                    | Purpose                                                                                              |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `canonicalJson(value)`                                      | The one serialization behind every byte and hash.                                                    |
| `overlay(base, run, primaryKey, { orderField? })`           | New key added; an existing key is replaced only by a newer record (see "Newer wins"). Sorted by key. |
| `split(records, sha256, partSizeBytes = 4 MiB)`             | Pack stamped records into hashed parts.                                                              |
| `buildHead`, `encodeHead`, `decodeHead`                     | The head object.                                                                                     |
| `assemble(head, fetchPart, sha256)` / `readParts(...)`      | Fail-closed read, whole or part by part.                                                             |
| `planPublish({ latestCopy, baseVersion, run, ... })`        | Pure: parts to upload, the head bytes and the head hash.                                             |
| `onConflict(newLatest, sameRun, context)`                   | Pure: re-plan on the NEW latest copy with the SAME run.                                              |
| `publishStream(ports, args)`                                | The publish state machine. Returns `registered`, `pending` or `stopped`.                             |
| `reconnectStream(ports, context)`                           | Registers an empty live head over a tombstone. Returns `reconnected`, `blocked` or `not-tombstoned`. |
| `filesOfConnection(names, connectionId, naming)`            | Every stream key, head and part of one connection.                                                   |
| `backoffDelayMs(attempt)`                                   | Capped doubling delay a host may use between attempts of a pending run.                              |
| `runConformance(vectorFiles, { sha256 })`                   | Runs the shared vectors.                                                                             |
| `@.../reference-host` (`ReferenceStore`, `ReferenceDevice`) | In-memory host with a controllable registry and a device with a durable-disk model, for tests.       |

A `Run` is `{ records, observedAt }`: the records one collection run produced
and the time the device observed them. A `StampedRecord` is `{ record,
observedAt }`.

## Host contract (read this before writing a host)

1. **Upload every part of a plan, then the head object, then register.** Never
   in another order. A registration that names a head or a part that is not
   stored breaks the guarantee that a registered head always names stored
   parts. The reference host throws `HostContractError` when it sees this.
2. **The head is content-addressed.** The head object is stored under a name
   built from the SHA-256 of its own bytes (`naming.headName(ref, hash)`), like
   a part. No head is ever written under a fixed name, so a writer that loses
   the race cannot damage the head a reader holds. The only mutable thing is
   the registry entry (`naming.streamName(ref)`), which maps the stream to one
   head hash.
3. **Registration is a compare-and-set.** `commitHead` must accept the head
   hash only if the registry version is still `expectedBase` and the
   connection is not tombstoned. Otherwise return `version-moved` or
   `tombstoned`. The registry owns the version increment.
4. **A run stays pending until its head is registered.** `publishStream`
   returns `status: "registered"` only after the compare-and-set succeeded.
   A host must not advance the connector cursor, and must not drop the run's
   records, before that. Until then the run is the only copy of the data. Use
   `outcome.runDisposition`: `complete` (drop the run, advance the cursor),
   `keep-pending` (keep both, try again later) or `discard` (the connection
   was deleted; drop the run, do not advance). Any exception thrown by the
   driver or a port means "not registered": keep the run. `ReferenceDevice`
   implements this rule and has a crash test.
5. **No retry limit drops a run.** After `maxAttempts` (default 5) lost races
   `publishStream` returns `pending` with reason `conflict-retries-exhausted`.
   The host keeps the run and calls again later, spaced by `backoffDelayMs`.
6. **Parts and heads are immutable.** Putting one twice is harmless. Do not
   delete one while any registered head could still list it. Objects no
   registered head lists are orphans (for example after a crash) and harmless.
7. **Never publish from the device's own stale copy after a conflict.**
   `publishStream` does this for you: on `version-moved` it refetches the
   latest head, verifies and reads it, and plans again with the same run.

## Newer wins (overlay)

The overlay never lets an older value replace a newer one. For a key present in
both the base and the run, the run's record replaces the base record when:

1. the stream declares an `orderField` and both records have it with
   comparable values (numbers, or strings compared by code unit): the larger
   value wins, and equal values go to the run; otherwise
2. the run's observation time is greater than or equal to the base record's
   (a tie goes to the run).

The observation time is metadata kept beside the record in the part
(`observedAt` array), never inside the record body, so it does not change what
the connector produced. A missing or incomparable `orderField` falls back to
observation time.

**Clock-skew limit.** Without a declared order field, "newer" means "observed
later by the device's clock". Two devices with clocks that disagree can pick
the wrong winner by the size of the disagreement. Streams whose source carries
a version or modification time should declare it as `orderField`.

## Reconnect and delete

- A delete writes a tombstone at the registry. Publishing over a tombstone is
  always refused (`tombstoned`); the driver then returns `stopped` and the run
  is discarded.
- **Reconnect registers an empty live head over the tombstone** with intent
  `reconnect` and an expected base equal to the tombstone's version. A device
  that stopped at the tombstone resumes when it next sees a live head (the
  reference device clears its cursor and its stopped flag then, and
  re-collects). A device that never saw the tombstone and publishes after the
  reconnect rebases onto the empty live head, so its run is registered, not
  dropped. Two simultaneous reconnects: one wins, the other sees
  `not-tombstoned`.
- **Part names must not be reused across a delete, or cleanup could remove
  live parts.** Parts are named by content, so the same rows after a reconnect
  give the same part names. The chosen rule is **block reconnect until the
  delete's blob cleanup is final**: `reconnectStream` returns
  `{ status: "blocked", reason: "cleanup-pending" }` while the host reports
  queued cleanup (the host's `commitHead` returns `cleanup-pending`). After
  cleanup is final no stale queued deletion can match a new part. A
  per-connection salt in the part hash input would instead allow an immediate
  reconnect, at the cost of defeating part dedup across a reconnect and
  changing every hash; that was not chosen. If the namespace work wants an
  immediate reconnect, swap to a salt: it changes `split` and the vectors, not
  the publish state machine.

## Format and design choices

- **Part**: canonical JSON `{"observedAt":[t1,t2,...],"records":[r1,r2,...]}`,
  UTF-8, records in key order, `observedAt[i]` for `records[i]`. Part size
  counts bytes of this exact text (the times count), so a part exactly at the
  limit is allowed. A record too large for any part gets a part of its own and
  an `oversized-record` warning (the publish still proceeds). No records means
  no parts (a head with an empty `parts` list), not an empty part.
- **Hash**: lowercase hex SHA-256 of the exact part or head bytes, no algorithm
  prefix. The head's `format` field covers any later change.
- **Head** (canonical JSON, fields exactly):
  `baseVersion` (string or `null`), `connectionId`, `format` (1), `parts`
  (ordered `{bytes, hash}`), `recordCount`, `stream`. An unknown `format`
  greater than 1 fails with `unsupported-format-version`; any other deviation
  (extra field, bad hash, wrong type) fails with `malformed-head`. Strictness is
  deliberate: unknown shapes fail closed. A head whose bytes do not hash to the
  name the registry holds fails with `part-integrity` (reason `hash`).
- **Versions** are opaque strings to the core. The core stores and compares
  them and never increments one. The registry owns the arithmetic.
- **Key**: the tuple of the primary-key field values, compared as canonical JSON
  of the tuple. `1` and `"1"` differ, `0` and `-0` are equal. A `null` value
  counts as present; an absent field (or `undefined`) is missing. Only own
  properties count, so `constructor` and `__proto__` are ordinary fields and
  never touch a prototype.
- **Order**: records sort by canonical key string in UTF-16 code unit order.
  That is deterministic, not numeric: id `10` sorts before id `2` and before id
  `1` (the closing `]` sorts after digits). Every surface must use the same
  rule, which the vectors pin.
- **Duplicates** inside the base or inside a run follow the same newer-wins
  rule. A record missing a key field fails the overlay (`missing-key-field`,
  with `source` `base` or `run`) even when the bad record is in the base, so a
  corrupt base is loud rather than silently repaired.
- **Canonical JSON** accepts only the JSON data model. `undefined`, `NaN`,
  `Infinity`, `bigint`, `Date`, class instances and cycles throw
  `non-canonical-value`. Numbers print as ECMAScript prints them (`1e21` is
  `1e+21`), keys sort by code unit, strings use JSON escaping and are not
  Unicode-normalized.
- **No no-op detection**: a run that changes nothing still produces a new head.
  A host that wants to skip that compares `plan.head.parts` with the current
  head. Skipping re-upload of parts that are already stored is likewise a host
  option, not a core concern.
- **A corrupt latest copy aborts the publish** with `part-integrity`. The core
  never uses an unverified copy as a base. The run stays pending (any thrown
  error means "not registered").
- **Names** are an input. The placeholder grammar in `naming.ts` is
  `pdpp.<connection>.<stream>` for the registry key, `<key>.head-<hash>` for
  heads and `<key>.part-<hash>` for parts, with dot-free segments. Everything
  that needs a name takes a `StorageNaming`. The connection id is opaque. The
  deletion helper uses the parser, never "the text before the first dot".

## Conformance vectors

`vectors/*.json` hold inputs and expected outputs: exact canonical text, byte
counts, SHA-256 hashes, heads and typed errors. Other surfaces load these files
and call `runConformance(files, { sha256 })`; the runner does no I/O. The file
shapes are documented at the top of `src/conformance.ts`. Expected texts are
written by hand, and hashes come from `node:crypto`, not from this package.

Run the package tests from the repository root:

```sh
nice -n 10 npx vitest run --maxWorkers=4 packages/stream-sync
```
