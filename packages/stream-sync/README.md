# @opendatalabs/personal-server-ts-stream-sync

## Current protocol and ownership

Documentation snapshot: Personal Server source tree
`2f3228e6f461d5a1c2e1672d1570c1980bafdd2e`.

This package supplies pure protocol building blocks for connection-log stream
sync. It is not itself the database, transport or publication loop. The host
core stores canonical local records, publishes encrypted operation segments,
and advances the connection's registry log head. Readers follow that head and
apply its segments; it is not a new whole-file head for each stream on every
save. The source entry points are
[`log-publish.ts`](../core/src/localdb/log-publish.ts) and
[`log-apply.ts`](../core/src/localdb/log-apply.ts); the model's
[progressive first-load section](../../docs/formal/log-protocol/README.md#progressive-first-load-shows-only-rows-the-finished-log-keeps-partialviewtla-host-run-2026-11-17)
describes segment references and ordered application.

Publication commits registry rows as a batch, with the connection's active
control generation required for the commit. A connection delete publishes the
control tombstone as its fence; an earlier generation cannot continue to
publish through that fence. See
[`log-publish.ts`](../core/src/localdb/log-publish.ts),
[`delete.ts`](../core/src/localdb/delete.ts), and
[`delete-batch.ts`](../core/src/localdb/delete-batch.ts).
These are runtime contracts, not claims that the formal models prove the
actual gateway's concurrency or authorization behavior. See the
[formal evidence summary](../../docs/formal/log-protocol/README.md#current-evidence-summary-and-open-obligations)
for those boundaries.

The pure package does no I/O: hosts supply cryptographic ports and perform
registry/storage operations. Keep package codecs and reducers separate from
those host orchestration responsibilities. The tables below are retained
historical revision-4.1 documentation, **not a current export inventory or the
connection-log wire specification**. In particular, their per-stream head,
merge, checkpoint and fallback descriptions must not be used as today's
publication contract.

## History: whole-file design revision 4.1

The original README described a private version 0.0.1 whole-file package not
wired into release workflows. That packaging/release statement is historical;
this document does not assert current release wiring. The following contract,
API and vector descriptions record that design and are retained for context.

### Historical contract

| Area          | Rule                                                                                                                                                                                                                                                                                     |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Names         | Stream scope `pdpp.<c>~<ns>.<s>`, control scope `pdpp.<c>~<ns>`. `ns` is 16 lowercase hex, or empty for identity-less connectors. Head blob `h-<keccak hex>`, part blob `g<gen>-p-<sha256 hex>`. Scopes over 256 UTF-8 bytes are a permanent error.                                      |
| Master key    | `streamMasterKeyFromSignature(signature)` returns the 65-byte owner signature as r, low s and v = 27/28. Every stream-sync key (`K_ns`, head and part keys) derives from it, so every encoding of one signature gives one `ns` and `keyCheck`. Legacy scope keys keep the raw signature. |
| Namespace     | `ns = hex(first 8 bytes of HMAC-SHA256(K_ns, canonicalJson([c, accountId])))`, `keyCheck = hex(first 8 bytes of HMAC-SHA256(K_ns, "key-check"))`. The host derives `K_ns` with label `pdpp-stream-sync/namespace/v1` and passes an HMAC port bound to it.                                |
| Control row   | `ACTIVE_DATA = keccak256("pdpp.stream-sync.connection.active.v1:" + keyCheck)`. A read classifies as `absent`, `active(g)`, `deleted(v)` or `foreign` (another key's row).                                                                                                               |
| Lines, parts  | `pkHash = sha256(canonicalJson([pk values]))`. A part is NDJSON lines `{"o":<run start ms>,"r":"<runId>","v":<record>}` sorted by `pkHash`. Format 2 stores each record as a frame (envelope plus body) and has no record size limit; see SPANS.md. Parts ≤ 16 MiB, heads ≤ 1 MiB.       |
| Merge         | Greatest `(o, r)` wins per key; on equal `(o, r)` the later line wins. Feed base lines, then run lines. Seed lines have `o = 0`, `r = "seed"`. The reducer keeps one line per key.                                                                                                       |
| Planner       | 256 spool shards by first `pkHash` byte. Split a bucket over the target by the next bit, never deeper than 16 bits. Deeper than 8 bits, the host makes one counting pass per shard when asked (`needs_counts`).                                                                          |
| Head format 1 | Canonical JSON with `complete`, `connector`, `format`, `generation` (decimal string), `keyCheck`, `ns`, `observedAt`, `parts`, `primaryKey`, `profile {key, version}`, `recordCount`, `stream`. Readers check the hash, format, names and `keyCheck`.                                    |
| Admission     | `decide(S, C)` over the start snapshot `S` and the authoritative read `C`. The target generation depends on `S` only, so one run never publishes at two generations. After a create or reconnect reply the host re-reads and decides with phase `after_write`.                           |
| Checkpoint    | Save `(ns, T)` only when every stream is committed or no-op at `T`, no stream was published `complete:false`, seed receipts are in, and control re-reads `active(T)`.                                                                                                                    |
| `needsFull`   | Publishing `complete:false` sets it and clears the checkpoint; a full run that commits `complete:true` clears it; any entry for a connector forces full runs.                                                                                                                            |
| Eligibility   | One predicate for reads, readiness and totals: a complete live view, else `unavailable` while any connection of the connector is deleted, else a legacy or raw file, else `unavailable`. `isReady` is `eligible(...).kind !== "unavailable"`.                                            |

Open questions and the readings the package takes until they are answered are
in [DESIGN-QUESTIONS.md](DESIGN-QUESTIONS.md).

### Historical API

| Export                                                                      | Purpose                                           |
| --------------------------------------------------------------------------- | ------------------------------------------------- |
| `Sha256`, `Keccak256`, `NamespaceHmac`, `HashPorts`                         | Port types the host implements.                   |
| `canonicalJson`                                                             | The one serialization behind every byte and hash. |
| `streamScope`, `controlScope`, `parseScope`                                 | Build and parse registry scopes.                  |
| `headBlobName`, `partBlobName`, `parseBlobName`                             | Build and parse blob names.                       |
| `deriveNs`, `deriveKeyCheck`, `controlHashes`                               | Namespace, key check and control-row hashes.      |
| `encodeLine`, `decodeLine`, `pkHash`, `shardOf`, `pkHashBits`, `inPrefix`   | Line codec, key hash, shard and prefix helpers.   |
| `compareStamp`, `BucketReducer`, `mergeLines`                               | Merge rule and winner-only reduce.                |
| `encodePart`, `encodeWinners`, `decodePart`                                 | Part codec with fail-closed verification.         |
| `planBuckets`, `basePartsFor`                                               | Bucket planner and base-part routing.             |
| `encodeHead`, `decodeHead`, `digestHead`, `verifyHead`                      | Head format 1.                                    |
| `isHeadLive`, `chooseBase`, `writerCompatibility`, `headComplete`, `isNoop` | Head rules.                                       |
| `classifyControl`, `sameControl`                                            | Control-row states.                               |
| `startState`, `decide`, `targetFor`, `checkpointDecision`                   | Admission, generation and checkpoint rules.       |
| `afterCommit`, `runMustBeFull`                                              | `needsFull` rules.                                |
| `selectConnection`, `eligible`, `isReady`                                   | The eligibility predicate.                        |
| `createOutboxEntry`, `streamRunResult`, `OutboxEntry`                       | Outbox entry type.                                |
| `runVectors`                                                                | Run `vectors/v1.json` against a host's ports.     |

### Historical vectors

`vectors/v1.json` holds byte-exact expected outputs (namespace, scopes, key
hashes, lines, merge, parts, planner, heads) and the expected result of every
rule (every `decide` table cell, traces, checkpoint, `needsFull`,
eligibility). It is plain JSON. A host in another repository can load it and
call `runVectors(vectors, ports)` with its own crypto ports, or read it with
its own runner.

`scripts/generate-vectors.mjs` writes the file. It computes bytes with
`node:crypto` and `@noble/hashes`, independently of the package code, and
holds the rule expectations as hand-written tables. A test fails if the
checked-in file differs from the generator output.

## Package tests

```sh
nice -n 10 npx vitest run --maxWorkers=4 packages/stream-sync
```
