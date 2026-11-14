# @opendatalabs/personal-server-ts-stream-sync

The pure core of whole-file stream sync (design revision 4.1, section 2). Every
host (full server, Lite, and client libraries) builds against this one tested
package.

The package does no I/O. It imports no SDK, no Node built-ins, no browser APIs,
no clock and no randomness. Hosts inject SHA-256, Keccak-256 and the namespace
HMAC, and do every registry, storage and spool call themselves.

This is version 0.0.1 and marked `private`. It is not wired into the release
workflows.

## Contract

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

## API

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

## Vectors

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

## Tests

```sh
nice -n 10 npx vitest run --maxWorkers=4 packages/stream-sync
```
