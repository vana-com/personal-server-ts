# Live dev replica journey

Run from this repository on Linux with Node 22 and the existing workspace dependencies. The harness requires `prlimit` and `/proc` to disable core dumps and measure each child process's high-water RSS. Build this checkout's core first so workspace imports use this branch's code.

```sh
mkdir -p "$HOME/.tmp"
export TMPDIR="$HOME/.tmp"
./node_modules/.bin/tsc --build packages/core
./node_modules/.bin/tsx scripts/pdpp-replica-dev-preflight.ts
./node_modules/.bin/vitest run \
  packages/core/src/replication/transport.test.ts \
  packages/core/src/replication/evidence.test.ts \
  packages/server/src/storage/pdpp-replication-transport.test.ts --maxWorkers=1
./node_modules/.bin/tsx scripts/pdpp-replica-live-journey.ts \
  "$HOME/.tmp/replica-journey.json"
```

The separate sender-crash probe is:

```sh
./node_modules/.bin/tsx scripts/pdpp-replica-live-journey.ts \
  "$HOME/.tmp/replica-put-retry.json" --put-retry-only
```

The pending visibility probe is:

```sh
./node_modules/.bin/tsx scripts/pdpp-replica-live-journey.ts \
  "$HOME/.tmp/replica-visibility.json" --visibility-only
```

It measures each receiving reader independently from the source write in both directions. The owner must first read the record with `confirmation: "not yet confirmed"`, while grant reads, canonical rows and received operations still exclude it. The receiver is killed and restarted during that interval; its owner preview must survive without exposing the record to the grant reader. Finalized evidence then allows promotion, after which the grant reader sees exactly one imported operation and the owner marker disappears. The receipt reports `ownerVisibleMs` and `appVisibleMs`; polling adds two seconds plus one worker cycle of observation uncertainty. This probe exercises the Node reader API, not an HTTP token or consent flow.

Both commands create a new random owner in memory. They never load `.env`, personal configuration, wallet files or existing accounts. Owner and server keys travel only through private process IPC. The two worker hosts use independent SQLite databases, distinct registered server signers and one shared owner master key. Connection and declaration authority are provisioned explicitly in each host. They drive the canonical store, receiver and transport directly; they do not start the application bootstrap or prove HTTP/authentication routes.

Network destinations are fixed to dev Gateway `dp-rpc-dev.vana.org`, dev storage `storage-dev.vana.org` and Moksha RPC `rpc.moksha.vana.org`, chain 14800. Other fetch origins and redirects are rejected. Replication is enabled only in these hosts. No Lite host or scheduler is started.

## Acceptance checks

1. A publishes canonical records and referenced binary bytes. B must hold equal records and independently matching SHA-256 blob digests. Repeat from B to A. Importing peer data must not append an echo to the local mutation journal.
2. A writes an incompressible 101 MiB source blob. The worker uses its normal 4 MiB chunk target. Every encrypted fragment must fit the 100 MiB storage cap, and the receiver must reconstruct the source digest. Each child has a 2 GiB V8 heap and a measured 3 GiB RSS budget. Exceeding the RSS budget terminates the run; the report records the observed peak.
3. B pauses its real storage GET after response bytes begin, with at least two fragments of that large batch already durable. The parent sends SIGKILL. A new B process must retain those fragments and avoid downloading them again. A second SIGKILL occurs after `receiver.import` returns inside the worker's outer transaction, before COMMIT. Restart must show that canonical records, received operations and history rolled back. The final import must add exactly one record-history row. A subsequent steady-state cycle must add none.
4. Offline edits on the same key must reach both devices. The winner must equal the maximum persisted `(counter, writerId, operationId)` tuple, with tied counters exercising the writer tie-break. Canonical deletion propagates. Reset must converge the live view and generation, remain empty through additional cycles, then allow a generation-2 record to replicate.
5. Every published/imported scope must retain Active version-one finalized registry evidence, with a block number and hash. The final stores must have no receiver quarantine or inbox errors. The sender-crash probe separately kills A after a successful storage PUT and before registration, then requires two PUT attempts at the same scope with the same ciphertext SHA-256.

Reset here means convergence of the live canonical view and generation. It does not assert erasure of retained operations, transport payloads or historical blob bytes.

## Reading a report

A zero exit and `status: "passed"` are required. The default run has five numbered case receipts; the sender probe has `case: "exact-byte-put-retry"`. The JSON includes the repository head, harness SHA-256, package/script dirty state, process IDs, records, blob digests, wire fragment sizes, publication/import counters, finalized chain evidence and per-process peak RSS in KiB. Timings are milliseconds. A pending Gateway head is not a pass. Each stage waits up to twelve minutes while preserving the worker's durable retry backoff.

The harness removes its databases and generated local blobs on exit. Its report remains at the supplied path with mode 0600. Ciphertext published to dev services remains under the ephemeral owner; deleting the local fixture does not erase remote ciphertext. Keys are discarded, and core dumps are disabled before keys are generated.

## Remaining consent and promotion work

Slice 8b must drive the receiving device through the existing authorization journey: select a connection, fields and time scope; narrow and approve the exact digest; return to the requesting app; read the expected records and blob bytes; deny hidden fields and an independent account; revoke and deny the same token; and reject expired or replayed authorization. Repeat after concurrent edits, deletion/reset, restart and the large fragmented source. Verify the exact Account route in a browser and align resource routing with the existing issuer.

Promotion also requires the Lite publisher host and scheduling, phone/Desktop persistence and a real WebView journey; the supported old/new producer-reader matrix and existing bad legacy heads; device memory/capacity/cost measurements; preparation error classification (`RangeError` currently marks a batch permanent); writer rotation for restored or cloned databases; and a separate decision to enable runtime replication. This two-Node worker journey does not supply those results.

Authority and ordering decisions remain open: accept the provisional Lamport/writer/operation order versus stronger upstream freshness; retain one authority/issuer versus replicate authorization state with revocation and rollback protection; and accept stale/absent legacy reads versus a separate compatibility bridge. This harness keeps the existing ordering and single-issuer defaults.

## Verified dev run — 21 October 2026

[Committed receipts](../docs/261021-pdpp-replica-live-journey.json) bind the full passing run to `da4157e8b94fe6a6eb1331ccb748980e4793c735` and harness SHA-256 `89fcb8175836bf6049f08ef771e3174b970035e397151e7759f8b419c4d33982`. It ran from 02:23:21.596 to 02:52:06.924 UTC on Node 22.23.1. The package/script worktree was clean.

A to B took 183.360 seconds; B to A took 297.339 seconds. The 101 MiB source plus restart journey took 432.586 seconds and used 34 fragments, each at most 5,593,321 encrypted bytes. Source and receiving blob SHA-256 were `155dc724e9656b36db52b92adac2ff83536afcb7c7d7aeb2ca9c8a4404158d74`. The independent five-record comparison also matched timestamps, references and SHA-256.

B retained two fragments across the first SIGKILL without downloading them again. The import-transaction SIGKILL left history at 4 rows; retry added exactly one row, and the next steady-state cycle left it at 5. Concurrent edits had equal Lamport counter 10, both peer operations arrived, and both stores selected the expected writer tie-break winner. Convergence took 240.071 seconds, deletion 197.223 seconds, reset 187.130 seconds and the generation-2 write 173.726 seconds.

A published 39 fragments and B published 4. Each host imported all 43 fragments in 10 batches. Final receiver quarantine and inbox errors were zero. Peak RSS was 1,902,780 KiB on A and 1,874,604 KiB on B, within the 3 GiB budget. A separate sender-crash probe at `f8576b7` passed two PUT attempts at one scope with identical ciphertext SHA-256.

The first large run exposed an allocation failure in `fromBase64`. Its 16 MiB regression aborted under a 192 MiB heap before the fix and passes with direct byte-array filling. Canonical base64 rejection remains covered. Another run correctly failed its crash checkpoint because the SDK had captured fetch before instrumentation; installing the wrapper before adapter construction made the same live case pass. All 42 focused tests, core/server/scripts TypeScript builds, focused ESLint, Prettier, mechanical test-proof checks and Opus review passed.

## Pending visibility draft checkpoint — 21 October 2026

PR #438 adds the pending-read policy. Source commit `602e0b8de8603e6db62c7880be348fd314b167ff` passed 292 focused tests across eight files, core/Lite/server/scripts TypeScript builds, focused ESLint, Prettier and mechanical test-proof checks. The policy truth table pins all 24 reader/state/mode combinations. Four two-connection integration cases verify that changing owner or grant visibility does not relabel or expose another connection's records. The HTTP test checks owner markers and pending binary access, grant record/blob denial before promotion, and grant access after promotion. It also verifies that confirmed blob reads keep the host's byte source.

The intended integration contracts are `ReplicaVisibilityPolicy`, `readStore({reader})`, both route factories' optional `replicaReads` adapter, and the `confirmation: "not yet confirmed"` row field. Low-level `stage`, `promote`, pending `quarantine` and `readVisibleRecords` remain provisional internal hooks. A receiving host must derive reader identity from authentication, never a URL parameter. The worker is inert unless explicitly enabled; production bootstrap remains unwired.

Later the same day the optional `replicaReads` route adapter became the required host capability `createApp({ pdpp: { reads } })`, which also feeds the legacy `/v1/data` view; see `packages/server/src/storage/pdpp-replication-receiver.md`.

Claude Opus 5.5 reviewed the source at high effort in two rounds. Its final verdict is **MERGE-WITH-NITS for the internal draft only; do not enable at runtime**. It independently reproduced the connection-isolation and host-byte-source regressions by removing their fixes. Its design findings map to the leverage rubric as follows:

1. Goal: owners can see pending records with a marker, while the default app view requires finalized evidence.
2. Rules and authority: one core predicate owns visibility and authenticated tokens own reader classification. Node still has a second materializer for preview; this must be unified with canonical reconciliation before enablement.
3. Information flow: pending storage stays outside canonical rows, clocks, journals and history; promotion plus acknowledgement is atomic. Node pending removals still lack a marker. Already-confirmed slot revalidation and canonical retraction belong to the separate consent-acceptance work.
4. Feedback loops: a conflicting optimistic copy can permanently stall its writer's successors. Retained confirmation/import loops remain unbounded and lack waiting/error backoff. These block runtime enablement.

Additional enablement work: compute and persist a sparse preview rather than recomputing complete logs on each read, key provisional content by fingerprint so finalized replacement can recover, give the pending-enabled switch one owner, and measure backlog/native-mobile memory and crash durability. The reviewer measured roughly 4.8 seconds for a 10-row owner page with 3,000 records and one pending operation. This draft does not establish acceptable large-backlog performance.

The short live visibility probe uses receiver reader APIs. The HTTP fixture uses token-scoped routes. Neither substitutes for the consent lane's real AS-issued app-token live journey.

The clean-source live run at `602e0b8` passed in both directions. A→B owner visibility took 16.159 seconds and grant visibility 234.093 seconds; B→A took 7.375 and 144.890 seconds. Each receiving process was killed after pending visibility, restarted with its preview intact, and exposed the new record to grants only after promotion. The app timings include publication, discovery, finalized evidence and scheduling; they are not isolated consensus-finality measurements. Peak host RSS was A 327.4 MiB and B 328.8 MiB for these small records. [Committed receipts](../docs/261021-pdpp-replica-visibility-journey.json) bind the run to the clean source commit, harness hash and finalized evidence. This does not repeat the 101 MiB journey or prove real AS/RS consent.
