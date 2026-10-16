# Durable additions producer

Personal Server producer for BUI-904/VANA-12, based on `main@76c3a2f72a809d26169d675199dcfac9fdae4dcc`. Gateway draft #168 is pinned at `228bbf1cd6893a5b34da248832d8861f245d6d3d`. Both PRs remain unpublished, draft and unmerged. Desktop/Web rendered acceptance belongs to the later consumer issues.

## Storage and authority

`createDurableAdditions` receives one fixed owner, network, master key, inventory client, encrypted storage adapter and AddData signer. Network identities include chain ID and Gateway origin. Encrypted documents repeat owner, network and exact source; mismatches cannot contribute counts. Storage URLs include chain and owner. Envelope plaintext and encrypted-size metadata must match both inventory hashes before folding. Original source envelopes are unchanged.

Ordinary ledger names are `vana.system.additions.<source>`. When that name exceeds 256 UTF-8 bytes, the selected mapping is `vana.system.additions-hash.<keccak256(exact source)>`. The exact source remains inside the validated encrypted document. The separate namespace cannot collide with a literal source suffix. This fallback is coordinator-approved; it is no longer a pending format decision.

Inventory remains owner-wallet only. Every request includes a fresh signed nonce because Gateway consumes read proofs once. No server key is silently promoted to owner authority. `CreateServerOptions.additionsWriter` accepts an already-authorized storage/AddData/Gateway capability for TEE checkpoints. TEE additions remain unavailable without both owner inventory signing and that injected writer. The ordinary enclave public-read adapter still cannot upload. This injection creates no credential, registration, grant or egress permission.

## Recovery

1. Discover source scopes, including deleted rows, and exclude literal `vana.system.`.
2. Read numeric-string version pages with both hashes, lifecycle status and tombstones.
3. Start after the last settled tombstone. Reimport baseline identities have unknown arrival dates and are not new arrivals.
4. Validate the entire stored checkpoint prefix against current commitments. Same-version replacement invalidates the prefix.
5. Fold readable envelopes in numeric order using only `collectedAt`. Retain exact permanent identity/timestamp evidence. Missing evidence, failed/unknown slots and tentative pending slots prevent complete coverage.
6. Re-read the inventory and source listing before certifying. Pages are separate snapshots, not owner-wide atomic finality.
7. Publish encrypted checkpoints and a changed portable summary. Re-read registration and blob commitments after publication. System writes never recursively fold.

Cross-device correctness does not depend on process-local locks or CAS registration. A later reader repairs lost or lower-prefix checkpoints. If source blobs are missing during required replay, history remains partial. An inaccessible checkpoint is never overwritten with a failed rebuild. Full runtime has no 200-version/256-MiB backfill cap. Inventory pages are still accumulated, with a configurable page limit, so full-runtime memory includes the version inventory and one scope ledger.

## Summary contract

The version-1 payload retains local route fields and adds coverage, through markers, recent `buckets`, `fineSince`, and older `daily` UTC counts, globally and per source. Ten complete UTC days plus today retain quarter-hours. This covers the current seven-local-day chart at UTC-12 through UTC+14, DST transitions and current fractional-hour zones. Counts older than `fineSince` compact into UTC days without deleting permanent ledger evidence.

Full-runtime requested local days are rebuilt directly from exact ledger timestamps, including older intervals. `projectPortableAdditionsByLocalDay` returns `partial` with `days: null` when an older non-UTC interval cannot be reconstructed from the portable document. UTC intervals can use older daily counts exactly. Consumers must not feed compacted UTC days into the quarter-hour-only helper and invent local boundaries.

`readAdditionsSummaryJson` enforces an 8-MiB UTF-8 document limit; bounded HTTP readers must enforce the limit before materializing JSON. The producer refuses to publish an oversized portable summary and returns behind instead. This is a transport limit, not a claim that arbitrarily many sources or years always fit in one browser document. Ordinary route summaries can still reconstruct older requested days from exact ledgers.

Source deletion uses the existing durable deletion pipeline for its checkpoint and summary invalidation. Subsequent recovery reads current source tombstones. Captured prior ciphertext remains owner-decryptable, as with ordinary source data deletion.

## Budgeted hosts

One `AdditionsBudget` covers inventory bodies, ciphertext, contiguous copies, decoded plaintext, parse input work, checkpoint verification and derived summary work across scopes. Exhaustion is sticky. Monotonic deadline checks catch CPU work that runs past an undelivered timer callback. Real fetch/stream cancellation is awaited; no timeout race abandons an SDK operation.

Vana's signed adapter exposes `downloadBounded`, using the already-public canonical blob GET with namespace validation and redirect rejection. It checks advertised length and actual stream chunks, including missing/false lengths and HTTP decompression expansion. Inventory readers bound JSON before parsing and share the accumulator's budget. They require a cancellation-aware signing capability rather than letting wallet prompts outlive the deadline.

The SDK crypto and checkpoint APIs still do not expose cancellation or a preallocation plaintext/decompression ceiling. Therefore the installed Lite path returns **unavailable** before starting recovery when bounded crypto/publication capability is absent. It no longer claims behind progress after whole-object SDK work or runs checkpoint publication under a fresh unlimited budget. A host may inject `boundedWork` only if it cancels and settles crypto/publication and enforces the plaintext limit. Returned checkpoint proofs are revalidated by the coordinator under the same budget. No production bounded-work implementation is supplied in this PR; incremental Lite progress and checkpoint resume acceptance remain **unproved**. This safe unavailable state is an explicit remaining gate, not completion of browser catch-up.

## Reproducible evidence

With dependencies installed in both isolated checkouts:

```sh
npm test -- packages/core/src/additions packages/core/src/storage/adapters/vana-bounded.test.ts packages/core/src/signing
node --import tsx scripts/verify-additions-gateway.mjs ../data-gateway
node --import tsx scripts/verify-additions-gateway.mjs ../data-gateway --large
npm run validate
npm run build
```

The runner refuses any Gateway revision other than the pinned commit. It owns a disposable PostgreSQL cluster and loopback HTTP/blob service, uses a throwaway owner key, real Gateway inventory/listing handlers, replay fencing, real encryption and exact commitments. It checks numeric paging, invalid proof denial, authoritative revalidation and restart after original blob pruning. Registrations are explicitly SQL-seeded confirmed fixtures; checkpoint registration is a fixture port. This does not prove POST AddData authorization, chain settlement, production Storage, browser worker or native behavior.

Observed full-runtime runs: 102 versions passed the paging proof. The large run replayed 90 versions / **377,509,603 ciphertext bytes**, returned complete/total 2, and recovered identical counts after original pruning. Peak process RSS was **487,292,928 bytes**, including fixture generation and imported Gateway code. This is measured evidence, not a constant-memory guarantee for unbounded identities or versions.

## Remaining acceptance gates

- Registered-server INVENTORY authorization remains pending Callum's confirmation. No Gateway permission change is included. An existing owner signing capability remains the supported alternative.
- TEE needs an actual authorized owner inventory signer and host-injected writable checkpoint capability. The injection is prepared; no authority was manufactured.
- Lite needs concrete cancellation-aware bounded signing, crypto and checkpoint adapters with real worker/transport proof, plus resumable interrupted checkpoints. Missing capability returns unavailable. The hard 8-MiB/ten-second incremental catch-up gate is not accepted.
- Browser/native cross-surface rendered equality is later consumer work. No production data, publishing, deployment or shared-branch writes were used.
