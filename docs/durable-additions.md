# Durable additions producer

Personal Server producer for BUI-904/VANA-12, based on `main@76c3a2f72a809d26169d675199dcfac9fdae4dcc`. Gateway draft #168 is pinned at `228bbf1cd6893a5b34da248832d8861f245d6d3d`. Existing remote PRs stay unchanged and unmerged; this continuation is local only. Desktop/Web rendered acceptance belongs to the later consumer issues.

## Storage and authority

`createDurableAdditions` receives one fixed owner, network, master key, inventory client, encrypted storage adapter and AddData signer. Network identities include chain ID and Gateway origin. Encrypted documents repeat owner, network and exact source; mismatches cannot contribute counts. Storage URLs include chain and owner. Envelope plaintext and encrypted-size metadata must match both inventory hashes before folding. Original source envelopes are unchanged.

Ordinary ledger names are `vana.system.additions.<source>`. When that name exceeds 256 UTF-8 bytes, the selected mapping is `vana.system.additions-hash.<keccak256(exact source)>`. The exact source remains inside the validated encrypted document. The separate namespace cannot collide with a literal source suffix. This fallback is coordinator-approved; it is no longer a pending format decision.

This Lite composition uses existing owner-wallet authority. Every inventory request includes a fresh signed nonce because Gateway consumes read proofs once. The coordinator owns the separately approved inventory-only registered-server exception; it does not confer checkpoint write authority. No server key is silently promoted to owner authority. `CreateServerOptions.additionsWriter` accepts an already-authorized storage/AddData/Gateway capability for TEE checkpoints. TEE additions remain unavailable without both owner inventory signing and that injected writer. The ordinary enclave public-read adapter still cannot upload. This injection creates no credential, registration, grant or egress permission.

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

The Lite sync composition now creates a real dedicated-worker session when `ownerSyncSigner` supplies `signMessageBounded` and `signAddDataBounded`. Those host methods must cancel and settle the actual signing request when their signal aborts. Missing bounded signing remains unavailable; no race against an unresolved wallet prompt is supplied. Worker creation, traversal, OpenPGP decryption, commitment checking, folding, summary construction and checkpoint encryption use the production path. The driver terminates the worker and awaits all aborted host operations before returning. Binary network/publication buffers transfer across the worker channel instead of being cloned. The master key is copied once to the dedicated worker.

The package builds `dist/additions-worker.bundle.js` separately from TypeScript output, so subsequent type checks cannot overwrite the browser artifact with an unbundled module. Bundlers can supply `additionsWorkerFactory` through the browser-runtime or sync options. Upload notifications trigger inventory-backed recovery without cloning upload data/proof into the worker. Explicit durable deletion stays in the ordinary sync pipeline outside the timed recovery session. An owner/network Web Lock covers the complete session and serializes encrypted publication intents across tabs; its wait is included in the ten-second deadline. Hosts without browser Web Locks cannot execute this bounded lane.

OpenPGP is pinned to installed version 6.3.0. A per-call compressed tag-8 packet override throws from packet `read` before decoder execution; no global prototype or configuration is changed. Compressed historical envelopes remain unsupported on this bounded lane and produce incomplete coverage. Full runtime retains SDK compatibility. Uncompressed ciphertext reserves conservative decryption capacity before decrypting; parse and serialization work are charged separately.

Before another source unit starts, recovery reserves 128 KiB plus 128 times the candidate checkpoint serialization and two seconds within the same owner-wide allowance. The attempted unit receives only the remainder, and its actual HTTP/signing operations receive its remaining deadline. A failed unit cannot consume the prefix publication reservation. Candidate admission checks the enlarged checkpoint before advancing its durable prefix. Oversized histories can remain behind; no per-publication budget reset exists.

The host uses canonical abortable Storage PUT and Gateway AddData POST with existing owner signatures, redirect rejection and bounded response parsing. It seals each candidate version, both hashes and encrypted bytes in Lite persistence before signing or PUT. AES-GCM associated data binds owner, chain/Gateway origin and exact system scope. On restart, the worker reconciles real inventory/blob commitments before retrying the same candidate version. An ambiguous receipt never blindly increments the version. The prior checkpoint stays readable until the candidate verifies. Confirmed journal intents clear after verification; durable deletion also clears its scope's intent. Journal operations require `stateStore.bounded`; the default IndexedDB implementation aborts transactions on cancellation, resolves writes only on commit, fails blocked upgrades and aborts/closes late open results. An injected store without that cancellation contract disables bounded recovery.

The version-2 local publication journal stores AES-GCM ciphertext and IV as binary IndexedDB values. Its authenticated plaintext is a four-byte header length, at most 4 KiB of JSON metadata, and the original encrypted checkpoint bytes. This avoids expanding each random byte into a JSON number. Header lengths are checked before decoding. Legacy numeric journals authenticate and atomically migrate to binary before retrying, preserving the exact candidate. Migration can occupy one capped invocation; the committed intent remains available to the next one.

Each locked worker session creates a fresh host transport context. After reading a journal, that context keeps only its authenticated metadata/ciphertext fingerprint. Publication compares against that fingerprint instead of reading and decrypting the same journal again. Fingerprints cannot survive the lock or worker lifetime; transferred buffers are never cached. Network registration and downloaded plaintext commitments still require independent verification. Binary journal reading reserves 24 times its payload size, publication reserves another 32 times checkpoint ciphertext plus header work, and subsequent network/decrypt/parse steps charge the same budget. These conservative charges fit the existing 128-times checkpoint admission reserve for the tested near-limit candidates; neither the aggregate 8 MiB limit nor its deadline changes. Arbitrarily slow network or an inventory that itself exceeds the cap can still return behind.

## Reproducible evidence

With dependencies installed in both isolated checkouts:

```sh
npm test -- packages/core/src/additions packages/core/src/storage/adapters/vana-bounded.test.ts packages/core/src/signing
node --import tsx scripts/verify-additions-gateway.mjs ../data-gateway
node --import tsx scripts/verify-additions-gateway.mjs ../data-gateway --large
node --import tsx scripts/verify-additions-browser.mjs ../data-gateway
node --import tsx scripts/verify-additions-browser.mjs ../data-gateway --journal-regression
npm run validate
npm run build
```

The runner refuses any Gateway revision other than the pinned commit. It owns a disposable PostgreSQL cluster and loopback HTTP/blob service, uses a throwaway owner key, real Gateway inventory/listing handlers, replay fencing, real encryption and exact commitments. It checks numeric paging, invalid proof denial, authoritative revalidation and restart after original blob pruning. Registrations are explicitly SQL-seeded confirmed fixtures; checkpoint registration is a fixture port. This does not prove POST AddData authorization, chain settlement, production Storage, browser worker or native behavior.

Observed full-runtime runs: 102 versions passed the paging proof. The large run replayed 90 versions / **377,509,603 ciphertext bytes**, returned complete/total 2, and recovered identical counts after original pruning. Peak process RSS was **487,292,928 bytes**, including fixture generation and imported Gateway code. This is measured evidence, not a constant-memory guarantee for unbounded identities or versions.

## Runtime proof and remaining authority

The coordinator-owned `scripts/verify-additions-browser.mjs` exercises the production session, transport, worker and IndexedDB against isolated Gateway handlers, real PostgreSQL and encrypted loopback blobs with disposable owner signing. Its final output records the tested dependency head, capped invocation progress, restarts, interrupted publication, cancellation and malicious transport cases. This is local fixture evidence; chain settlement remains simulated and production Storage is not exercised.

The enclave entry point now composes a dedicated host additions broker through `additionsInventorySigner` and `additionsWriter`. The sandbox account stays public-only. The host derives its existing registered epoch account and fixes owner, chain, Gateway/storage origins, checkpoint scope, method and registry domain. It rechecks sandbox placement after asynchronous work and requires fresh registered-server inventory evidence before checkpoint writes. No general signing operation or owner key enters the sandbox. The Gateway dependency must include the inventory-only registered-server exception; earlier owner-only inventory builds fail closed. Local native proof uses fake dstack key derivation and loopback services, not hardware attestation or production Storage. A noncancelable external wallet cannot provide bounded Lite signing. Missing capabilities preserve unavailable behavior. Browser/native consumer rendering belongs to the later consumer issues. No production data, publishing, deployment or shared-branch writes are part of this local delivery.
