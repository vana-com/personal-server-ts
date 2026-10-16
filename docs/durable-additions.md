# Durable additions producer

This draft implements the Personal Server part of BUI-904/VANA-12 against Gateway draft PR #168, exact head `228bbf1cd6893a5b34da248832d8861f245d6d3d`. It is not a release, deployed service or proof of cross-surface equality. Desktop and Web integrations remain separate work.

## Storage and authority

`createDurableAdditions` receives a fixed owner, network identity, master key, owner-authenticated inventory client, encrypted storage adapter and AddData signer. Runtime network identities include both chain ID and Gateway origin. Each document repeats owner, network and exact source scope; a mismatched document rebuilds rather than contributing counts. No owner key is extracted from a master-key signature, and no registered server is silently treated as the owner.

The storage adapter already namespaces blob URLs by chain and owner. Ledger and summary envelopes use the existing per-scope derived key and OpenPGP encryption. Plaintext and encrypted-size metadata are verified against both inventory hashes before folding. No derived data is stamped into original source envelopes.

Ordinary names use `vana.system.additions.<source>`. If that exceeds Gateway's 256 UTF-8-byte limit, `additionsLedgerScope` uses `vana.system.additions-hash.<keccak256(source)>`, retaining the exact source inside the encrypted document. The separate hash namespace avoids collisions with literal source suffixes. This bounded fallback is a proposed resolution of the accepted literal-name/length conflict; it requires coordinator acceptance before release.

## Recovery

1. Discover source scopes including tombstones. Reserved scopes are omitted before counting.
2. Read numeric-string version pages, including both hashes, status and tombstone markers.
3. Locate the latest settled tombstone and discard prior-incarnation ledger contributions. Reimport baseline identities have unknown arrival dates and are not new arrivals.
4. Load the encrypted derived ledger and compare its entire claimed prefix with the current commitments and lifecycle observations. A changed slot, including same-version replacement, invalidates that prefix and triggers replay.
5. Fold readable source envelopes in numeric version order. Dates come only from envelope `collectedAt`. A missing version/blob, failed or unknown lifecycle remains partial. Pending/submitting content can contribute tentative counts but prevents complete coverage.
6. Repeat the complete inventory observation before certifying coverage. Recheck source discovery after recovery. These are separate Gateway snapshots, not an atomic owner-wide snapshot or chain finality proof.
7. Publish changed encrypted ledger checkpoints and, on reads only, a changed portable UTC summary. Upload hooks can use verified in-memory envelope bytes. Reserved writes never recursively fold.

No numeric cursor alone certifies coverage. Independent writers may lose derived writes because Gateway registration is not CAS. A later reader checks the surviving document's commitments and repairs lower-prefix or replaced-slot state. No process-local lock is relied on for cross-device correctness. If old source blobs are missing during a necessary replay, coverage remains partial; the code does not invent prior content.

The full producer has no 200-version or 256-MiB rebuild cap. The local-only sidecar fallback retains its older bounded rebuild for diagnostics, always marked unavailable for authoritative coverage. Version traversal has a configurable page bound; inventory pages are currently materialized in memory.

## Summary and deletion

The version-1 payload keeps Desktop's existing fields and adds `coverage`, per-source numeric `through`, and UTC 15-minute buckets globally and per source. `partial` means historical dates are unknown, while `coverage` means current recovery is complete, behind, partial, or unavailable. Read consumers must inspect coverage before presenting zero as measured zero. The supported browser-safe summary subpath contains a Zod validator and local-day helper.

Identities and fine buckets are retained permanently. Compacting fine buckets into UTC days would prevent accurate old local days in DST and fractional-hour zones without rereading the ledger. Keeping fine buckets is the proposed minimum retention resolution, with storage proportional to history. Individual snapshots above 200,000 identities remain explicitly incomplete.

Source deletion uses the existing durable delete pipeline to delete its derived ledger and invalidate the summary. Reserved callbacks cannot recursively delete their own derived data. A subsequent reader rebuilds the summary from current source tombstones. Ciphertext captured before deletion remains owner-decryptable, as with existing source deletion.

## Remaining required gates

- The pinned inventory API requires fresh owner wallet signatures. Desktop and TEE normally have derived server keys. Supply an authorized owner request signer or amend Gateway to allow an active registered server for this specific read. The draft exposes `ownerRequestSigner` and returns unavailable without one. TEE's existing public-read adapter also refuses uploads; its durable producer needs an authorized write adapter before it can persist checkpoints.
- Lite supplies a shared 8-MiB read budget and ten-second inventory signal. Ciphertext and plaintext bytes are charged, including derived ledgers. The Storage SDK exposes whole-blob download without abort or streaming limits. Checks between atomic operations cannot guarantee a hard transfer/time bound. Checkpoint writes finish after byte exhaustion so progress can resume. Add bounded/abortable storage reads and bounded inventory parsing before claiming the accepted browser-budget gate passed.
- Owner-wide source discovery uses the public head listing, including tombstones. It cannot enumerate failed slots whose head disappeared. Exact known-scope inventory can still read those slots. No universal historical owner-inventory certificate is claimed.
- Gateway and blob fixtures in Personal Server tests are simulated ports, with real filesystem persistence and encryption. They are not an end-to-end run of the Gateway SQL handler, chain settlement, actual Storage service, browser, Desktop or TEE. The prerequisite Gateway SQL suite has its own retained evidence.
- Large real backfill beyond 256 MiB, native cross-surface equality and production data were not exercised. No release, deployment, merge or shared-branch push is authorized.

These gates keep VANA-12 blocked rather than accepted. The draft preserves supported source work for review and the coordinator's next contract decision.
