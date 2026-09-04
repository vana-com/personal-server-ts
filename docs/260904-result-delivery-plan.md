# Result delivery: single object-storage path

Date: 2026-09-04
Status: plan, not started
Supersedes the inline-result arm in `260901-personal-server-gateway-enclave-architecture.md`.

## Why

The enclave job path caps a result at `MAX_INLINE_RESULT_BYTES` = 1 MiB. The pre-enclave direct read
(`readPersonalServerData` → `GET /v1/data/{scope}` on the per-user PS URL → `new Response(decoded.bytes)`)
had no ceiling at all, so this is a regression, not a carried-over bound. Observed 2026-09-04: Lorebook's
`chatgpt.conversations` chapter fails with job `state: failed`, surfaced to the user as "That page stayed
blank."

Raising the constant does not fix it. Vercel caps a function **request or response** body at 4.5 MB, and
that cap applies to both legs: the runtime's `POST /v1/jobs/:id/complete` and the builder's
`GET /v1/jobs/:id`. Real inline ceiling after base64 is about 3.2 MB. Target is 20-50 MB.

## Shape

One path. Every result, any size, goes to object storage. No inline column.

```
enclave ──PUT──> vana-storage (jobresults/)  <──GET── builder
   │                                                     ▲
   └──── complete: handle metadata only ──> Gateway ──────┘
                                            (never sees bytes)
```

- Objects are ECIES-sealed to the builder key, so reads are public exactly like every other blob
  (`vana-storage/src/middleware/auth.ts:147-165`). No bucket auth, no presigning, no new credentials.
- Writes reuse the delegated-server check that already exists
  (`vana-storage/src/auth/gateway-client.ts:27`): the enclave is a registered server for the owner.
- An R2 lifecycle rule on the prefix reaps objects. No purge cron.

## The prefix

**`jobresults/{chainId}/{jobId}`** — top level in the existing bucket, not nested under an owner.

This is deliberate and non-obvious. `toR2Key` (`vana-storage/src/blobs/url-parser.ts:84-87`) builds
`chains/{chainId}/{owner}/{scope}/{collectedAt}`, so owner precedes scope. R2 lifecycle rules filter on a
**leading** key prefix, so a per-owner subfolder like `{owner}/cache/` can never be targeted by one rule.
A top-level prefix can.

Consequences, all good:

- Outside every owner-delete prefix (`toR2Prefix` returns `chains/{chainId}/{owner}/`), so a scope or
  owner delete cannot wipe pending results.
- Excluded from per-owner usage metering, so builder artifacts do not bill against the owner.
- `{jobId}` is a uuid, so keys are unguessable. Enumeration is already impossible: a public GET is
  rejected unless the path resolves to a full blob triple (`vana-storage/src/blobs/routes.ts:162-176`).
- No owner address in the URL the builder holds.

**TTL.** R2 lifecycle granularity is whole days; one day is the floor. So: logical expiry enforced at the
Gateway (stops serving the handle) plus a one-day lifecycle rule as the physical backstop. A builder who
already holds a URL keeps it until the rule fires, which is harmless because only that builder can decrypt.

## Work, by repo

### vana-storage (new)

1. `src/job-results/routes.ts`: `PUT /v1/job-results/{chainId}/{owner}/{jobId}`,
   `GET|HEAD /v1/job-results/{chainId}/{jobId}`. Key builder emits `jobresults/{chainId}/{jobId}`.
   Owner is in the PUT path for authorization only and never enters the key.
2. `src/index.ts`: mount under the same auth middleware. Extend the GET/HEAD public short-circuit to
   cover this resource; PUT falls through to the existing Web3Signed delegated-server branch.
3. Skip the usage tracker for this prefix. Reuse `MAX_BLOB_SIZE` (100 MB) unchanged.
4. **Human action:** add the R2 lifecycle rule on prefix `jobresults/`, 1 day, on `vana-storage-dev`
   first, then `vana-storage`. Lifecycle rules are bucket config, not `wrangler.toml`.

### personal-server-ts (#245)

5. `packages/server/src/jobs/worker.ts:237-241`: delete the `MAX_INLINE_RESULT_BYTES` check and the
   `RESULT_TOO_LARGE` throw. PUT the sealed bytes to storage, then return handle metadata
   (`objectKey`, `hash`, `size`).
6. Write **raw bytes**, not base64. Base64 existed only for JSON transport, so this is a free 33% cut in
   both bytes stored and memory held.
7. Order is write-object, then complete. A failed completion leaves an orphan the lifecycle reaps. A
   missing result becomes impossible.

### data-gateway (#100)

8. `api/v1/jobs/[id]/complete.ts`: delete the `RESULT_HANDLE_UNSUPPORTED` rejection (`:48`) and the 413
   inline check (`:60`). Require handle fields; stop accepting `resultCiphertext`.
9. `lib/jobs/http.ts:123-127`: stop returning `resultCiphertext`; return the handle plus the storage URL
   the builder should fetch. Needs `STORAGE_API_URL` in gateway config.
10. `lib/jobs/repository.ts:351`: the expired-inline-nulling becomes handle logical expiry.

### vana-sdk

11. `protocol/jobs.ts:40`: remove `MAX_INLINE_RESULT_BYTES`. Remove `resultCiphertext` from
    `CompleteRequest` and `JobStatus`; make the handle required on a completed job.
12. `openResult`: fetch the object from the handle URL, verify the hash, decrypt. Same public API, so
    builders see no change beyond the version bump.
13. `jobs-client.ts:788-807` `readRaw`: check `job.state` and surface `failureReason`. Today any terminal
    job goes straight to `openResult`, which is why a size failure reached Lorebook as a generic message
    about a missing inline result. **Fix this first** — it is independent and it makes every later failure
    legible.
14. Removing protocol fields is semver-major. Do it now: the fields shipped in 3.23.0 but nothing is in
    production, so today it is free and after the first builder depends on it, it is a deprecation cycle.

### lorebook (#1)

15. Follow the handle. Mostly free once the SDK hides it.
16. `src/components/LorebookApp.tsx:406`: a failed job renders as "That page stayed blank. No new data was
    added to Lorebook." Surface the real failure.
17. `src/components/LorebookApp.tsx:389` → `connect-flow.ts:405-433`: "Try that again" calls
    `transports.createRequest()` unconditionally, minting a new data-connection request and a fresh
    approval prompt every time. Retry the read against the existing grant instead.

## Database migrations

Current `0054_jobs.sql` creates `jobs` with `result_ciphertext`, `result_hash`, `result_size`,
`result_expires_at`, `result_handle_id` plus a `result_handles` table.

**Amend `0054` in place rather than adding a `0056`.** #100 has not merged and nothing is in production,
so this is the last moment to avoid shipping a column that is dropped immediately after. The enclave stack
needs re-validation for result delivery regardless, so the re-validation cost is already sunk.

Changes:

1. Drop `jobs.result_ciphertext`. Nothing writes it any more.
2. Fold `result_handles` into `jobs`: `result_object_key text`, and keep the existing
   `result_hash`, `result_size`, `result_expires_at`. Drop the `result_handles` table and
   `jobs.result_handle_id`. The relation is 1:1 with a job and always was; a separate table buys a join
   and a foreign key for nothing. `bucket` is config, not per-row data.
3. Keep `0055` untouched.

Cost: the spike Neon branches already ran the old `0054`. They are preview branches; recreate them rather
than hand-patching. Never mainnet.

Alternative if you would rather not disturb a reviewed migration: add `0056` doing the same drops. Costs a
dead column in one released migration and a second file. Not recommended.

## How to test end to end

Fixtures needed: one small scope (Spotify profile, a few hundred bytes), one mid scope (~5 MB, above the
old Vercel inline wall), one large scope (~50 MB, the target).

**Level A, local, fake dstack.** Extend the existing `scripts/e2e-identity-local.sh` harness.

1. Seed all three scopes for a test owner through the ingest path.
2. Run a builder raw read per scope through the job path.
3. Assert per read: object exists at `jobresults/{chainId}/{jobId}`; job row carries the handle and **no**
   ciphertext column; builder fetch returns the object; hash matches; decrypted bytes are byte-for-byte
   equal to the source.
4. Assert the object is publicly GETtable with no Authorization header, and that a GET on
   `jobresults/{chainId}` alone is rejected rather than listing.
5. Assert logical expiry: after the Gateway TTL the job status stops serving the handle even though the
   object still exists.
6. Assert the orphan case: kill the worker between the PUT and the complete, confirm the job fails rather
   than completing with a missing object, and confirm the orphan is inert.

**Level B, Phala CVM.** Reuse the spike fleet scripts (`b6-level-b.sh`, `b6-recovery.sh` shapes).

7. Same three scopes on a real CVM. Record submit-to-first-byte and total, warm and cold, for each size.
   The 50 MB number is the one that matters: hydration alone was 65 s p95 for a 50 MB owner.
8. **Watch sandbox memory.** 256 MiB tmpfs, ~136 MiB active per sandbox. Sealing 50 MB in one buffer may
   not fit. If it does not, hybrid stream encryption (ECIES-wrap a content key, AES-GCM the stream) becomes
   part of this work rather than a follow-up. Measure before deciding; do not assume either way.
9. Crash-lever recovery, as already proven for the inline path.

**Acceptance test, the real one.** Kahtaf's own ChatGPT conversations through Lorebook's deep-cut chapter
on the hosted previews, signed out, cold, from Lorebook first. A portrait renders. That is the exact flow
that fails today.

## Order

Do 13 first on its own; it is independent and it makes everything after it debuggable. Then vana-storage
(1-4), then the SDK protocol change (11-12, 14), then gateway (8-10) and worker (5-7) together since they
share the wire contract, then lorebook (15-17). Migrations land with the gateway change.
