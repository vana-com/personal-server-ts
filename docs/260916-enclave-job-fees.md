# Enclave job reads pay the same data-access fee as legacy reads

Kahtaf 2026-09-16: "Legacy and tee should behave the same way in terms of fees."

`data-gateway lib/jobs/admission.ts` hard-codes `price '0' / payer 'builder' / paymentState 'none'`
on every enclave job — "admission does not reserve or settle payment", in its own comment — while a
legacy read is charged the FeeRegistry `data_access` fee (1480: 10000 of `0xF1815bd5…`; 14800 its
own). Step 25 proved the split in production; the 2026-09-08 review (A3) separately flagged that the
builder never signs the price it accepts.

## The rule

**One delivered read to a grantee = one `data_access` fee, from that chain's FeeRegistry, paid by
the grantee, authorized before bytes are released, settled with the access receipt.** Only where the
money artifact is collected differs. Zero fee is honest: a chain whose `data_access` is disabled or
`0` gives `paymentState='free'`, never `'none'` as a placeholder.

| shape                       | money artifact                     | authorized                  | settled              | v1                    |
| --------------------------- | ---------------------------------- | --------------------------- | -------------------- | --------------------- |
| legacy PS Lite read         | x402 → `/v1/escrow/pay`            | `payments` row              | `drainAccessRecords` | charged today         |
| enclave job read (Lorebook) | in the signed `POST /v1/jobs` body | `payments` row at admission | same drain           | **this slice**        |
| enclave MCP read (Claude)   | none — PS serves, posts a record   | none                        | none                 | **zero-rated, below** |

## Flow

```
builder                 gateway                                 node agent / sandbox
  |- GET /v1/jobs/quote ->| getFee('data_access') -> amount, asset, payee
  |<- 200 amount,asset ---|
  |- POST /v1/jobs ------>| admitJob + quote; quote > maxPrice -> 402 PRICE_CHANGED
  |  body adds maxPrice,  | verify GenericPayment sig, payer == builder
  |  priceAsset, payment  | available = finalized - authorized - withdrawing
  |  (the Web3Signed body |   < price                         -> 402 PAYMENT_REQUIRED
  |   hash covers them)   | INSERT payments       <-- this IS the soft lock
  |<- 202 jobId, price ---| jobs.payment_state = 'reserved'
  |                       |<---------------- POST /v1/jobs/{id}/claim ---------|
  |                       |<- complete{ accessRecord{dataPointId, version,     |
  |                       |     accessor, recordId, signature} } --------------|
  |<- GET /v1/jobs/{id} --| signer == owner's registered enclave address;
  |                       | bind payments.access_*; handle released; 'settling'
  |                       | cron -> drainAccessRecords -> recordAccessAndSettle
  |                       |   (UNCHANGED) -> 'settled'
  |                       | fail/expire/sweep: settled_status='voided' +
  |                       |   payment_state='released' -> escrow freed
```

No new settlement machinery. `lockPaymentCapacity` already computes `available = finalizedBalance −
SUM(amount WHERE payment_finalized_at IS NULL AND settled_status <> 'voided') − withdrawing`, so
_writing the row_ is the reservation and `'voided'` already means "never settles, payout never left
escrow, excluded from the authorized sum". `drainAccessRecords` requires `access_signature IS NOT
NULL`, so a reserved-but-unfinished row is skipped with no new guard, and
`findUnsettledPaymentsForGrant` is `op_type='grant'`-scoped and never sees one.

## Changes

**data-gateway** — new `lib/jobs/fees.ts`: quote + payee snapshot from `getFee('data_access')`,
capacity via `lockPaymentCapacity` plus the in-flight `withdrawals` sum, both lifted from
`api/v1/escrow/pay.ts`. `admission.ts`: `Admitted` carries `price, priceAsset, payee, paymentState`.
`api/v1/jobs.ts`: recover the builder's `GENERIC_PAYMENT_TYPES` signature, require it to match the
quote, insert the payment row in the job's transaction (`onConflictDoNothing`, so an idempotent
resubmit mints no second row); new `GET /v1/jobs/quote`. `jobs/[id]/complete.ts`: accept
`accessRecord`, require the signer to be the owner's registered enclave `server_address`, bind
`access_*`. `fail.ts` + `cron/jobs-sweep.ts`: void. `PaymentState` becomes `'free' | 'reserved' |
'settling' | 'settled' | 'released'`. The row: `op_type='job_access'` (new value), `op_id =
keccak256(jobId)` (GenericPayment `opId` is `bytes32`, a job id a UUID), outbox version 1, and
`kind='data_access'` so every index, drain and gauge takes it unchanged.

**402 parity.** `/v1/escrow/pay` has no machine code; its body is `{success:false, error, asset,
amount, finalizedBalance, alreadyAuthorized, withdrawing, available}`. The jobs 402 repeats those
fields and adds `code:"PAYMENT_REQUIRED"` per the jobs endpoints' `errorBody(code, error)`. The SDK
maps it to the **existing** `PaymentRequiredError`, which Lorebook's `mapClientError` checks first —
one sentence for both paths, no Lorebook copy change.

**vana-sdk (semantic-release → 4.2.0)** — `JobSubmission` gains `maxPrice`, `priceAsset`, `payment`.
It is a **Web3Signed body hash, not an EIP-712 struct**, so the existing header signs the new fields
with no typed-data version bump. `jobs-client` gains `quoteJob()`, signs the GenericPayment with the
builder key it holds, and throws `PaymentRequiredError` on 402.

**personal-server-ts** — the sandbox holds no key, so the **node agent** signs the
`RecordDataAccess` EIP-712 (`ownerAddress, scope, version, accessor, recordId`, `dataRegistryDomain`)
with the enclave wallet at completion, exactly as it already signs access records and
`/agent/v1/job-results/sign`, refusing a body that disagrees with what it knows. `CompleteRequest`
extends locally (`packages/enclave/src/jobs/types.ts` already does that for `assignment`) — **no SDK
bump for PS**. Needs a fleet roll. **lorebook** — bump to 4.2.0, pass `maxPrice`; nothing else.

**Migration 0064** (additive, idempotent, hand-written per `db/migrations/README.md`) — `jobs` gains
`price_asset varchar(42)`, `payment_id bigint REFERENCES payments(id)`, `payment_quoted_at
timestamptz`; `price`/`payer`/`payment_state` exist and are reused. `prd_moksha` first, then mainnet,
the way steps 15/16 deployed.

## MCP reads — zero-rated in v1 (Kahtaf, 2026-09-16)

An MCP `read_scope` creates **no job**: the prewarmed PS serves it and POSTs a signed access record
(step 10). Its grantee is a DCR-minted OAuth client (`0x7ffcd45c…`) with no escrow deposit and no way
to fund one at consent time, so the same rule would 402 every MCP read and kill the Claude path.
**Decided: MCP reads are zero-rated and say so** — `access_records` gains a nullable
`payment_state`, stamped `'unbilled'`, rather than leaving the read silently free. **The hole,
plainly: a builder holding a grant can read the same scope free over MCP instead of paying for a
job.** Closing it needs escrow funding at DCR or an owner/sponsor payer; neither exists.

## Rollout and tests

`JOB_FEES_ENFORCED` per Gateway deployment, default `false`: a submission with no payment artifact is
admitted at `paymentState='unbilled'` and logged. Gateway (backward compatible) → SDK 4.2.0 →
Lorebook → flip enforcement on `dp-rpc-moksha`, then `dp-rpc`. Rollback is the flag first, the
deployment id second. Unit: quote (enabled/disabled/zero), `maxPrice` refusal, the 402 body
field-for-field against `/v1/escrow/pay`, void on fail/expire, receipt signer mismatch. PostgreSQL
(`describeWithPostgres` + `pushSchema`, per `access-receipt-void-postgres.test.ts`): reserve → bind →
drain → settled, and reserve → void → capacity freed, verified failing on `origin/main`; CI has no
Postgres, so a render guard mirrors step 24. E2E on canonical Moksha (step 24's pattern: local dev
server on `prd_moksha`, live relayer): quote → job → completed → settled on chain; insufficient
balance → 402; zero-fee → free.

## Open

1. **Fleet roll — approved 2026-09-16.** Full parity takes the enclave-signed receipt, so the node
   agent change rolls Moksha canonical first, then mainnet (step 8's dual-pin procedure), with
   PS #313 folded into the same roll and compose hashes recorded before and after.
2. Mainnet proof needs Lorebook's builder `0x6a9A4cfa…68a4` funded with USDC.e on 1480 — in flight.
   Unfunded, both paths 402 identically: parity, but not a demo.
