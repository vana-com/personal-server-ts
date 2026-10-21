# External-owner replica composition

Real connector mode reuses `~/.tmp/replica-owner-composition-B8aUYY/auth.sqlite` and the exact issuer/Personal Server origin `http://127.0.0.1:3286`. An explicit `--root` requires an existing readable authority DB. Real mode also checks that its recorded owner matches the configured owner. No token, grant, retained declaration, or old fixture data is deleted.

```sh
PATH=/home/tnunamak/.local/lib/qwen-code/node/bin:$PATH TMPDIR=$HOME/.tmp \
node --import tsx scripts/pdpp-replica-owner-composition.ts \
  --root "$HOME/.tmp/replica-owner-composition-B8aUYY" \
  --owner 0x21674d255a8a6806ba332b4d0b795822ae85a67f \
  --port 3286 \
  --account-origin http://localhost:3084 \
  --client-id odl_app_4e15deb70fdd449b8d09f733 \
  --redirect-uri http://localhost:3284/api/demo/pdpp/callback \
  --declaration-path "$HOME/.tmp/cutover-handoff/strava-browser-public-0.1.35-1021/collection-profiles/strava-browser/source-declaration.json" \
  --declaration-sha256 659b0e99f4a4284514c72989881dee56c0d72347f0cc77ddb5cf7fd9aa9851bb \
  --method-id strava-browser \
  --connection-id strava:0x21674d255a8a6806ba332b4d0b795822ae85a67f \
  --grantee-address 0xB2611DD01170810Ed47c26dbeAD422dd7b66DCA6
```

This host uses Node 22. The flow worker owns the connector's supported Node 24.21+/Patchright 1.63 process, JSONL, browser handoff, login and OTP. The host loads no bundled connector entry and launches no browser. Parent verification of the signed artifact is separate from the host's exact declaration-byte hash and production declaration/schema validation.

The dedicated disposable owner must sign again after restart. The wallet private key is not exported. The master-key signature **is sensitive and leaves the Account SDK**: the host derives the shared data-encryption key and passes that key to B over local IPC. Never put signatures, keys or raw tokens in URLs, files or logs.

## Signing and authority

1. Read `GET /composition/state`. It publishes the loaded head and runtime source hashes, actual declaration, phase, pending signing requests, actual registered connection/binding facts, and digest/count receipts. CORS permits only Account `http://localhost:3084`; the loopback listener rejects other Host origins. Responses use `Cache-Control: no-store`.
2. Use the real Account wallet SDK to sign the fixed requests. A `personal_sign` request has `{request_id, method, message}` containing the SDK master-key message. Each `eth_signTypedData_v4` request has `{request_id, method, device, typed_data}`; sign `typed_data` unchanged. Registration messages bind the owner, fresh A/B server addresses/public keys, run-specific server URLs, and dev registration domain.
3. Submit `POST /composition/signatures` from Account with JSON `{request_id, signature}`. Recovery must match the owner; each ID is consumed once, including concurrent attempts. Unsigned bodies, wrong signers, unknown IDs, extra fields, query parameters and foreign origins fail closed. Accepted signatures are not returned.
4. Separately call normal Web3Signed `POST /pdpp/v1/owner/token` with the signed JSON body `{"source_id":"https://registry.pdpp.dev/sources/strava"}`. An empty body fails. The wrapper captures a successful production route response only after the existing token service verifies owner, kind and source, for B's authenticated introspection. It configures no dev-token bypass, direct token issuance or second authority.

A is an in-process `openReplicaRuntime`; B remains a real Device child with the separated replica adapter. Fresh A/B data directories live below a new `connector-run-*` inside the existing root. Source, streams, fields and inventory come from the exact declaration and actual registered store. Real mode generates zero synthetic records and never calls fixture `put`/`blob`/`delete`/`reset` commands.

## Normal ingestion and B reads

Wait for `state.ingestion.ready`. Before A exists, connection ID, generation and ingest URLs are null. After normal runtime/bootstrap registration, state exposes the actual binding from `A.store.getInstanceBinding`, method, URL and schema for each declared stream. Supervisors must use those values, without inferring ownership from the handle or guessing generation 1.

C1's `__c1IngestStravaRecords` closure retains the genuine source owner token and calls:

```text
POST /pdpp/v1/streams/activities/records/ingest?method=strava-browser&binding_generation=<actual state value>
Authorization: Bearer <normal source owner token held in memory>
Content-Type: application/json
```

The body is a normal RECORD envelope or array. The supervisor may validate `type: "RECORD"`, remove only that discriminator and the route-level stream, and attach the explicitly registered `instance`. Preserve `key`, `data`, `emitted_at` and optional `op` verbatim. `STATE` events remain runtime cursor state. There is no messages mapper, `$pdpp` wrapper, custom ingest endpoint or captured-credential injection.

The request reaches production `pdppRecordsRoutes` via `createPdppRecordsDeps`, the same AS token service and A's actual store/database/journal. Wrong owner/source, unowned connection, inactive method, missing parameters and stale generation are refused. Owner-token renewal does not restart A or clear its records. Only B may restart against its same durable directory to refresh its introspection credential.

All public stream/record/blob GETs proxy to B's actual HTTP RS with the caller's Bearer and query unchanged. Shared receiver policy gates grant reads. AS routes and discovery remain on the stable origin.

Ready requires nonempty actual A rows, matching B confirmed grant-visible rows, equality of all seven canonical fields (`instance`, `stream`, `record_key`, `data`, `emitted_at`, `deleted`, `blob_id`), matching referenced blob digests, and active chain evidence. This is recomputed as ingestion proceeds. Strava declares no blob field: its receipt reports zero referenced blobs. The old fixture blob receipt remains separate baseline evidence. Connector state omits fixture connections, messages stream and October fixture window.

## Normal DCR compatibility

`--grantee-address` mounts the separately reviewed production legacy factory over A's real signer, dev SDK Gateway client and real raw-file/index ports. The optional typed `legacyRoutesFactory` is the in-process composition seam. Its normal index is `A/legacy-index.db`; raw storage is `A/data`, separate from receiver and authority databases.

Owner-signed `POST /v1/grants` uses ordinary Web3Signed proof over the exact body, the configured grantee address and `scopes: ["strava.activities"]`. Optional `expiresAt` is Unix seconds; optional `grantVersion` is a decimal string. Success is the actual gateway result, HTTP 201 `{"grantId":"..."}`. The parent maps that ID to Web DCR completion's `grant_id`. A PDPP owner Bearer is not a legacy grant proof.

`GET /v1/data/strava.activities` uses the production data handler and normal projection of actual raw bytes. Empty raw storage stays empty. An unauthenticated probe gets production 401; an authenticated owner request for an absent object gets 404. No raw envelope is generated from canonical records, and no legacy read success is fabricated.

## Verification and lifecycle

```sh
PATH=/home/tnunamak/.local/lib/qwen-code/node/bin:$PATH TMPDIR=$HOME/.tmp \
node_modules/.bin/vitest run scripts/pdpp-replica-owner-composition.test.ts
PATH=/home/tnunamak/.local/lib/qwen-code/node/bin:$PATH TMPDIR=$HOME/.tmp \
node_modules/.bin/tsc -p scripts/tsconfig.json --pretty false
```

The tests also cover `evaluateConnectorReadiness`, the fail-closed predicate behind the connector `ready` receipt: each refusal (no rows, pending outbound work, a missing or unconfirmed B row, a differing `data`, `emitted_at` or `blob_id`, an oracle mismatch, a blob digest mismatch, no `Active` chain) returns not-ready with a reason. A second test takes the row A accepts through its normal owner ingest, exports A's replication operations and imports them into a separate B runtime with the same source binding. It asserts that B accepts the operation and holds the same seven canonical fields.

Tests use the checked-in exact public declaration and labelled offline rows. They cover authority inode/token survival; missing-root and wrong-owner refusal; dynamic zero-row startup; genuine owner ingest; auth/method/generation refusal; renewal without record loss; signing/CORS/replay; exact callback/PKCE; and production legacy 401/404. They do not prove live collection or C1's consent/read journey.

Preserve the old public receipt before restart. Hold port 3286 until parent review/commit and the reviewed #438 prerequisite are complete. SIGINT/SIGTERM closes owned listeners, workers and file ports without revoking consent or deleting authority/data. No remote cleanup is claimed without API confirmation.

Without real-source flags, the older fixture mode remains available in its own fresh root. Its fixed messages/connection/window/blob receipts are baseline evidence only.
