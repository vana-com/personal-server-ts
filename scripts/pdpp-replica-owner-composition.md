# External-owner replica composition

Run from this checkout with Node 22 and a dedicated disposable dev owner. This host receives the owner's master-key signature and derives its shared data-encryption master key, which is sent to both worker processes. The wallet private key is not exported, but the master-key signature is sensitive and leaves the Account SDK. This host uses the real production AS route factory, one isolated `auth.sqlite`, and the existing A/B replica worker processes. C1 owns the Account browser, isolated dev Neon database, local CG API, and real PKCE requester. This script does not launch a browser or configure those services.

```sh
PATH=/home/tnunamak/.local/lib/qwen-code/node/bin:$PATH TMPDIR=$HOME/.tmp \
node --import tsx scripts/pdpp-replica-owner-composition.ts \
  --owner "$DISPOSABLE_OWNER_ADDRESS" \
  --port 3286 \
  --account-origin http://localhost:3084 \
  --client-id "$REQUESTER_CLIENT_ID" \
  --redirect-uri "$REGISTERED_REDIRECT_URI"
```

The public issuer and Personal Server origin are both `http://127.0.0.1:3286`. Configure local CG to use that stable origin. Only the exact CLI requester and callback are registered; there is no callback discovery or arbitrary signing endpoint. The listener binds to loopback and rejects other Host origins. CORS permits only the exact Account origin above.

1. Read `GET /composition/state`. It publishes public source/client configuration, owner-proof receipt, pending signing requests, phase, server addresses, retry counts, and confirmed record/blob digests. Responses have `Cache-Control: no-store`.
2. Use the real Account embedded-wallet SDK to sign the returned fixed payloads. A `personal_sign` request has `{request_id, method, message}` containing the SDK `MASTER_KEY_MESSAGE`. Each `eth_signTypedData_v4` request has `{request_id, method, device, typed_data}`; pass `typed_data` unchanged to the SDK's typed-data signer. The two requests bind this owner, ephemeral server addresses/public keys, run-specific server URLs, and the SDK's dev registration domain.
3. Submit each result from the Account page to `POST /composition/signatures` with JSON `{request_id, signature}`. The host verifies recovered owner identity and consumes each ID once, including concurrent requests. Unknown IDs, extra fields, query parameters, unsigned bodies, foreign origins, and wrong signers fail closed. It never returns accepted signatures. Do not place a signature in a URL or copy it to a log/file.
4. Separately call the **normal** `POST /pdpp/v1/owner/token` with Web3Signed owner proof and signed JSON body `{"source_id":"https://replica-journey.invalid/declaration"}`. An empty body fails. C1's source-aware helper already supplies this body. The signing queue is not an owner-auth mechanism. The wrapper captures a successful route response in memory only after the real token service verifies its owner, kind, and source; no dev token, access-token override, direct token issuance, or alternate auth authority is configured.
5. Wait for `phase: "ready"`. The host derives the shared master from the actual SDK message signature, registers A/B against dev Gateway, collects fresh standard fixtures on A, and runs real worker cycles. Readiness requires B's confirmed grant-reader row, canonical SQL equality across both independent stores, matching blob SHA-256, and active chain evidence. All public stream/record/blob GETs then proxy to B's actual HTTP RS with the caller's bearer and query unchanged. AS routes and issuer discovery remain on the public origin.

The fixture source is `https://replica-journey.invalid/declaration`, stream `messages`, export connections `conn` and `conn-other`. Fields are `id`, `text`, `collected_at`, `blob_ref`, and `private_note`. The intended consent selection is `conn`, fields `text`/`collected_at`/`blob_ref`, and half-open October 2026 (`2026-10-01T00:00:00Z` through exclusive `2026-11-01T00:00:00Z`). Fixtures include `visible`, an older row, a row exactly at the exclusive bound, and a row on the other connection. The host creates no consent or requester token; C1 must perform the actual Account consent and PKCE redemption.

The normal production owner token lasts 15 minutes. If C1 obtains another genuine owner token, the host refreshes B's in-memory introspection credential by restarting B against its same durable record store. The public origin stays stable. Grant lifetime follows the actual consent; the host does not autonomously revoke or impose a short expiry on that approval.

SIGINT/SIGTERM closes this host and its owned workers without revoking consent. Local run data lives under an isolated `~/.tmp/replica-owner-composition-*` directory. Keep it while C1 needs the session. Server keys, raw signatures, derived data keys and host credentials stay in process/IPC memory; they must not be printed or exported. The normal AS persists its own authority in the single auth store. Dev server registrations and encrypted test objects are real; this wrapper does not invent unsupported remote deletion calls. Do not claim remote cleanup until an owning API confirms it.

Focused checks:

```sh
PATH=/home/tnunamak/.local/lib/qwen-code/node/bin:$PATH TMPDIR=$HOME/.tmp \
node_modules/.bin/vitest run scripts/pdpp-replica-owner-composition.test.ts
PATH=/home/tnunamak/.local/lib/qwen-code/node/bin:$PATH TMPDIR=$HOME/.tmp \
node_modules/.bin/tsc -p scripts/tsconfig.json --pretty false
```

These checks prove the public auth, queue, metadata, callback, and proxy-refusal boundaries. They do not prove C1's live wallet, consent, replication, or requester read. Live readiness and C1's actual journey provide that evidence.
