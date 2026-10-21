# Consent over replicated records on dev

This harness collects canonical records and blob bytes on device A, replicates them through the dev Gateway, storage service and finalized Moksha registry to device B, then drives the real authorization and resource HTTP routes. It generates a new random owner and server signers for each run. It never loads existing accounts, environment files or personal server configuration.

Use Linux, Node 22 and this checkout's existing dependencies:

```sh
export TMPDIR="$HOME/.tmp"
./node_modules/.bin/tsc --build packages/core packages/server scripts
./node_modules/.bin/vitest run \
  packages/server/src/pdpp/replica-authorization.test.ts \
  scripts/pdpp-replica-consent-live-journey.test.ts
./node_modules/.bin/tsx scripts/pdpp-replica-consent-live-journey.ts \
  "$HOME/.tmp/replica-consent.json"
```

The issuer holds the grant, authorization code, token and revocation state in its own SQLite database. B holds canonical replicated records and blob bytes. On every application request, B authenticates to that issuer's existing introspection endpoint using an explicitly provisioned source-scoped owner credential. B validates the issuer's complete v0.2 grant and maps its handles through the trusted local owner/source/connection registry. A missing mapping, ambiguous mapping, different owner, unavailable issuer, invalid credential or inactive token denies access. No positive authorization cache or second issuer is created.

The accepted endpoints are fixed dev Gateway/storage/Moksha origins and the exact ephemeral loopback origins opened by the harness. Other origins and redirects are rejected. Core dumps are disabled before generating keys. Keys and credentials remain in process memory and private child IPC; reports must not contain them. Local databases and generated blob fixtures are removed on exit. Remote dev ciphertext can remain where the API has no deletion path; local cleanup does not erase it.

## Evidence boundaries

This command drives the same PS authorize/review/approve API used by the Account transport. It exercises owner narrowing, exact review digest approval and PKCE code redemption over real HTTP. It does not prove deployed Account UI, Account login, Context Gateway callback or browser return navigation. For a separate local composition with a real Account embedded-wallet owner and requester, use [the external-owner host](./pdpp-replica-owner-composition.md); its browser, connection-readiness and callback outcomes require their own evidence.

The app reads the actual B resource HTTP routes. A separate independent read-only SQL oracle compares A and B across `instance`, `stream`, `record_key`, `data`, `emitted_at`, `deleted` and `blob_id`; canonical serialization supplies the record SHA-256. App responses must equal the approved field projection, with out-of-window and other-connection records excluded. Blob responses must match A's byte length and SHA-256. Raw snapshots alone are never an app-access oracle.

Both owner and grant reads use the receiver's shared visibility policy. The live run requires an owner-visible pending record while the app sees only confirmed data, repeats that boundary across a B restart, and checks a new edit under the same active grant. Revocation and expiry receipts require a healthy issuer and an explicit inactive-token response before B's denial counts as a pass; an unavailable issuer is a distinct error.

This is explicit experimental host composition. It does not enable replication or separated authorization in ordinary application bootstrap. The introspection credential is the existing source-scoped owner-token mechanism; a general long-lived resource-server identity and credential renewal remain separate deployment work. v0.1's incomplete introspection projection is refused rather than reconstructed.

## Adversarial coverage

The 35-case acceptance ledger is maintained with the run report. Distinguish live dev evidence, deterministic HTTP/SQLite evidence, partial coverage and deferred contracts. A prior 8a transport receipt does not prove consent. Account UI, phone/Desktop persistence and the supported producer/reader compatibility matrix remain promotion work unless separately proved.

Generation-bound grants remain a promotion blocker: resetting a connection does not currently bind an existing grant to its previous generation. The protocol must decide that authority boundary; the recommended behavior is fail closed and require owner reapproval. Revocation during an already-started response is a separate open specification question, not a blocker for the current request-based OAuth contract. New requests, pages and requests after restart reauthorize.
