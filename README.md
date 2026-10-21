# Vana Personal Server

[![CI](https://github.com/vana-com/personal-server-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/vana-com/personal-server-ts/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@opendatalabs/personal-server-ts)](https://www.npmjs.com/package/@opendatalabs/personal-server-ts)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![node >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![TypeScript 5.7](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org)

TypeScript implementation of the Vana Data Portability Protocol's Personal Server. Stores user data locally, serves it to authorized users via grant-enforced APIs, and syncs encrypted copies to storage backends.

## Architecture

NPM workspaces monorepo with three packages:

| Package           | Purpose                                                                |
| ----------------- | ---------------------------------------------------------------------- |
| `packages/core`   | Protocol logic — auth, grants, scopes, storage, keys, gateway client   |
| `packages/server` | Hono HTTP server — routes, middleware, composition root                |
| `packages/cli`    | Facade package for external tools (`@opendatalabs/personal-server-ts`) |

By default, Personal Server uses `~/personal-server` as its root namespace:

- Data: `~/personal-server/data/`
- Config: `~/personal-server/config.json`
- Index: `~/personal-server/index.db`
- Server keypair: `~/personal-server/key.json`
- Access logs: `~/personal-server/logs/`

Override the root with `PERSONAL_SERVER_ROOT_PATH` (for example, the Vana desktop app uses `~/.vana/desktop/personal-server`).

## Setup

```bash
node -v  # >= 20
npm install
cp .env.example .env   # dev/test master key — see file for details
npm run build
```

## Run

```bash
npm start             # build + start server
npm run dev           # run from source (no build step)
PERSONAL_SERVER_ROOT_PATH=~/.vana/desktop/personal-server npm start
```

The server starts on the port defined in `${PERSONAL_SERVER_ROOT_PATH:-~/personal-server}/config.json` (default: 8080). Health check at `GET /health`.

## Configuration

The server reads `${PERSONAL_SERVER_ROOT_PATH:-~/personal-server}/config.json` on startup (created with defaults if missing).

```json
{
  "server": {
    "port": 8080
  },
  "logging": {
    "level": "info",
    "pretty": false
  },
  "storage": {
    "backend": "local"
  }
}
```

Set `"pretty": true` for human-readable logs during development.

### PDPP bearer compatibility

`pdpp.protocolProfile` defaults to `"current"`, which keeps the existing
403 `grant_revoked` and `grant_expired` responses. `"candidate-0.1.0"` answers
an inactive bearer (a revoked or expired grant, by the authorization server or
on chain) with HTTP 401 `invalid_token` and a
`WWW-Authenticate: Bearer error="invalid_token"` challenge; the cause stays in
the message. In both profiles, chain expiry is never reported as revocation,
and a client access token without a finite expiry is refused when stored and
inactive when presented. Unknown profile values fail configuration loading.

### PDPP data and legacy grants

A legacy chain grant reads actual legacy files only, with or without a PDPP
grant binding. The canonical view of a scope, and every stored version with
PDPP origin (native `$pdpp` import metadata, or a `pdpp-projector` /
`pdpp-import-projection` producer stamp), reach a non-owner only through the
PDPP resource server with a PDPP access token. This applies to `/v1/data`
(Node and Lite), MCP, derivative questions and TEE jobs. The owner keeps full
access. A version path never changes its bytes once published.

### Server Registration

Register your server with the Vana Gateway so it can participate in the data portability network:

```bash
export VANA_OWNER_PRIVATE_KEY=0x...         # your owner wallet private key
npm run register-server                     # uses server.origin from config
npm run register-server https://my.server   # override server URL
PERSONAL_SERVER_ROOT_PATH=~/.vana/desktop/personal-server npm run register-server
```

The script signs an EIP-712 `ServerRegistration` message with the owner key and POSTs it to the gateway. Once registered, `GET /health` will show `delegation.registered: true`.

## Test

```bash
npm test              # run all tests
npm run test:watch    # watch mode
npm run test:e2e      # end-to-end tests (limited mocking)
```

Tests are co-located with source (`foo.ts` → `foo.test.ts`).

## API

All authenticated endpoints use `Authorization: Web3Signed <base64url(json)>.<signature>` — no sessions, no cookies.

| Endpoint                               | Method | Auth            | Purpose                        |
| -------------------------------------- | ------ | --------------- | ------------------------------ |
| `/health`                              | GET    | None            | Health check                   |
| `/v1/data/{scope}`                     | POST   | Owner           | Ingest data                    |
| `/v1/data/{scope}/imports/{operation}` | PUT    | Owner           | Accept or replay a JSON import |
| `/v1/data`                             | GET    | Builder         | List scopes                    |
| `/v1/data/{scope}`                     | GET    | Builder + Grant | Read data                      |
| `/v1/data/{scope}/versions`            | GET    | Builder         | List versions                  |
| `/v1/data/additions`                   | GET    | Owner           | Additions summary              |
| `/v1/data/{scope}`                     | DELETE | Owner           | Delete data (durable)          |
| `/v1/grants`                           | GET    | Owner           | List grants                    |
| `/v1/grants/verify`                    | POST   | None            | Verify grant signature         |
| `/v1/access-logs`                      | GET    | Owner           | Access history                 |
| `/v1/sync/trigger`                     | POST   | Owner           | Force sync                     |
| `/v1/sync/status`                      | GET    | Owner           | Sync status                    |
| `/v1/sync/file/{fileId}`               | POST   | Owner           | Sync specific file             |

### Owner import acceptance

`PUT /v1/data/{scope}/imports/{operation}` accepts an owner root JSON object up to the data-ingest limit (512 MiB). `operation` is a stable 64-character lowercase hexadecimal identifier for one intended import; derive it from the owner, saved run identity and scope, excluding the body digest and server port. Ordinary `POST` continues to create a distinct write on each request. Binary, lineage and query parameters (including `supersede`) are refused on import PUT.

First acceptance returns `201`; a matching replay returns `200` with the original `{ scope, collectedAt, status, importReceipt: { operation, bodySha256, scope, collectedAt, acceptedAt } }`. `bodySha256` is SHA-256 over the UTF-8 RFC 8785 canonical JSON body: object key ordering and whitespace do not change identity; changed values or array order return `409 IMPORT_CONFLICT`. The receipt identifies local acceptance, not settled remote propagation or a final gateway version. Replaying an accepted import after a later write does not append data or make the old import newest. Replay can wake unfinished sync without another data-written event.

Node storage persists the exact prepared envelope and original causal deletion marker in SQLite before publishing it without replacement, then commits the index and immutable receipt together. Startup and subsequent publication recover prepared imports at their original timestamp. Only import PUTs use this journal. Ordinary JSON, binary and replica writes keep their own staged-file and revision-guarded index commit, and are not journaled. Imports take the same short SQLite writer gate and the same revision-guarded index insert, so an import advances the scope's CAS revision like any other write and is refused (`409 SCOPE_CLOSED_FOR_WRITES`) when the index has closed the scope for writes. An import lands after the scope's current newest version. This gives processes sharing one root a single import authority; independent roots retain independent acceptance. Import identities and receipts do not expire. Deleting a version or scope durably retires its operations before cleanup; matching retries return `410 IMPORT_DELETED` with the original accepted receipt in `error.details.importReceipt`, and an intentional re-add needs a new operation. A cancelled preparation has no accepted receipt. Scope cleanup removes the files and index rows captured at retirement, preserving later writes. Failed deletion keeps cleanup retryable.

Older servers reject the dedicated PUT route before ingestion; unsupported storage returns `501 IMPORT_UNSUPPORTED`. Clients must retain pending delivery and request an upgrade, never fall back to POST. Before upgrading a shared root to a build with the owner-import journal, stop all old writers: the index schema version stamp prevents newly starting old binaries, but cannot evict already-open old connections. Back up `index.db`, its WAL and data files as one root; do not discard receipts or downgrade the schema. Historical POST acceptances cannot acquire trustworthy operation receipts retrospectively.

Windows skips directory fsync barriers; file fsync and journal recovery remain in place. Directory-entry and power-loss durability are outside the Windows guarantee.

### Additions summary

`GET /v1/data/additions?tz=<IANA zone>&days=<1..31>` remains owner-only and keeps `timezone`, `total`, `days`, `trackedSince`, `partial` and `scopes`. The version-1 response adds `coverage`, numeric-string `through` markers, recent UTC quarter-hour `buckets`, `fineSince`, older daily UTC `daily` counts, and corresponding per-scope counts. A day's additions mean records that arrived then, including records absent from later snapshots. Current `total` can therefore be smaller than historical additions.

The durable producer stores encrypted per-source ledgers at `vana.system.additions.<scope>` and the portable owner summary at `vana.system.additions`. It verifies both registered envelope commitments and revalidates the version inventory before certifying coverage. The local format-v5 sidecar is a cache; v4 sidecars rebuild. Local-only results return `coverage: unavailable` because a local index cannot establish complete owner inventory.

`partial` describes unknown historical baseline dates. `coverage` independently describes current recovery: `complete`, `behind`, `partial`, or `unavailable`. A delete/reimport starts a fresh baseline whose existing records are not new arrivals. A missing version or unreadable blob is never silently certified complete. Literal `vana.system.` scopes are excluded from discovery and Memory totals and cannot be read or written through grants or MCP. `vana.profile`, bare `vana.system` and `vana.systematic.*` retain their ordinary behavior.

The pure fold permanently retains identities rather than pruning them after 90 days or evicting absent keys. Its storage grows with distinct record identities. The existing 200,000-key limit applies to individual snapshots; an over-limit snapshot explicitly marks incomplete coverage. Record rules and identity extraction otherwise remain unchanged.

Consumers can import `AdditionsSummarySchema`, `readAdditionsSummaryJson`, and `projectPortableAdditionsByLocalDay` from `@opendatalabs/personal-server-ts-core/additions/summary`. Ten complete UTC days plus today retain quarter-hours; older counts compact into UTC days. Full runtime reconstructs older local intervals from exact ledger timestamps. Portable readers return partial with no projected days when older non-UTC boundaries cannot be reconstructed. Portable JSON is limited to 8 MiB. Lite remains unavailable without concrete bounded signing, crypto and checkpoint capabilities; it does not fall back to unbounded SDK operations. See [the producer contract](docs/durable-additions.md) for capability requirements and retained local SQL/encryption evidence.

This is an unpublished implementation requiring the Gateway contract at `data-gateway@228bbf1cd6893a5b34da248832d8861f245d6d3d`. Ordinary Desktop/TEE server keys cannot authorize that owner-wallet-only inventory route. Their durable producer remains unavailable without an explicitly injected owner request signer. Lite's ordinary owner signer does not supply the required bounded crypto/checkpoint capabilities, so incremental recovery remains unavailable. See [the producer contract and remaining gates](docs/durable-additions.md) before integrating or releasing this draft.

### Durable deletion

`DELETE /v1/data/{scope}` registers an owner-signed tombstone at the gateway, removes the ciphertext from storage one exact version key at a time (every registry version up to the tombstone plus any covered local key; never a scope-wide delete, so a re-add registered above the tombstone version keeps its blob by construction), then removes the local copy, in that order; the response reports each step. Blob deletes run in batches under the storage rate limit and any key not finished in a pass is queued as an exact retry marker that later sync cycles drain. Reads of a deleted scope answer `410 DATA_DELETED`, never a tombstone as data, and the scope and version listings hide copies a tombstone covers. Every replica keeps an in-memory view of gateway tombstones fed by its sync cycle and consulted before serving or charging for a read, so the consistency window for a deletion made on another replica is one sync poll interval while sync is healthy (60s by default), and at most `maxStalenessMs` (120s) plus one gateway lookup otherwise; a scope re-added on another replica after its deletion becomes readable here on the same schedule, because remembered tombstones age out and are re-checked too. Whether a local copy is covered by a tombstone is decided by registry versions and an ingest-time marker (the tombstone version the replica knew when the row was written), never by comparing clocks across machines; data ingested before a replica learns of a deletion made elsewhere is treated as deleted. A replica that cannot reach the gateway serves its last known state rather than failing reads. Ciphertext that left the server before the deletion stays decryptable by the owner; the scope key is derived, not stored, so there is nothing to destroy.

## Docs

- [DPv1 Protocol Spec](docs/260121-data-portability-protocol-spec.md) — canonical protocol behavior
- [Architecture](docs/260127-personal-server-scaffold.md) — design decisions and repo structure
