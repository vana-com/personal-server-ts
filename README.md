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

| Endpoint                    | Method | Auth            | Purpose                |
| --------------------------- | ------ | --------------- | ---------------------- |
| `/health`                   | GET    | None            | Health check           |
| `/v1/data/{scope}`          | POST   | Owner           | Ingest data            |
| `/v1/data`                  | GET    | Builder         | List scopes            |
| `/v1/data/{scope}`          | GET    | Builder + Grant | Read data              |
| `/v1/data/{scope}/versions` | GET    | Builder         | List versions          |
| `/v1/data/additions`        | GET    | Owner           | Additions summary      |
| `/v1/data/{scope}`          | DELETE | Owner           | Delete data (durable)  |
| `/v1/grants`                | GET    | Owner           | List grants            |
| `/v1/grants/verify`         | POST   | None            | Verify grant signature |
| `/v1/access-logs`           | GET    | Owner           | Access history         |
| `/v1/sync/trigger`          | POST   | Owner           | Force sync             |
| `/v1/sync/status`           | GET    | Owner           | Sync status            |
| `/v1/sync/file/{fileId}`    | POST   | Owner           | Sync specific file     |

### Additions summary

`GET /v1/data/additions?tz=<IANA zone>&days=<1..31>` (owner only) returns `{ timezone, total, days: [{ date, added }], trackedSince, scopes: [{ scope, total, trackedSince }] }`: how many records each scope holds and how many were first seen on each of the last `days` local calendar days. `days` is digits only and both parameters are validated before any storage access.

It is computed from a per-scope first-seen ledger kept as a sidecar beside the data (`<data dir>/first-seen/<scope>.json` on Node), derived from the scope's stored versions. The ledger is never part of a stored data envelope, never synced and never served to grantees.

- **Building it.** A write never reads stored data: it folds only the version it already has in memory into an existing ledger, or starts a ledger when it is the scope's first version, and otherwise leaves it for the owner's next `/additions` read. The ledger records up to which version it is known complete (`through`); the read catches up on every version newer than that, and rebuilds an absent or stale ledger from the retained versions, one at a time: the newest 200 versions at most and about 256 MB of stored envelopes at most. A rebuild that cannot read any version is remembered, so it is not retried on every request.
- **`trackedSince`** is the scope's baseline: the oldest version the ledger covers that has trackable records. A day's count is meaningful for a scope only for days after its `trackedSince`. It is `null` (and the scope is total-only) while no version is trackable: a binary file, a snapshot over the record cap, or records without ids. When history is longer than the rebuild window, `trackedSince` is the oldest version folded, not the oldest retained, and a version synced in later that is older than that never moves it back.
- **`total` and `added`.** `total` is the record count of the scope's newest version; a binary file counts as one record. `added` counts only records present in the newest version that has trackable records, so while a scope's newest version is a binary file, an over-cap snapshot or a rebuild that could not be read, the scope reports its `total` and no additions: `added` never exceeds `total`. A scope with a failed rebuild reports `total` 0 until a newer version arrives.
- **Identity and the record cap.** Only records with a non-empty string or numeric id are tracked; records without one count toward `total` but never toward `added`. A snapshot with more than 200,000 tracked records is untrackable for that version only: its `total` is kept, it adds no keys and is never a baseline, and tracking resumes with the next normal import (and after the oversized version ages out or is deleted, a rebuild is unaffected by it). If the records the ledger remembers pass 200,000, it drops those absent from the newest tracked version, oldest first; a dropped record that returns is dated as new. No owner action is needed.
- **Retention.** The ids of records no longer present are kept for 90 days after the newest tracked version (pruning runs when a newer version is folded), so a record that skips one export and returns keeps its original date. Folding is order independent for versions within that window; versions further apart folded in a different order can re-date a record that was already pruned.
- **Known limitations.** Scopes with no rule key records by the array name in the body (legacy form) or the dataset name (stored PDPP `{ records }` form); a generic scope whose array name differs from its dataset name is re-keyed when its body moves between the two forms, and its records show as added once. A rebuild or a delete on one scope makes that scope's other ledger operations (ingest bookkeeping, delete, `/additions`) wait for it, bounded by the byte budget. Two operating-system processes sharing one data directory can lose a ledger update; the read repairs versions newer than `through`, and anything older needs the ledger deleted to be rebuilt.
- **Deletion.** Deleting a scope, or its last version by any path, deletes its ledger; a newer reimport starts a fresh baseline. If a scope's newest version is removed but older ones remain, the ledger is rebuilt on the next read.

### Durable deletion

`DELETE /v1/data/{scope}` registers an owner-signed tombstone at the gateway, removes the ciphertext from storage one exact version key at a time (every registry version up to the tombstone plus any covered local key; never a scope-wide delete, so a re-add registered above the tombstone version keeps its blob by construction), then removes the local copy, in that order; the response reports each step. Blob deletes run in batches under the storage rate limit and any key not finished in a pass is queued as an exact retry marker that later sync cycles drain. Reads of a deleted scope answer `410 DATA_DELETED`, never a tombstone as data, and the scope and version listings hide copies a tombstone covers. Every replica keeps an in-memory view of gateway tombstones fed by its sync cycle and consulted before serving or charging for a read, so the consistency window for a deletion made on another replica is one sync poll interval while sync is healthy (60s by default), and at most `maxStalenessMs` (120s) plus one gateway lookup otherwise; a scope re-added on another replica after its deletion becomes readable here on the same schedule, because remembered tombstones age out and are re-checked too. Whether a local copy is covered by a tombstone is decided by registry versions and an ingest-time marker (the tombstone version the replica knew when the row was written), never by comparing clocks across machines; data ingested before a replica learns of a deletion made elsewhere is treated as deleted. A replica that cannot reach the gateway serves its last known state rather than failing reads. Ciphertext that left the server before the deletion stays decryptable by the owner; the scope key is derived, not stored, so there is nothing to destroy.

## Docs

- [DPv1 Protocol Spec](docs/260121-data-portability-protocol-spec.md) — canonical protocol behavior
- [Architecture](docs/260127-personal-server-scaffold.md) — design decisions and repo structure
