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

`GET /v1/data/additions?tz=<IANA zone>&days=<1..31>` (owner only) returns `{ timezone, total, days: [{ date, added }], trackedSince, partial, scopes: [{ scope, total, trackedSince, partial }] }`: how many records each scope holds and how many were first seen on each of the last `days` local calendar days. `days` is digits only and both parameters are validated before any storage access.

It is computed from a per-scope first-seen ledger kept as a sidecar beside the data (`<data dir>/first-seen/<scope>.json` on Node), derived from the scope's stored versions. The ledger is never part of a stored data envelope, never synced and never served to grantees.

- **Building it.** A write never reads stored data: it folds only the version it already has in memory into an existing ledger, or starts a ledger when it is the scope's first version, and otherwise leaves it for the owner's next `/additions` read. The ledger records up to which version it is known complete (`through`); the read catches up on every version newer than that, and rebuilds an absent or stale ledger from the retained versions, one at a time: the newest 200 versions at most and about 256 MB of stored envelopes at most. A rebuild that cannot read any version is remembered, so it is not retried on every request.
- **When a record counts as added.** A record counts on the local day of the stored version it first appeared in. The scope's first version counts too: connecting a new source with 5,000 records reports 5,000 added that day, and so does reimporting a scope after deleting it. This holds only when the scope's baseline is known to be its first version (next bullet); otherwise the baseline's records are left out and every later record still counts.
- **`trackedSince` and `partial`.** `trackedSince` is the scope's baseline: the oldest version the ledger covers that has trackable records (`null`, and `partial` false, while none is: a binary file, a snapshot over the record cap, or records without ids). A scope is `partial`, and the records first seen at `trackedSince` are not counted, unless all of these hold: the baseline is the scope's oldest retained version (an earlier binary, id-less or over-cap version makes the first trackable one not the oldest), that oldest version looks like the scope's first (its version number is 1, or it was written after a deletion), and the history was not truncated (more than 200 retained versions or about 256 MB made the rebuild stop early). This is decided from the index on every read, not stored, so it follows later changes: a version number rewritten by an upload, an older version downloaded, the oldest version deleted. A version that cannot be read is not a truncation: it is retried and the scope becomes complete once it is read or deleted. A version synced in later that is older than a truncated baseline never moves it back. The top-level `partial` is true when any scope is.
- **Devices and upgrades.** A second device or a reinstall receives only a scope's latest version by sync, usually with a version number above 1, so its scopes start `partial` there and their baseline is not counted on that device; additions made after that agree across devices. Rows imported before DPv2 were backfilled to version 1, so such a scope whose older versions were deleted looks complete and counts its oldest remaining version as first imports. A version deleted from the middle of a history leaves no trace, so such a scope is not reported partial and its records are dated by the next version. Ledgers written by earlier releases are discarded and rebuilt once under this rule.
- **`total` and `added`.** `total` is the record count of the scope's newest version; a binary file counts as one record. `added` counts only records present in the newest version that has trackable records, so while a scope's newest version is a binary file, an over-cap snapshot or a rebuild that could not be read, the scope reports its `total` and no additions: `added` never exceeds `total`. A scope with a failed rebuild reports `total` 0 until a newer version arrives.
- **Identity and the record cap.** Only records with a non-empty string or numeric id are tracked; records without one count toward `total` but never toward `added`. A snapshot with more than 200,000 tracked records is untrackable for that version only: its `total` is kept, it adds no keys and is never a baseline, and tracking resumes with the next normal import. A scope remembers at most 200,000 records. When a version brings more than fit, the ledger makes room once, by dropping records that are absent from the newest tracked version and from the version being folded. What this does and does not protect:
  - Records first seen at or before the baseline (the first trackable version) are never dropped, whether or not the scope is partial. Among the others, the most recently first-seen absent records go first.
  - Other records that are absent from the newest version can be dropped when a later version brings the ledger to the cap, and are then dated as new if they return. This needs a scope within reach of the 200,000-record cap, and a holder of a write grant on that scope can provoke it (they can already replace the scope's contents). The ids in the incoming version itself are never dropped, so a flood does not displace its own records, only absent older ones.
  - If nothing more can be dropped, the new records that do not fit are left out (smallest ids kept), so at the cap `added` under-counts.
  - No owner action is needed.
- **Totals follow the owner app.** `total` equals what the owner app counts for the scope: one record per item, one per profile, join-only streams counted when stored as their own scope, every ad row (topics, advertisers and categories). Where identity is not provably the same in both stored forms the scope is counted but never tracked (`trackedSince` null, no additions): the LinkedIn lists, the YouTube lists except playlists, Oura sleep, the HEB and Whole Foods scopes, and the profiles. Only `chatgpt.memories`, `chatgpt.messages`, `github.profile` and `instagram.profile` are 0, because the app shows none. Two places the app and the data disagree and the server follows the app: a legacy Oura sleep body counts the same sleep row twice (`dailyScores` and `sleepPeriods`) where the rows form counts it once, and `github.starred` counts undated items the app hides.
- **Retention.** The ids of records no longer present are kept for 90 days after the newest tracked version (pruning runs when a newer version is folded), so a record that skips one export and returns keeps its original date. Folding is order independent for versions within that window; versions further apart folded in a different order can re-date a record that was already pruned.
- **Incremental versus rebuild.** A record absent for more than 90 days that then returns is dated as new when the ledger is updated incrementally; a rebuild from the retained versions can date it earlier, so the two can differ. After a version that is not the newest is deleted, its ids and its effect on the baseline stay in the ledger until they are pruned or the ledger is rebuilt. A version that cannot be read is remembered in the ledger and read again at most once an hour; in between, the ledger is served as it is, with the numbers of the newest version it could read, and nothing is read. Once the version is readable, or deleted, the ledger converges to what a rebuild gives.
- **Lite.** Each scope's ledger is a side record of the persistence adapter. If deleting one fails, the data delete still succeeds, the scope is remembered as pending, and the leftover is deleted when the storage next loads or the next ledger is deleted; until then it is never read, because its newest version is gone.
- **Known limitations.** Scopes with no rule key records by the array name in the body (legacy form) or the dataset name (stored PDPP `{ records }` form); a generic scope whose array name differs from its dataset name is re-keyed when its body moves between the two forms, and its records show as added once. A rebuild or a delete on one scope makes that scope's other ledger operations (ingest bookkeeping, delete, `/additions`) wait for it, bounded by the byte budget. Two operating-system processes sharing one data directory can lose a ledger update; the read repairs versions newer than `through`, and anything older needs the ledger deleted to be rebuilt.
- **Deletion.** Deleting a scope, or its last version by any path, deletes its ledger; a reimport starts a fresh baseline whose records count as added on the reimport's day. If a scope's newest version is removed but older ones remain, the ledger is rebuilt on the next read.

### Durable deletion

`DELETE /v1/data/{scope}` registers an owner-signed tombstone at the gateway, removes the ciphertext from storage one exact version key at a time (every registry version up to the tombstone plus any covered local key; never a scope-wide delete, so a re-add registered above the tombstone version keeps its blob by construction), then removes the local copy, in that order; the response reports each step. Blob deletes run in batches under the storage rate limit and any key not finished in a pass is queued as an exact retry marker that later sync cycles drain. Reads of a deleted scope answer `410 DATA_DELETED`, never a tombstone as data, and the scope and version listings hide copies a tombstone covers. Every replica keeps an in-memory view of gateway tombstones fed by its sync cycle and consulted before serving or charging for a read, so the consistency window for a deletion made on another replica is one sync poll interval while sync is healthy (60s by default), and at most `maxStalenessMs` (120s) plus one gateway lookup otherwise; a scope re-added on another replica after its deletion becomes readable here on the same schedule, because remembered tombstones age out and are re-checked too. Whether a local copy is covered by a tombstone is decided by registry versions and an ingest-time marker (the tombstone version the replica knew when the row was written), never by comparing clocks across machines; data ingested before a replica learns of a deletion made elsewhere is treated as deleted. A replica that cannot reach the gateway serves its last known state rather than failing reads. Ciphertext that left the server before the deletion stays decryptable by the owner; the scope key is derived, not stored, so there is nothing to destroy.

## Docs

- [DPv1 Protocol Spec](docs/260121-data-portability-protocol-spec.md) — canonical protocol behavior
- [Architecture](docs/260127-personal-server-scaffold.md) — design decisions and repo structure
