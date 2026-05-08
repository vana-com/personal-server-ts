# Personal Server DPv2 Refactor Spec

## Status

This document is an architecture/refactor planning specification
It is based on the two Linear source documents and current repository inspection.
All implementation tasks following this spec must use red/green TDD and must preserve user data unless a breaking migration is explicitly approved.

## Authoritative Inputs

- Data Portability v2: https://linear.app/vana-team/document/data-portability-v2-f4c7ce43450d
- Personal Server / Vana SDK Structure: https://linear.app/vana-team/document/personal-server-vana-sdk-structure-72ffa90c144d
- PS Lite PoC: https://github.com/Kahtaf/research/tree/main/browser-local-compute-runtime-poc (browser-based API server with blind relay, local checkout ~/Documents/workspace_kahtaf/research)
- Vana SDK GitHub: https://github.com/vana-com/vana-sdk
- Local SDK Checkout: ../vana-sdk

## Goals

- Preserve `personal-server-ts` as the canonical Personal Server HTTP/data-plane contract while refactoring internals for DPv2.
- Define a runtime-agnostic PS core usable by both `ps-node` and `ps-lite`.
- Align reusable primitives with `vana-sdk` without breaking current protocol behavior.
- Keep plaintext strictly inside the user/Personal Server boundary; ODL services must not broker, persist, or deliver plaintext.
- Verify builder, grant, scope, expiry, revocation, and fee state before returning protected data.
- Return typed `ps_unavailable` when the relevant Personal Server runtime is inactive or unreachable.
- Commit and push each atomic chunk of work, when tsc, tests and builds pass. Make sure it's tested as end-to-end as possible first.

## Non-goals

- No one-step migration of all existing primitives into `vana-sdk`. Some of it has been migrated already.
- No definition or implementation of future `ps-worker` runtime internals in this phase.
- No treatment of `vana-connect` as Personal Server internals; it remains an adjacent integration surface.
- Seed recovery/backup UX is not finalized here and remains TBD if unresolved in later tasks.

## Decided / TBD / Out of Scope

| Topic                                              | Status                  | Notes                                                                                          |
| -------------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------- |
| Node baseline                                      | Decided                 | Node 22.                                                                                       |
| Canonical PS contract source                       | Decided                 | `personal-server-ts` remains the canonical HTTP/data-plane contract during refactor.           |
| Runtime scope                                      | Decided                 | Initial spec scope includes `ps-node` and `ps-lite`.                                           |
| Runtime split (`ps-node`, `ps-lite`)               | Decided                 | Introduce runtime-agnostic core with runtime-specific adapters.                                |
| SDK dependency source                              | Decided with validation | Use GitHub dependency syntax for now; keep validation open for monorepo install behavior.      |
| SDK import path                                    | Decided                 | Node runtime imports from `@opendatalabs/vana-sdk/node`.                                       |
| PS Lite API server                                 | Decided direction       | Follow PS Lite PoC direction and adapt to the Personal Server contract surface.                |
| Reusable primitives alignment with `vana-sdk`      | Decided                 | Align shared primitives incrementally; avoid big-bang migration.                               |
| Plaintext boundary                                 | Decided                 | Plaintext remains inside user/PS runtime boundary only.                                        |
| Data read preconditions                            | Decided                 | Validate builder, grant, scope, expiry, revocation, and fee state before return.               |
| Runtime unavailable behavior                       | Decided                 | Return typed `ps_unavailable` when target runtime is down/unreachable.                         |
| `vana-connect` placement                           | Decided                 | Adjacent integration, not PS internal runtime module.                                          |
| Key derivation / seed backup                       | TBD                     | Random seed + HKDF is the likely direction; seed recovery remains unresolved.                  |
| GitHub dependency syntax                           | TBD after validation    | Scratch validation showed direct GitHub alias installs the monorepo root, not the SDK package. |
| Seed recovery / backup UX                          | TBD                     | Kept unresolved here pending dedicated design decisions.                                       |
| Exact final package/export shapes                  | TBD                     | Deferred to Task 4 package-boundary details.                                                   |
| Final DPv2 endpoint/auth contract text             | TBD                     | Deferred to Task 5 contract and auth sections.                                                 |
| Full storage/encryption/runtime migration sequence | TBD                     | Deferred to Task 6 runtime and migration sections.                                             |
| `ps-worker`                                        | Out of Scope            | Future extension only.                                                                         |
| Code changes, dependency changes, test changes     | Out of Scope            | This task only updates the planning doc.                                                       |

## Current Inventory

### Monorepo and package ownership

- `README.md`: Documents npm workspace split and public API surface; useful baseline but auth wording is partially stale.
- `packages/core/package.json`: Core export surface and dependency ownership for protocol/storage/sync primitives.
- `packages/server/package.json`: Server export surface (`.` API and `./runtime`) and UI copy build step.
- `packages/cli/package.json`: Facade package only.

### Current runtime composition (`ps-node` today)

- `packages/server/src/index.ts`: Node runtime entrypoint and listener lifecycle.
- `packages/server/src/bootstrap.ts`: Composition root and dependency wiring.
- `packages/server/src/app.ts`: Route mounting and global error/404 JSON handling.

### Current HTTP and protocol routes

- `packages/server/src/routes/data.ts`: `/v1/data*` list/read/ingest/delete behavior.
- `packages/server/src/routes/grants.ts`: `/v1/grants*` list/create/verify behavior.

### Current protocol and storage primitives (core)

- `packages/core/src/gateway/client.ts`: Gateway REST client for builder/grant/schema/server/file operations.
- `packages/core/src/config/loader.ts`: Config load/validate/save and cloud-mode env override gating.
- `packages/core/src/storage/hierarchy/manager.ts`
- `packages/core/src/storage/hierarchy/paths.ts`
- `packages/core/src/storage/index/schema.ts`
- `packages/core/src/storage/index/manager.ts`
- `packages/core/src/storage/adapters/vana.ts`
- `packages/core/src/storage/encryption/index.ts`
- `packages/core/src/sync/index.ts`
- `packages/core/src/sync/cursor.ts`
- `packages/core/src/sync/engine/sync-manager.ts`
- `packages/core/src/sync/workers/upload.ts`
- `packages/core/src/sync/workers/download.ts`

### Current auth and policy middleware inventory

- `packages/server/src/middleware/web3-auth.ts`
- `packages/server/src/middleware/owner-check.ts`
- `packages/server/src/middleware/builder-check.ts`
- `packages/server/src/middleware/grant-check.ts`
- `packages/server/src/routes/ui-config.ts`

### Current runtime gotchas to preserve during refactor

- `loadConfig()` in `packages/core/src/config/loader.ts` may create/rewrite `config.json` during startup.
- HTTP listener starts before slow background readiness completes (`packages/server/src/index.ts`, `packages/server/src/bootstrap.ts`).
- Non-cloud runtime may bind a second loopback auth listener (`packages/server/src/index.ts`).
- Dev UI auth token is ephemeral and rotates on restart (`packages/server/src/bootstrap.ts`, `packages/server/src/app.ts`).
- Tunnel prereq failures degrade to local-only and can still be unroutable if registration prerequisites are missing (`packages/server/src/index.ts`, `packages/server/src/bootstrap.ts`).

## Target Architecture

Target layering for DPv2 refactor:

1. `vana-sdk`
   - Shared cross-runtime protocol/client primitives that are broadly reusable.
   - Consumed by PS layers where reuse is appropriate.
2. `ps-core`
   - Runtime-agnostic Personal Server domain core: request/response contracts, policy checks, grant/scope/fee/revocation validation orchestration, and typed errors like `ps_unavailable`.
   - No direct Node-only or browser-only dependencies.
3. `ps-node`
   - Node runtime adapter: Hono HTTP serving, local filesystem/SQLite wiring, token/tunnel integrations, process lifecycle.
4. `ps-lite`
   - Browser/local runtime adapter: lightweight runtime suitable for PS Lite constraints while preserving the same PS contract semantics.
5. `vana-connect`
   - Adjacent integration surface used by builders/clients; not an internal PS runtime layer (future)
6. `ps-worker` (future)
   - Explicit future/non-goal runtime path, not implemented or specified in this task.

## Runtime Matrix

| Runtime     | Environment                  | Storage             | API Exposure                                        | Sync Mode        | Secret Handling                                        | In Scope    |
| ----------- | ---------------------------- | ------------------- | --------------------------------------------------- | ---------------- | ------------------------------------------------------ | ----------- |
| `ps-node`   | Node 22                      | Filesystem + SQLite | Hono HTTP                                           | Daemon sync      | Local key material now; OS keychain integration future | Yes         |
| `ps-lite`   | Browser/WebView              | IndexedDB/OPFS      | Browser-local API server/bridge (per PoC direction) | Foreground sync  | Browser keystore / seed handling TBD                   | Yes         |
| `ps-worker` | Cloudflare Worker or similar | R2/KV/D1            | HTTPS worker endpoint                               | Queue/event sync | Deployed encrypted secret handling TBD                 | No (future) |

## Package Boundaries

This section defines the refactor boundary contract for DPv2 internals while preserving existing external behavior.

Node baseline for this boundary split is Node 22 (see Decided/TBD table and runtime matrix).

### Responsibility table

| Layer/package (working names, final exports TBD)   | Primary responsibility                                                                                          | Must not own                                   |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `ps-core`                                          | Protocol/domain semantics, policy orchestration, typed errors, contract-level validation flow.                  | Hono route handling and runtime-specific APIs. |
| `ps-node` (current `packages/server` Node runtime) | Node-only adapters and runtime wiring: Hono app serving, process lifecycle, tunnel/token/FS/SQLite integration. | Browser-only runtime adapters.                 |
| `ps-lite`                                          | Browser-only adapters and local-runtime execution path preserving PS contract semantics.                        | Node-only process/FS/server internals.         |
| `vana-sdk`                                         | Reusable primitives consumed by PS adapters/core where appropriate.                                             | PS-specific route contract ownership.          |

Required boundary rules:

- Protocol/domain semantics belong in `ps-core`, not Hono route handlers.
- Node-only adapters belong in `ps-node` / current `packages/server` Node runtime.
- Browser-only adapters belong in `ps-lite`.
- Reusable primitives should come from `vana-sdk` where that reuse is stable and non-PS-specific.
- Existing package exports must be preserved or migrated with compatibility notes because package `exports` are current public API boundaries.

### Internal ports required before SDK swap

SDK-backed adapters must be introduced behind explicit PS-internal ports before replacing concrete implementations:

- protocol gateway
- storage backend
- grant verifier
- auth/session verifier
- schema resolver
- file registry/sync registry
- platform crypto
- runtime storage

## DPv2 API Contract

DPv2 contract work starts from the existing Personal Server API surface and preserves compatibility-first semantics for current clients:

- Existing contract baseline: `/v1/data`, `/v1/grants`, `/v1/sync`, `/health`.
- Current concrete route shapes remain the starting point for implementation, and any DPv2-specific route reshaping is explicitly TBD.
- Builder read flow is direct-to-PS: the builder calls the Personal Server with `grantId` and requested scope/file selector; no ODL plaintext broker path is introduced.
- Before returning protected data, PS must verify grant status and fee state via DP RPC/Gateway or an SDK-backed protocol port adapter.
- Decryption occurs only inside the PS boundary before response serialization.
- Builders must never receive file encryption keys from PS.
- If the relevant runtime is inactive/unreachable, PS returns typed `ps_unavailable`.

### Contract table (compatibility-first, final DPv2 shapes TBD)

| Contract area     | Current compatibility baseline                                                                        | DPv2 expectation in this refactor spec                                                                                                           | Request requirements                                                                 | Response expectation                                                       | Typed errors                                                                                                                                                                      |
| ----------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Health/readiness  | `GET /health`                                                                                         | Keep existing health contract as baseline; add runtime availability signaling as needed (shape TBD).                                             | None.                                                                                | Health payload with runtime/network indicators.                            | `ps_unavailable` when target runtime is not active/reachable.                                                                                                                     |
| Builder data read | Existing `/v1/data/:scope` read semantics (plus selectors such as `fileId`/`at` in current behavior). | Direct builder-to-PS read with `grantId` and requested scope/file selector; final endpoint shape remains TBD and must remain compatibility-safe. | Builder identity + `grantId` + scope/file selector; auth mechanism per matrix below. | Approved plaintext data only, after in-boundary decrypt and policy checks. | `grant_revoked`, `grant_expired`, `scope_mismatch`, `fee_required`, `ps_unavailable`, `server_not_configured` (+ existing compatibility auth/validation errors where applicable). |
| Grant management  | `/v1/grants*`                                                                                         | Existing grant routes remain baseline; DPv2 may adjust route payload details (TBD).                                                              | Owner-level auth for management operations.                                          | Grant list/create/verify behavior compatible with current expectations.    | Existing compatibility errors + `server_not_configured` where signer/owner material is missing.                                                                                   |
| Sync/control      | `/v1/sync*`                                                                                           | Keep owner control-plane posture; any DPv2 sync contract adjustments are TBD.                                                                    | Owner/control-plane auth.                                                            | Sync trigger/status compatibility preserved.                               | Existing compatibility errors + `server_not_configured` where prerequisites are missing.                                                                                          |

### Builder read flow (architecture-level)

1. Builder calls PS directly with auth payload, `grantId`, and requested scope/file selector.
2. PS resolves caller identity (address/grantee/client/app mapping as required by configured auth mechanism).
3. PS verifies builder eligibility + grant validity + scope match + expiry + revocation + fee/payment state using DP RPC/Gateway or SDK-backed protocol ports.
4. PS reads encrypted-at-rest content from local/runtime storage and decrypts inside PS boundary.
5. PS returns only approved data payload; no encryption keys leave PS.

### Error model (typed)

- `ps_unavailable`: Runtime inactive/unreachable.
- `grant_revoked`: Grant exists but is revoked.
- `grant_expired`: Grant exists but is expired.
- `scope_mismatch`: Requested scope/file is not authorized by grant.
- `fee_required`: Required DPv2 fee/payment condition not satisfied.
- `server_not_configured`: Required owner/key/runtime config is missing.
- Existing compatibility auth/validation errors remain applicable where current contract already defines them.

## Auth, Grants, Revocation, and Fees

This section distinguishes transport/authentication from authorization decisions and defines DPv2 read-path security checks.

Owner authentication must not be conflated with builder grant authorization. Passing an owner route auth check does not imply a builder may read protected data.

### Auth matrix

| Surface                                                            | Allowed auth mode(s)                                                                                                           | Identity source to resolve before policy checks                                               | Primary authorization checks                                                                | Notes                                                                              |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Owner routes (config/control/data-write/grant-write/sync controls) | Owner Web3Signed, dev token (bypass in dev flow), `PS_ACCESS_TOKEN` where enabled, persisted CLI session bearer where enabled. | Owner signer address or owner-scoped bearer identity.                                         | Owner check (or explicit dev bypass behavior where configured).                             | Matches current multi-mode owner auth posture; implementation keeps compatibility. |
| Builder data-read routes                                           | Web3Signed protocol auth (DPv2 baseline), with compatibility allowances only where already supported.                          | Builder signer address, then resolved grantee/client/app identity required for grant binding. | Builder registration/eligibility + grant authorization.                                     | Builder identity must be explicit before any grant decision.                       |
| Dev token bypass                                                   | Dev-token bearer (ephemeral startup token).                                                                                    | Dev token subject mapped to local policy-bypass context.                                      | Bypass semantics remain explicitly dev-only.                                                | Must not redefine production authorization model.                                  |
| Control-plane owner auth                                           | `PS_ACCESS_TOKEN` bearer for control-plane/owner operations where enabled.                                                     | Control-plane token subject mapped to owner capability.                                       | Owner-level authorization only.                                                             | Not a substitute for builder grant checks.                                         |
| Persisted CLI session token auth                                   | Bearer token from token store/device approval flow.                                                                            | Persisted session subject mapped to owner capability.                                         | Owner-level authorization only.                                                             | Not a substitute for builder grant checks.                                         |
| Web3Signed protocol auth                                           | Signed request payload verification (method/path/origin semantics).                                                            | Signer address from verified signature payload.                                               | Depends on route: owner check for owner routes, builder+grant+fee checks for builder reads. | Core protocol auth mechanism for DPv2-facing builder reads.                        |

### Grant, revocation, scope, expiry, and fee requirements

- Builder reads require a resolvable builder identity and `grantId` before grant checks proceed.
- Grant authorization must verify: grant exists, identity binding matches, requested scope/file selector is authorized, and expiry has not passed.
- Revocation must be checked against DP RPC/Gateway at read time. Optional cache refresh can reduce latency but cannot be source of truth for revocation state.
- DPv2 read path requires fee/payment validation before protected data return; exact fee API and settlement record shape remain TBD.
- Failure mapping must use typed errors: `grant_revoked`, `grant_expired`, `scope_mismatch`, `fee_required`, and `server_not_configured` where system prerequisites are missing.

### Security boundary rules

- Decrypt only inside PS boundary.
- Return only approved plaintext payload to authorized caller.
- Never expose file encryption keys to builders or adjacent services.
- ODL/adjacent services may assist with routing/session mechanics but must not broker, persist, or deliver plaintext.

## Storage, Encryption, and Keys

Storage and key handling must keep plaintext/ciphertext boundaries explicit across runtimes:

- In `ps-node`, plaintext remains in the local PS/user boundary (filesystem `data/` plus local processing memory), while remote/cloud storage receives ciphertext only.
- In `ps-lite`, the browser-local equivalent of the plaintext boundary is IndexedDB/OPFS (or equivalent browser-safe local adapters); remote/cloud storage still receives ciphertext only.
- Grant records and grant verification flows must never expose file encryption keys to builders.

DPv1 key derivation and DPv2 direction:

- Current DPv1-style derivation `HKDF(signature, scope)` is not compatible with non-deterministic Para signatures.
- Direction for DPv2 is random seed material plus HKDF-derived working keys; final backup/recovery/rotation design is security-sensitive and remains TBD.

DPv2 storage/index requirements to lock during implementation:

- File records must preserve stable IDs (`fileId`) that map between local index rows and remote registry records.
- Schema linkage must preserve explicit schema identifiers (`schemaId`) so decrypt/parse logic can resolve scope/model correctly.
- Exact final algorithms (cipher suite details, key wrapping formats, and rotation primitives) remain TBD until security review closes them.

Migration-sensitive state separation:

- Current mutable sync cursor lives in `config.json`; config and mutable sync cursor should be separated or migrated carefully to avoid accidental cursor resets during config rewrites.

## PS Node

`ps-node` remains the full local daemon runtime on Node 22 and preserves the current Personal Server transport contract.

- Runtime and transport: Hono HTTP server stays the local/full runtime transport for `/health`, `/v1/data*`, `/v1/grants*`, and `/v1/sync*` compatibility-first behavior.
- Local state/artifacts: filesystem plaintext data hierarchy, SQLite index (`index.db`), access logs, token store (`tokens.json`), config (`config.json`), server identity/key material (`key.json`), tunnel assets, and background sync state remain part of the runtime.
- Background capabilities: tunnel lifecycle, gateway registration checks, and sync execution remain available in daemon mode.

Current runtime gotchas that migration must preserve or explicitly rework:

- `loadConfig()` can rewrite `config.json` on load.
- HTTP can start before slow background readiness completes.
- Non-cloud startup can bind an additional loopback auth listener.
- Dev UI token is ephemeral and rotates on restart.
- Tunnel prerequisites can degrade runtime to local-only and still be unroutable if registration is incomplete.

Compatibility requirement:

- Existing local data/config/index behavior must remain compatible by default for current deployments unless a specific breaking migration is explicitly documented and approved.

## PS Lite

`ps-lite` is the browser/webview runtime variant and must follow or adapt the browser-local-compute-runtime PoC direction: https://github.com/Kahtaf/research/tree/main/browser-local-compute-runtime-poc

- Runtime model: active only while browser/webview is active; no always-on daemon assumption.
- API exposure: use the browser-local API server/bridge/relay pattern shown by the PoC; exact production bridge mechanism stays TBD until implementation hardening.
- Storage: use IndexedDB/OPFS (or equivalent browser-safe adapter) for local runtime state.
- Sync posture: foreground/best-effort while runtime is active.
- Unavailable behavior: when runtime is inactive, product/builder boundary must receive typed `ps_unavailable`.
- SDK imports: browser-safe SDK primitives must come from `@opendatalabs/vana-sdk/browser`.
- Secrets: seed/secret persistence, backup, and recovery are security-sensitive and remain TBD.

## vana-sdk Integration

### Source and dependency posture

- Target dependency package: `@opendatalabs/vana-sdk` from `https://github.com/vana-com/vana-sdk`.
- Local checkout for research/co-development: `../vana-sdk`.
- GitHub dependency must be treated as a validation item because the upstream repository is a monorepo and root package installability/consumability is not yet proven for CI consumption.
- Candidate GitHub dependency syntax remains TBD. Scratch validation on 2026-05-08 showed `@opendatalabs/vana-sdk@git+https://github.com/vana-com/vana-sdk.git` / `github:vana-com/vana-sdk` installs the monorepo root under the alias and does not expose `@opendatalabs/vana-sdk/node` or `@opendatalabs/vana-sdk/browser`.

### Import path policy

- Node runtime imports must use `@opendatalabs/vana-sdk/node`.
- Browser runtime imports must use `@opendatalabs/vana-sdk/browser`.
- Root imports from `@opendatalabs/vana-sdk` are forbidden (`Root imports` policy).

### Integration boundary rules

- SDK-backed adapters should sit behind the internal ports listed in Package Boundaries so SDK types do not leak throughout PS domain code.
- `@opendatalabs/connect` / `vana-connect` is builder-side adjacent and relevant for interoperability (notably Web3Signed canonicalization and direct PS fetch behavior), but it is not a PS-internal dependency by default.

### Validation checklist (future implementation checks)

- Validate the exact npm GitHub dependency install command.
- Validate `npm ci` can install from lockfile in CI with the selected GitHub dependency shape.
- Validate built import smoke tests for `@opendatalabs/vana-sdk/node` and `@opendatalabs/vana-sdk/browser` where applicable.
- Validate no root SDK import appears in source (`npm run validate:sdk-imports`).

## Migration Sequence

Each implementation item in this sequence must follow red/green TDD: write one failing behavior test, implement the minimum change to pass, verify green, then repeat.

1. Spec freeze: finalize DPv2 object model, auth matrix, package boundaries, and SDK dependency validation.
2. Add characterization tests around current public route/core behavior before refactor.
3. Introduce internal ports without behavior change.
4. Add DPv2 models and SDK-backed adapters side-by-side.
5. Refactor `ps-node` behind ports while preserving current routes or documenting approved breaking changes.
6. Add `ps-lite` runtime architecture using the PoC pattern and browser-safe adapters.
7. Add migration/versioning for `config.json`, `index.db`, data hierarchy, token store, `tokens.json`, and sync cursor.
8. Final validation and compatibility review.

Explicit migration concerns to track across steps 5-7:

- `config.json` currently carries mutable runtime configuration and sync cursor concerns; migration must prevent cursor loss.
- `index.db` schema/version transitions must preserve read-path behavior and file lookup guarantees.
- `tokens.json` and token store migration must preserve owner/control-plane auth continuity.
- Data hierarchy migration must preserve scope/file discoverability and rollback safety.
- Sync cursor migration must be explicit, idempotent, and compatibility-tested.

## Validation Plan

Spec validation commands:

```bash
test -s docs/260507-ps-refactor.md
grep -q "## Goals" docs/260507-ps-refactor.md
grep -q "## Non-goals" docs/260507-ps-refactor.md
grep -q "## Current Inventory" docs/260507-ps-refactor.md
grep -q "## Target Architecture" docs/260507-ps-refactor.md
grep -q "## Package Boundaries" docs/260507-ps-refactor.md
grep -q "## DPv2 API Contract" docs/260507-ps-refactor.md
grep -q "## Auth, Grants, Revocation, and Fees" docs/260507-ps-refactor.md
grep -q "## Storage, Encryption, and Keys" docs/260507-ps-refactor.md
grep -q "## PS Node" docs/260507-ps-refactor.md
grep -q "## PS Lite" docs/260507-ps-refactor.md
grep -q "## vana-sdk Integration" docs/260507-ps-refactor.md
grep -q "## Migration Sequence" docs/260507-ps-refactor.md
grep -q "## Validation Plan" docs/260507-ps-refactor.md
grep -q "## Risks" docs/260507-ps-refactor.md
grep -q "## Open TBDs" docs/260507-ps-refactor.md
grep -q "Node 22" docs/260507-ps-refactor.md
grep -q "@opendatalabs/vana-sdk/node" docs/260507-ps-refactor.md
grep -q "ps_unavailable" docs/260507-ps-refactor.md
grep -q "ps-node" docs/260507-ps-refactor.md
grep -q "ps-lite" docs/260507-ps-refactor.md
grep -q "grantId" docs/260507-ps-refactor.md
grep -q "https://github.com/Kahtaf/research/tree/main/browser-local-compute-runtime-poc" docs/260507-ps-refactor.md
```

Future implementation validation commands:

```bash
npm run lint
npm run lint:eslint
npm run format:check
npm test
npm run build
```

## Risks

- GitHub dependency for `@opendatalabs/vana-sdk` may not install the workspace package correctly from the monorepo, causing CI and local install failures.
- Node 22 baseline affects CI images, Docker runtime/base image assumptions, user install environments, and downstream consumers pinned to older Node versions.
- DPv2 grant and fee model details may remain underspecified, leading to rework in route contracts and authorization logic.
- PS Lite may over-scope beyond the PoC if MVP boundaries are not enforced, delaying compatibility-focused delivery.
- Migration across current config/index/data surfaces can mutate user state if sequencing and idempotency are not tightly controlled.
- SDK adapters and existing internal Gateway clients can drift if both remain active sources of truth during transition.
- Web3Signed canonicalization must match builder/client libraries exactly or requests may fail despite valid user intent.
- `vana-connect` can scope-creep into PS internals if adjacency boundaries are not enforced.

## Open TBDs

- Exact GitHub dependency syntax for the `@opendatalabs/vana-sdk` workspace package that is reliable in CI and lockfile installs.
- Final seed backup, recovery, and rotation model for key material across runtimes.
- Exact DPv2 fee-record API and verification payload shape used by read-time checks.
- Exact final route versioning policy: keep `/v1`, add `/v2`, or provide compatibility aliases.
- Exact package names and public exports for `ps-core`, `ps-node`, and `ps-lite` if they become real published packages.
- Exact PS Lite bridge/API server mechanism after deeper implementation-level PoC analysis.
