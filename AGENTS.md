# AGENTS.md

## Repo shape

- npm workspaces monorepo; use npm, not pnpm/yarn. Root build is `tsc --build` over `packages/core`, `packages/server`, `packages/cli`, and `scripts` via TS project references.
- Package boundaries matter: `core` owns protocol/auth/grants/storage/keys/gateway/sync; `server` owns the Hono HTTP app and runtime bootstrap; `cli` is only a facade re-exporting core config and server bootstrap.
- Public API is controlled by package `exports`; update `packages/*/package.json` when moving exported files or subpaths.

## Commands that are easy to guess wrong

- Install like CI: `npm ci`.
- Typecheck is named `npm run lint` (`tsc --noEmit`); ESLint is separate: `npm run lint:eslint`.
- Full local validation: `npm run lint && npm run lint:eslint && npm run format:check && npm test`.
- CI also requires `npm run build && npm test` on Node 20 and 22.
- Unit/integration tests: `npm test` (`packages/*/src/**/*.test.ts`). Focus with Vitest args, e.g. `npm test -- packages/server/src/routes/data.test.ts`.
- E2E tests are separate: `npm run test:e2e` (`tests/e2e/**/*.e2e.test.ts`, 15s timeout).
- `npm run dev` performs a full `tsc --build` before `tsx watch`; `npm start` rebuilds before running `packages/server/dist/index.js`.
- Server package build has an extra UI artifact step: `packages/server` runs `copy-ui` so `src/ui/index.html` lands in `dist/ui`.

## Runtime/config gotchas

- Default root namespace is `${PERSONAL_SERVER_ROOT_PATH:-~/personal-server}`; runtime writes `data/`, `config.json`, `index.db`, `key.json`, `logs/`, `tokens.json`, and possibly `bin/frpc*` under it.
- `loadConfig()` auto-creates/rewrites `config.json` with defaults, so simply starting the server can mutate the configured root.
- Cloud overrides (`SERVER_PORT`, `SERVER_ORIGIN`, `TUNNEL_ENABLED`, `DEV_UI_ENABLED`) only apply when `CLOUD_MODE=true`.
- `.env.example` contains a dev/test `VANA_MASTER_KEY_SIGNATURE`; without this, owner-restricted endpoints return server-not-configured errors and sync/tunnel are disabled.
- Dev UI is enabled by default in config, but it is mounted only when an ephemeral startup token is generated; restart rotates the token.
- Non-cloud startup may bind two listeners: the main server port and a loopback auth listener on `LOCAL_AUTH_PORT` or `server.port + 1`.
- Startup serves HTTP before slow background services finish; gateway registration and tunnel connection happen after listen.
- Tunnel requires `config.tunnel.enabled`, owner key material, and an on-demand frpc download. Missing prereqs degrade to local-only warnings; an unregistered server makes an established tunnel unroutable.

## Hono/server conventions

- Composition root is `packages/server/src/bootstrap.ts`; route mounting and global JSON error/404 shape live in `packages/server/src/app.ts`.
- Prefer adding route deps to `AppDeps`/route factory deps instead of importing singletons; tests instantiate routes with mocked deps.
- Auth is not only `Web3Signed`: owner routes can also authenticate via dev token, `PS_ACCESS_TOKEN`, or persisted CLI session tokens in `tokens.json`.
- Body limits are endpoint-specific: default helper is 1 MB, but data ingest uses 50 MB and structured 413 JSON.

## Testing/style conventions

- Tests are co-located as `foo.test.ts`; test utilities live under `packages/core/src/test-utils` and route tests build mock gateways/deps directly.
- Use red/green TDD for behavior changes and bug fixes: add one focused failing test through the public route/core API, make the minimal code change to pass, then repeat; do not batch-write imagined tests up front.
- ESLint enforces type-only imports and errors on unused vars unless prefixed with `_`; `no-explicit-any` is only a warning in source and disabled in tests.
- Root `.editorconfig` is 2-space, LF, final newline; Markdown allows trailing whitespace.
- Husky runs `lint-staged` pre-commit and commitlint on commit messages; PR titles are semantic-convention checked in GitHub Actions.

## Release/deploy/git notes

- `release.yml` is present but hard-disabled with `if: false`; canary prereleases publish from `main`, `develop`, and `feat/*` after build/test and rewrite package versions/pins for the publish job.
- Docker build intentionally replaces root `tsconfig.json` with references to only `core` and `server`; container defaults set `CLOUD_MODE=true`, `PERSONAL_SERVER_ROOT_PATH=/data`, `TUNNEL_ENABLED=false`, and `DEV_UI_ENABLED=false`.
- Use conventional commits for commit messages
