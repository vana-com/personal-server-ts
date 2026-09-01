/**
 * Dev-only: run THIS repo's Personal Server against the Vana Desktop app's own
 * data root, so the query layer can answer questions about real connected
 * sources instead of the generated `dogfood` fixture corpus.
 *
 * Run it from the repo root, AFTER `npm run build`:
 *
 *   PERSONAL_SERVER_ROOT_PATH=~/.vana/desktop-dev/personal-server/moksha \
 *   PORT=8081 PS_ACCESS_TOKEN=... VANA_MASTER_KEY_SIGNATURE=0x... \
 *   INFERENCE_BASE_URL=... INFERENCE_MODEL=... INFERENCE_E2EE=false \
 *   node --env-file-if-exists=.env scripts/dev-serve-desktop-root.mjs
 *
 * The build is not optional: the OS-sandboxed script runner is resolved as
 * `packages/server/dist/query/runner.js` (`query/sandbox-tool-host.ts`), so a
 * source-only checkout cannot execute a single model-written script.
 *
 * ## Why this exists rather than `npm run dev`
 *
 * `packages/server/src/index.ts` resolves its config file as
 * `<root>/config.json`. The desktop sidecar
 * (`unity-surfaces/apps/desktop/personal-server/index.js`) instead passes
 * `configPath: <root>/server.json`, so a plain
 * `PERSONAL_SERVER_ROOT_PATH=... npm run dev` would:
 *
 *   - ignore the desktop's gateway / chain / contract / storage config,
 *   - WRITE a fresh defaults-derived `config.json` into the app's data root,
 *   - and boot with `tunnel.enabled: true` (the schema default), starting a
 *     second frpc tunnel for the same server identity.
 *
 * This script reads the desktop's `server.json`, forces off the three things
 * that must not be shared with the app (tunnel, sync, background services),
 * and passes the config object directly so `loadConfig` never runs and
 * therefore never rewrites `server.json`.
 *
 * NOT PRODUCTION and not part of the shipped package. Delete freely.
 *
 * ## One server per root
 *
 * The root holds a SQLite `index.db`. Stop the desktop app's own Personal
 * Server (in-app: Settings -> Personal Server -> Stop) BEFORE starting this,
 * or point this at a different root. Two writers on one root corrupt the
 * version ledger.
 *
 * ## Env
 *
 *   PERSONAL_SERVER_ROOT_PATH  required. The desktop root, e.g.
 *                              ~/.vana/desktop-dev/personal-server/moksha
 *   VANA_MASTER_KEY_SIGNATURE  required for any owner endpoint. A signature
 *                              over "vana-master-key-v1" by the owner wallet;
 *                              it decides whose server this is. Without it
 *                              every owner endpoint answers
 *                              500 SERVER_NOT_CONFIGURED.
 *   PS_ACCESS_TOKEN            required. The owner bearer token this server
 *                              accepts; paste the same value into the chat
 *                              page's token box.
 *   INFERENCE_*                the built-in defaults point at the Phala relay
 *                              with E2EE on. Override them when the key in
 *                              .env is a direct provider key.
 *   PORT                       optional, default 8081.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { startPersonalServer } from "../packages/server/dist/client.js";
import { resolveRootPath } from "../packages/server/dist/config/paths.js";

const rootPathInput = process.env.PERSONAL_SERVER_ROOT_PATH;
if (!rootPathInput) {
  console.error(
    "PERSONAL_SERVER_ROOT_PATH is required (the desktop app's data root).",
  );
  process.exit(1);
}
const rootPath = resolveRootPath(rootPathInput);
const port = Number.parseInt(process.env.PORT ?? "8081", 10);

/**
 * Prefer the file the desktop sidecar actually maintains.
 *
 * `server.json` carries the gateway URL, chain id, contract addresses and
 * storage host the app registered this server under. `config.json` keeps this
 * usable against a root made by `npm run dev`; `{}` keeps it usable against an
 * empty directory.
 */
async function readConfigFile() {
  for (const name of ["server.json", "config.json"]) {
    try {
      const text = await readFile(join(rootPath, name), "utf-8");
      return { raw: JSON.parse(text), from: name };
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
  }
  return { raw: {}, from: "<schema defaults>" };
}

const { raw, from } = await readConfigFile();
const parsed = ServerConfigSchema.parse(raw);

/**
 * The overrides that keep this process from fighting the app.
 *
 * `tunnel.enabled` defaults to true in the schema, and a second frpc for the
 * same server identity is exactly the kind of thing that only surfaces later
 * as a confusing gateway error. Sync is off for the same reason: this process
 * must not push versions the app's ledger does not know about.
 */
const config = {
  ...parsed,
  server: { ...parsed.server, port, origin: `http://localhost:${port}` },
  logging: { ...parsed.logging, pretty: true },
  devUi: { ...parsed.devUi, enabled: true },
  sync: { ...parsed.sync, enabled: false },
  tunnel: { ...parsed.tunnel, enabled: false },
};

if (!process.env.VANA_MASTER_KEY_SIGNATURE) {
  console.warn(
    "VANA_MASTER_KEY_SIGNATURE is not set — /v1/query/* will answer 500 SERVER_NOT_CONFIGURED.",
  );
}
if (!process.env.PS_ACCESS_TOKEN) {
  console.warn(
    "PS_ACCESS_TOKEN is not set — the chat page will have no bearer token to send.",
  );
}

console.log(`[dev-serve] root      ${rootPath}`);
console.log(`[dev-serve] config    ${from}`);
console.log(
  `[dev-serve] gateway   ${config.gateway.url} (chain ${config.gateway.chainId})`,
);
console.log(
  `[dev-serve] inference ${process.env.INFERENCE_BASE_URL ?? config.inference.baseUrl}`,
);
console.log(
  `[dev-serve] model     ${process.env.INFERENCE_MODEL ?? config.inference.model}`,
);
console.log("[dev-serve] sync / tunnel / background services: off");

const handle = await startPersonalServer({
  // Passed explicitly so `loadConfig` never runs, and so the desktop's
  // `server.json` is never rewritten with a normalized copy.
  config,
  rootPath,
  port,
  localApproval: false,
  // No gateway registration, no sync worker, no tunnel: this process reads the
  // root, it does not manage the server's on-chain identity.
  startBackgroundServices: false,
  ...(process.env.VANA_MASTER_KEY_SIGNATURE
    ? { ownerSignature: process.env.VANA_MASTER_KEY_SIGNATURE }
    : {}),
});

console.log(`[dev-serve] listening on http://localhost:${port}`);
console.log(
  `[dev-serve] scopes:  GET  http://localhost:${port}/v1/query/scopes`,
);
console.log(`[dev-serve] ask:     POST http://localhost:${port}/v1/query/ask`);

const shutdown = async (signal) => {
  console.log(`[dev-serve] ${signal} — stopping`);
  await handle.stop().catch(() => undefined);
  process.exit(0);
};
process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));
