/**
 * One-off local drain for BUI-540: runs the patched upload worker directly
 * against the REAL desktop PS state (~/data-connect/personal-server) so the
 * stuck 409 backlog clears without waiting for a canary + desktop release.
 *
 * Reads the owner-binding signature from the macOS keychain (same slot the
 * Vana app uses), derives the master key, and refuses to run unless the
 * recovered owner matches EXPECTED_OWNER. Quit the Vana app first (it shares
 * the index.db and would double-sync).
 *
 * Usage: npx tsx scripts/drain-local-540.ts
 */

import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  createGatewayClient,
  deriveMasterKey,
  recoverServerOwner,
} from "@opendatalabs/vana-sdk/node";
import { initializeDatabase } from "../packages/server/src/storage/index-schema.js";
import { createIndexManager } from "../packages/server/src/storage/index-manager.js";
import { createNodeDataStorage } from "../packages/server/src/storage/node-data-storage.js";
import { loadOrCreateServerAccount } from "../packages/server/src/keys/server-account.js";
import { createVanaSyncStorageAdapter } from "../packages/core/src/storage/adapters/index.js";
import { createServerSigner } from "../packages/core/src/signing/signer.js";
import { uploadAll } from "../packages/core/src/sync/workers/upload.js";
import { ServerConfigSchema } from "../packages/core/src/schemas/server-config.js";
import type { Hex } from "viem";

const EXPECTED_OWNER = "0x01b57c0ae1065908a33fdffaca6d4ff3bd1e7038";
const KEYCHAIN_SERVICE = "org.vana.dataconnect.owner-binding";
const KEYCHAIN_ACCOUNT = `vana_user_798ad7477a015118b873893b44b6036b::${EXPECTED_OWNER}`;

const CONFIG_DIR = join(homedir(), "data-connect", "personal-server");
const GATEWAY_URL = "https://dp-rpc-dev.vana.org";
const STORAGE_API_URL = "https://storage-dev.vana.org";

const logger = {
  info: (obj: unknown, msg?: string) => {
    const o = obj as Record<string, unknown>;
    console.log(`    ✓ ${msg ?? ""} ${o?.path ?? ""} v${o?.version ?? "?"}`);
  },
  error: (obj: unknown, msg?: string) => {
    const o = obj as Record<string, unknown>;
    console.log(`    ✗ ${msg ?? ""} ${o?.path ?? ""}: ${o?.error ?? ""}`);
  },
  warn: () => {},
  debug: () => {},
} as unknown as import("../packages/core/src/logger/index.js").Logger;

async function main(): Promise<void> {
  // 1. Owner-binding signature from the keychain (never via shell args/env).
  const raw = execFileSync(
    "security",
    [
      "find-generic-password",
      "-s",
      KEYCHAIN_SERVICE,
      "-a",
      KEYCHAIN_ACCOUNT,
      "-w",
    ],
    { encoding: "utf8" },
  ).trim();
  const entry = JSON.parse(raw) as { ownerBindingSignature: string };
  const ownerSignature = entry.ownerBindingSignature as Hex;

  const masterKey = deriveMasterKey(ownerSignature);
  const serverOwner = (await recoverServerOwner(
    ownerSignature,
  )) as `0x${string}`;
  if (serverOwner.toLowerCase() !== EXPECTED_OWNER) {
    throw new Error(
      `Recovered owner ${serverOwner} != expected ${EXPECTED_OWNER} — refusing to touch local state`,
    );
  }
  console.log(`owner verified: ${serverOwner}`);

  // 2. Real local state + real server identity.
  const config = ServerConfigSchema.parse({
    storage: { backend: "vana", config: { vana: { apiUrl: STORAGE_API_URL } } },
    gateway: { url: GATEWAY_URL, chainId: 14800 },
  });
  const db = initializeDatabase(join(CONFIG_DIR, "index.db"));
  const indexManager = createIndexManager(db);
  const storage = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir: join(CONFIG_DIR, "data") },
  });
  const serverAccount = loadOrCreateServerAccount(join(CONFIG_DIR, "key.json"));
  console.log(`server identity: ${serverAccount.address}`);
  const storageAdapter = createVanaSyncStorageAdapter({
    config,
    serverOwner,
    serverAccount,
  });
  const signer = createServerSigner(serverAccount, config.gateway);
  const gateway = createGatewayClient(GATEWAY_URL);

  // 3. Drain in batches until empty or a full pass makes no progress.
  let pass = 0;
  for (;;) {
    pass += 1;
    const before = storage.findUnsynced().length;
    if (before === 0) break;
    console.log(`\npass ${pass}: ${before} pending`);
    let errors = 0;
    await uploadAll(
      {
        storage,
        storageAdapter,
        gateway,
        signer,
        masterKey,
        serverOwner,
        logger,
      },
      {
        batchSize: 50,
        onError: (entry, err) => {
          errors += 1;
          console.log(`    ✗ ${entry.path}: ${err.message.slice(0, 110)}`);
        },
      },
    );
    const after = storage.findUnsynced().length;
    console.log(
      `pass ${pass} done: ${before} -> ${after} pending (${errors} errors)`,
    );
    if (after >= before) {
      console.log("\nNo progress this pass — stopping. Remaining entries:");
      for (const e of storage.findUnsynced({ limit: 10 })) {
        console.log(`  - ${e.path} (scope=${e.scope}, v${e.version})`);
      }
      break;
    }
  }

  const remaining = storage.findUnsynced().length;
  db.close();
  console.log(`\n${"═".repeat(50)}`);
  console.log(
    remaining === 0
      ? "✓ Backlog fully drained — all entries registered/adopted"
      : `! ${remaining} entries remain (see errors above)`,
  );
}

main().catch((err) => {
  console.error("drain failed:", err);
  process.exitCode = 1;
});
