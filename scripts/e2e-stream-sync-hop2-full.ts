/**
 * Hop 2, full-server side: a normal full Personal Server on the real stack
 * (data-gateway on Postgres, blob store) reads a stream that a phone app
 * published through PS-Lite's run intake, and prints the record hashes.
 *
 * Start the stack first (scripts/stream-sync-real/up.sh), then:
 *   HOP2_SCOPE=pdpp.<connector>.<stream> HOP2_RECORDS='[{...}]' \
 *     npx tsx scripts/e2e-stream-sync-hop2-full.ts
 *
 * It waits up to HOP2_TIMEOUT_S seconds (default 360) for the scope to hold
 * the expected hashes, syncing from the registry on each pass. Exit 0 when
 * the hashes match. Unlike the real e2e it does not clear the registry,
 * because the phone registers itself first. Prints counts and truncated
 * hashes only, never record bodies or ids.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { privateKeyToAccount } from "viem/accounts";
import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer } from "../packages/server/src/bootstrap.js";
import { listenHttpServer } from "../packages/server/src/listen.js";
import {
  OWNER,
  OWNER_SIGNATURE,
  SERVER_KEY,
} from "../packages/server/src/stream-sync/oracle.test-utils.js";

const SCOPE = process.env.HOP2_SCOPE ?? "";
const hash = (value: unknown): string =>
  createHash("sha256")
    .update(canonicalJson(value as never))
    .digest("hex")
    .slice(0, 12);
// The records the phone was told to publish (JSON array), or their hashes.
const EXPECT = process.env.HOP2_RECORDS
  ? (JSON.parse(process.env.HOP2_RECORDS) as unknown[]).map(hash).sort()
  : (process.env.HOP2_EXPECT ?? "").split(",").filter(Boolean).sort();
const TIMEOUT_S = Number(process.env.HOP2_TIMEOUT_S ?? 360);
const PORT = Number(process.env.STREAM_SYNC_REAL_SERVER_PORT ?? 55453);
const TOKEN = "stream-sync-hop2-owner-token";
const CHAIN = 14800;

function stackEnv(): Record<string, string> {
  const file = join(
    process.env.STACK_DIR ??
      join(process.env.HOME ?? "", ".tmp/stream-sync-real-stack"),
    "env",
  );
  const out: Record<string, string> = {};
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const at = line.indexOf("=");
    if (at > 0) out[line.slice(0, at)] = line.slice(at + 1);
  }
  return out;
}

async function main(): Promise<number> {
  if (!SCOPE || EXPECT.length === 0) {
    throw new Error("set HOP2_SCOPE and HOP2_RECORDS (or HOP2_EXPECT)");
  }
  const env = stackEnv();
  const psql = (sql: string) =>
    execFileSync(
      "docker",
      [
        "exec",
        "-i",
        env.STREAM_SYNC_REAL_PG_NAME!,
        "psql",
        "-U",
        "gateway",
        "-d",
        "gateway",
        "-tAq",
        "-c",
        sql,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
  const root = await mkdtemp(join(tmpdir(), "stream-sync-hop2-"));
  const serverAccount = privateKeyToAccount(SERVER_KEY);
  process.env.PS_ACCESS_TOKEN = TOKEN;
  const config = ServerConfigSchema.parse({
    tunnel: { enabled: false },
    server: { port: PORT },
    gateway: { url: env.STREAM_SYNC_REAL_GATEWAY_URL, chainId: CHAIN },
    storage: {
      backend: "vana",
      config: { vana: { apiUrl: env.STREAM_SYNC_REAL_STORAGE_URL } },
    },
    sync: { enabled: true },
    streamSync: { write: true, read: true },
    logging: { level: "warn" },
  });
  const ctx = await createServer(config, {
    serverDir: join(root, "server"),
    dataDir: join(root, "server", "data"),
    ownerSignature: OWNER_SIGNATURE,
    serverAccount: {
      address: serverAccount.address,
      publicKey: serverAccount.publicKey,
      signMessage: (message: string) => serverAccount.signMessage({ message }),
      signTypedData: (params: unknown) =>
        serverAccount.signTypedData(
          params as Parameters<typeof serverAccount.signTypedData>[0],
        ),
    } as never,
  });
  const http = await listenHttpServer({
    fetch: ctx.app.fetch,
    port: PORT,
    hostname: "127.0.0.1",
  });
  psql(
    `insert into servers (id, owner_address, server_address, public_key, server_url, signature, status)
     values ('0x${"5e".repeat(32)}', '${OWNER}', '${serverAccount.address}', '0x04', 'http://127.0.0.1', '0x', 'confirmed')
     on conflict do nothing;`,
  );
  process.stdout.write("HOP2 full server ready\n");
  let last = "";
  let ok = false;
  const deadline = Date.now() + TIMEOUT_S * 1000;
  try {
    while (Date.now() < deadline && !ok) {
      await ctx.syncManager!.trigger().catch(() => undefined);
      const res = await fetch(`http://127.0.0.1:${PORT}/v1/data/${SCOPE}`, {
        headers: { authorization: `Bearer ${TOKEN}` },
      });
      const refusal =
        res.status === 200 ? "" : (await res.clone().text()).slice(0, 160);
      const records =
        res.status === 200
          ? (((await res.json()) as { data?: { records?: unknown[] } }).data
              ?.records ?? [])
          : [];
      const hashes = records.map(hash).sort();
      const line = `HOP2 full server read status=${res.status} count=${hashes.length} hashes=${hashes.join(",")}${refusal ? ` refusal=${refusal}` : ""}`;
      if (line !== last) process.stdout.write(`${line}\n`);
      last = line;
      ok = JSON.stringify(hashes) === JSON.stringify(EXPECT);
      if (!ok) await new Promise((r) => setTimeout(r, 4000));
    }
  } finally {
    await ctx.syncManager?.stop?.().catch(() => undefined);
    await new Promise<void>((resolve) => http.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  }
  process.stdout.write(
    `${ok ? "PASS" : "FAIL"} hop 2: full server read matches the phone (expected ${EXPECT.join(",")})\n`,
  );
  return ok ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    process.stderr.write(
      `hop2 reader crashed: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
    );
    process.exit(2);
  },
);
