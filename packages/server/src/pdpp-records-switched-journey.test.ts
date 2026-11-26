/**
 * A switched owner's stream pages through the PDPP records route on a REAL
 * bootstrapped Node server: mint an owner bearer with the dev token at
 * `POST /pdpp/v1/owner/token`, then page `GET /v1/streams/:stream/records`.
 */
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createStreamSyncKeyPorts } from "../../core/src/stream-sync/crypto.js";
import { remoteFixture } from "./localdb/apply-fixture.test-utils.js";
import { createServer, type ServerContext } from "./bootstrap.js";
import { registerTestConnection } from "./pdpp/test-connections.js";

const SOURCE = "https://example.test/fixture-source";
const OTHER = "https://example.test/other-source";
const contexts: ServerContext[] = [];
const directories: string[] = [];
afterEach(async () => {
  for (const context of contexts.splice(0)) await context.cleanup();
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

const ITEMS = ["a", "b", "c", "d", "e"].map((id) => ({ id }));

async function boot() {
  const root = await mkdtemp(join(tmpdir(), "node-records-"));
  directories.push(root);
  vi.stubEnv("PS_ACCESS_TOKEN", "node-records-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  const signature = await privateKeyToAccount(
    `0x${"11".repeat(32)}`,
  ).signMessage({ message: "Disposable Node records fixture" });
  const declaration = (sourceId: string) =>
    JSON.stringify({
      source_id: sourceId,
      source_kind: "connector",
      version: "1",
      streams: [
        {
          name: "items",
          fields: ["id"],
          required_fields: ["id"],
          primary_key: ["id"],
        },
      ],
    });
  const manifest = (key: string) =>
    JSON.stringify({
      connector_key: key,
      version: "1",
      streams: [
        {
          name: "items",
          semantics: "mutable_state",
          primary_key: ["id"],
          coverage_strategy: "full_inventory",
        },
      ],
    });
  const methods = [];
  for (const [key, sourceId] of [
    ["fixture-source", SOURCE],
    ["other-source", OTHER],
  ] as const) {
    const declarationPath = join(root, `${key}.declaration.json`);
    const manifestPath = join(root, `${key}.manifest.json`);
    await writeFile(declarationPath, declaration(sourceId));
    await writeFile(manifestPath, manifest(key));
    methods.push({
      method_id: key,
      declaration_path: declarationPath,
      manifest_path: manifestPath,
      manifest_sha256: createHash("sha256").update(manifest(key)).digest("hex"),
    });
  }
  const remote = await remoteFixture(createStreamSyncKeyPorts(signature));
  await remote.head("items", ITEMS, { f: 1 });
  const context = await createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      sync: { enabled: false },
      logging: { level: "fatal", pretty: false },
      pdpp: {
        enabled: true,
        declarationPaths: methods.map((m) => m.declaration_path),
        methods,
      },
    }),
    {
      rootPath: root,
      ownerSignature: signature,
      accountModeStore: createMemoryModeRecordStore(),
      streamSyncRegistry: remote.registry,
      streamSyncBlobs: remote.storage,
    },
  );
  contexts.push(context);
  await context.accountModeAuthority.submitEvidence({
    owner: context.serverOwner!,
    state: "on",
  });
  await (await context.getLocalSync!()).apply();
  return context;
}

function read(context: ServerContext, token: string, query: string) {
  return context.app.request(`/v1/streams/items/records${query}`, {
    headers: { authorization: `Bearer ${token}` },
  });
}

describe("PDPP records on a switched Node server", () => {
  it("pages a switched stream with an owner bearer minted from the dev token", async () => {
    const context = await boot();
    const scoped = await registerTestConnection(
      context.app,
      context.devToken,
      context.serverOwner!,
      SOURCE,
      "fixture-source",
    );
    const seen: string[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 5; page++) {
      const response = await read(
        context,
        scoped,
        `?limit=2&order=asc${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
      );
      expect(response.status, await response.clone().text()).toBe(200);
      const body = await response.json();
      seen.push(...body.data.map((row: { id: string }) => row.id));
      cursor = body.next_cursor;
      if (!body.has_more) break;
    }
    expect(seen).toEqual(ITEMS.map((item) => item.id));
  });

  it("applies a source to a scoped token as narrowing only", async () => {
    const context = await boot();
    const scoped = await registerTestConnection(
      context.app,
      context.devToken,
      context.serverOwner!,
      SOURCE,
      "fixture-source",
    );
    expect((await read(context, scoped, "?source=fixture-source")).status).toBe(
      200,
    );
    expect((await read(context, scoped, `?source=${SOURCE}`)).status).toBe(200);
    const refused = await read(context, scoped, "?source=other-source");
    expect(refused.status).toBe(403);
    expect((await refused.json()).error.code).toBe("grant_stream_not_allowed");
  });
});
