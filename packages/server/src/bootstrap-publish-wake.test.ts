/**
 * A run that ends with rows wakes the sync manager, so publish starts within
 * the notify debounce and does not wait for the 60 s poll.
 *
 * Real Node composition: HTTP intake, real SQLite, the real sync manager. Only
 * the registration check is stubbed (it asks the gateway) and the registry post
 * is the fixture's. The poll interval is the manager's default; the test never
 * advances time that far.
 */
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type * as SyncModule from "@opendatalabs/personal-server-ts-core/sync";
import { createStreamSyncKeyPorts } from "../../core/src/stream-sync/crypto.js";
import { remoteFixture } from "./localdb/apply-fixture.js";
import { createServer, type ServerContext } from "./bootstrap.js";

vi.mock(
  "@opendatalabs/personal-server-ts-core/sync",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SyncModule>();
    return {
      ...actual,
      createSyncManager: (
        ...args: Parameters<typeof actual.createSyncManager>
      ) =>
        actual.createSyncManager(args[0], args[1], {
          ...args[2],
          canSync: () => ({ ok: true }),
        }),
    };
  },
);

const contexts: ServerContext[] = [];
const directories: string[] = [];
afterEach(async () => {
  vi.useRealTimers();
  for (const context of contexts.splice(0)) await context.cleanup();
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

const POLL_MS = 60_000;
const headers = { Authorization: "Bearer publish-wake-fixture" };

async function world() {
  const root = await mkdtemp(join(tmpdir(), "publish-wake-"));
  directories.push(root);
  const declaration = JSON.stringify({
    source_id: "https://example.test/fixture-source",
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
  const manifest = JSON.stringify({
    connector_key: "fixture-source",
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
  await writeFile(join(root, "declaration.json"), declaration);
  await writeFile(join(root, "manifest.json"), manifest);
  const digest = createHash("sha256").update(manifest).digest("hex");
  const signature = await privateKeyToAccount(
    `0x${"11".repeat(32)}`,
  ).signMessage({ message: "Disposable publish wake fixture" });
  const remote = await remoteFixture(createStreamSyncKeyPorts(signature));
  const post = vi.fn(
    async (request: Parameters<typeof remote.registry.post>[0]) => {
      const prior = remote.reads.get(request.scope);
      const version = prior?.found ? prior.version + 1 : 1;
      remote.reads.set(request.scope, {
        found: true,
        version,
        dataHash: request.dataHash,
        metadataHash: request.metadataHash,
        deleted: false,
      });
      return { kind: "committed" as const };
    },
  );
  remote.registry.post = post;
  vi.stubEnv("PS_ACCESS_TOKEN", "publish-wake-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  const context = await createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      sync: { enabled: true },
      logging: { level: "fatal", pretty: false },
      streamSync: { write: true },
      pdpp: {
        enabled: true,
        declarationPaths: [join(root, "declaration.json")],
        methods: [
          {
            method_id: "fixture-source",
            declaration_path: join(root, "declaration.json"),
            manifest_path: join(root, "manifest.json"),
            manifest_sha256: digest,
          },
        ],
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
  const send = (path: string, method: string, value: unknown) =>
    context.app.request(path, {
      method,
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify(value),
    });
  const intake = (
    run: string,
    id: string,
    outcome: "succeeded" | "failed",
  ) => ({
    async finish() {
      const base = `/v1/stream-sync/runs/${run}`;
      const begin = await send(base, "PUT", {
        connector: "fixture-source",
        artifactDigest: digest,
        owner: { address: context.serverOwner!, leaseId: null },
        wantFull: true,
        observedAt: Date.now(),
      });
      expect(begin.status).toBe(200);
      const batch = await send(`${base}/batches`, "POST", {
        batch: 0,
        records: [{ stream: "items", data: { id } }],
      });
      expect(batch.status).toBe(200);
      return send(`${base}/end`, "POST", {
        outcome,
        coveredStreams: outcome === "succeeded" ? ["items"] : [],
        provenFullStreams: outcome === "succeeded" ? ["items"] : [],
        lastBatch: 0,
      });
    },
  });
  return { context, post, intake };
}

it("publishes within the notify debounce after a run ends, not at the next poll", async () => {
  const { context, post, intake } = await world();
  const local = await context.getLocalSync!();
  const cycle = vi.spyOn(local, "cycle");
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

  const end = await intake("wake", "item-1", "succeeded").finish();
  expect(end.status).toBe(200);
  expect(await end.json()).toMatchObject({ result: "queued" });
  expect(cycle).not.toHaveBeenCalled();

  // Past the 500 ms debounce, far short of the 60 s poll.
  await vi.advanceTimersByTimeAsync(600);
  expect(POLL_MS).toBeGreaterThan(600);
  expect(cycle).toHaveBeenCalledTimes(1);
  await cycle.mock.results[0]!.value;
  expect(post).toHaveBeenCalledTimes(1);
});
