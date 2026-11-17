import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createStreamSyncKeyPorts } from "../../../core/src/stream-sync/crypto.js";
import { createServer, type ServerContext } from "../bootstrap.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { remoteFixture } from "./apply-fixture.js";

const contexts: ServerContext[] = [];
const directories: string[] = [];
afterEach(async () => {
  for (const context of contexts.splice(0)) await context.cleanup();
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

const STREAMS = [
  ["profile", "singleton_presence"],
  ["following", "full_inventory"],
  ["posts", "full_inventory"],
  ["post_likes", "checkpoint_window"],
  ["ads", "full_inventory"],
] as const;

async function world() {
  const root = await mkdtemp(join(tmpdir(), "partial-run-"));
  directories.push(root);
  const declaration = JSON.stringify({
    source_id: "https://example.test/fixture-source",
    source_kind: "connector",
    version: "1",
    streams: STREAMS.map(([name]) => ({
      name,
      fields: ["id", "v"],
      required_fields: ["id"],
      primary_key: ["id"],
    })),
  });
  const manifest = JSON.stringify({
    connector_key: "fixture-source",
    version: "1",
    streams: STREAMS.map(([name, coverage]) => ({
      name,
      semantics: "mutable_state",
      primary_key: ["id"],
      coverage_strategy: coverage,
    })),
  });
  await writeFile(join(root, "declaration.json"), declaration);
  await writeFile(join(root, "manifest.json"), manifest);
  const digest = createHash("sha256").update(manifest).digest("hex");
  const signature = await privateKeyToAccount(
    `0x${"11".repeat(32)}`,
  ).signMessage({ message: "Disposable partial run fixture" });
  const remote = await remoteFixture(createStreamSyncKeyPorts(signature));
  vi.stubEnv("PS_ACCESS_TOKEN", "partial-run-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  const context = await createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      sync: { enabled: false },
      logging: { level: "fatal", pretty: false },
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
  const headers = { Authorization: "Bearer partial-run-fixture" };
  const send = (path: string, method: string, value: unknown) =>
    context.app.request(path, {
      method,
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify(value),
    });
  return {
    context,
    digest,
    storage: remote.storage,
    async run(
      id: string,
      observedAt: number,
      rows: Record<string, number>,
      end: EndShape,
      value = 0,
    ) {
      const begin = await send(`/v1/stream-sync/runs/${id}`, "PUT", {
        connector: "fixture-source",
        artifactDigest: digest,
        owner: { address: context.serverOwner!, leaseId: null },
        wantFull: true,
        observedAt,
      });
      expect(begin.status).toBe(200);
      const records = Object.entries(rows).flatMap(([stream, count]) =>
        Array.from({ length: count }, (_, i) => ({
          stream,
          data: { id: `${stream}-${i}`, v: value },
        })),
      );
      if (records.length > 0) {
        const batch = await send(`/v1/stream-sync/runs/${id}/batches`, "POST", {
          batch: 0,
          records,
        });
        expect(batch.status).toBe(200);
      }
      const response = await send(
        `/v1/stream-sync/runs/${id}/end`,
        "POST",
        endRequest({
          lastBatch: records.length > 0 ? 0 : -1,
          streams: ALL,
          live: Object.keys(rows).filter((stream) => rows[stream]! > 0),
          ...end,
        }),
      );
      expect(response.status).toBe(200);
      return response.json();
    },
    async publish() {
      const report = await (await context.getLocalSync!()).cycle();
      expect(report.connections.map((c) => c.error)).toEqual([null]);
    },
    async listed() {
      const response = await context.app.request("/v1/data?limit=100", {
        headers,
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        scopes: { scope: string }[];
      };
      return body.scopes.map((s) => s.scope);
    },
    async read(stream: string) {
      const response = await context.app.request(
        `/v1/data/pdpp.fixture-source.${stream}`,
        { headers },
      );
      await response.text();
      return response.status;
    },
  };
}

/** What the host saw of a run, beyond the records it sent. */
type EndShape = Omit<Parameters<typeof endRequest>[0], "lastBatch">;
const ALL: string[] = STREAMS.map(([name]) => name);
// Live shape: two streams finished and proven, two sent no records, and a
// failed DONE named ads as failed.
const FINISHED = ["profile", "following"];
const SKIPPED = ["posts", "post_likes"];
/** A failed DONE that named its failed stream, as Desktop reports it. */
const failedDone = (proven: string[], skipped: string[] = []): EndShape => ({
  finish: "certified_failed_done",
  observe: { ads: { failedInDone: true } },
  provenFullStreams: proven,
  skipped,
});
/** A failed DONE that named nothing: only its records count. */
const upsertOnly: EndShape = { finish: "failed_done_upsert_only" };

const SHAPES: {
  name: string;
  earlier: EndShape[];
  end: EndShape;
}[] = [
  {
    name: "after an earlier upsert-only run left incomplete heads",
    earlier: [upsertOnly],
    end: failedDone(FINISHED),
  },
  {
    name: "as the first run of the connection",
    earlier: [],
    end: failedDone(FINISHED),
  },
  {
    name: "with the siblings that sent nothing skipped",
    earlier: [upsertOnly],
    end: failedDone(FINISHED, SKIPPED),
  },
  {
    name: "after two earlier upsert-only runs",
    earlier: [upsertOnly, upsertOnly],
    end: failedDone(FINISHED),
  },
];

describe("a failed run's finished streams are served", () => {
  for (const shape of SHAPES) {
    it(`lists and reads the proven streams ${shape.name}`, async () => {
      const w = await world();
      let at = 1_000;
      for (const earlier of shape.earlier) {
        await w.run(
          `earlier-${at}`,
          at,
          { profile: 1, following: 19, ads: 3 },
          earlier,
        );
        await w.publish();
        at += 1_000;
      }
      // The run in question: two finished, two skipped, ads failed.
      expect(
        await w.run(
          `failed-done-${at}`,
          at,
          { profile: 1, following: 19 },
          shape.end,
        ),
      ).toMatchObject({ result: "queued" });
      await w.publish();
      const listed = await w.listed();
      expect(listed).toEqual(
        expect.arrayContaining([
          "pdpp.fixture-source.profile",
          "pdpp.fixture-source.following",
        ]),
      );
      expect(await w.read("profile")).toBe(200);
      expect(await w.read("following")).toBe(200);
      // The stream that failed is not served, however many earlier runs held it.
      expect(listed).not.toContain("pdpp.fixture-source.ads");
      expect(await w.read("ads")).toBe(404);
    });
  }

  it("keeps serving a complete stream when a later failed run only upserts", async () => {
    const w = await world();
    await w.run(
      "whole",
      1_000,
      { profile: 1, following: 19 },
      { provenFullStreams: ALL },
    );
    await w.publish();
    await w.run(
      "failed-upsert-only",
      2_000,
      { profile: 1, following: 20 },
      upsertOnly,
    );
    await w.publish();
    expect(await w.read("profile")).toBe(200);
    expect(await w.read("following")).toBe(200);
  });

  it("makes no storage read in a cycle that has nothing to publish", async () => {
    const w = await world();
    await w.run(
      "failed-done",
      1_000,
      { profile: 1, following: 19 },
      failedDone(FINISHED, SKIPPED),
    );
    await w.publish();
    // One cycle applies the log this device wrote.
    await w.publish();
    const reads = vi.spyOn(w.storage, "get");
    await w.publish();
    await w.publish();
    // A log segment is named by its data hash, so an applied position is
    // never read again.
    expect(reads).not.toHaveBeenCalled();
  });
});
