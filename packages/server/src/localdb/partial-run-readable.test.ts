import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createStreamSyncKeyPorts } from "../../../core/src/stream-sync/crypto.js";
import { createStorageStreamSyncBlobs } from "../../../core/src/stream-sync/blobs.js";
import type { StreamSyncBlobs } from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { StorageAdapter } from "../../../core/src/storage/adapters/interface.js";
import { DEFAULT_STORAGE_ACCESS_POLICY } from "../../../core/src/stream-sync/storage-retry.js";
import { createServer, type ServerContext } from "../bootstrap.js";
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

interface WorldOptions {
  /** Part size for published heads; small, to get a head of many parts. */
  partTargetBytes?: number;
  /** The blob store the server uses, built over the fixture's own storage. */
  blobs?: (raw: {
    get(key: string): Promise<Uint8Array | null>;
    put(key: string, bytes: Uint8Array): Promise<void>;
  }) => StreamSyncBlobs;
}

async function world(options: WorldOptions = {}) {
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
  remote.registry.post = async (post) => {
    const prior = remote.reads.get(post.scope);
    const version = prior?.found ? prior.version + 1 : 1;
    if (String(version) !== post.expectedVersion)
      return { kind: "conflict", latestVersion: String(version - 1) };
    remote.reads.set(post.scope, {
      found: true,
      version,
      dataHash: post.dataHash,
      metadataHash: post.metadataHash,
      deleted: false,
    });
    return { kind: "committed" };
  };
  vi.stubEnv("PS_ACCESS_TOKEN", "partial-run-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  const context = await createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      sync: { enabled: false },
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
      streamSyncBlobs: options.blobs?.(remote.storage) ?? remote.storage,
      ...(options.partTargetBytes === undefined
        ? {}
        : { streamSyncPartTargetBytes: options.partTargetBytes }),
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
      end: Record<string, unknown>,
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
      const response = await send(`/v1/stream-sync/runs/${id}/end`, "POST", {
        checkpointCandidate: {},
        lastBatch: records.length > 0 ? 0 : -1,
        ...end,
      });
      expect(response.status).toBe(200);
      return response.json();
    },
    async cycle() {
      const report = await (await context.getLocalSync!()).cycle();
      return report.connections.map((c) => c.error);
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

/**
 * The end request Desktop sends when a run fails after finishing some streams
 * (`EndRequest::body` in apps/desktop/src-tauri/src/commands/pdpp_stream_sync_run.rs,
 * built by `finish_plan(RunKind::CertifiedFailedDone | FailedDoneUpsertOnly)`
 * and `with_proven_full` in pdpp_runtime.rs): outcome `partial`, the covered
 * streams, the covered streams it read whole, and no cursor.
 */
const failedDone = (covered: string[], proven: string[]) => ({
  outcome: "partial",
  coveredStreams: covered,
  provenFullStreams: proven,
  checkpointCandidate: {},
});
const ALL = STREAMS.map(([name]) => name);
// Live shape: two streams finished and proven, two skipped for having no
// records, one failed and left retry-pending (not covered).
const FINISHED = ["profile", "following"];
const SKIPPED = ["posts", "post_likes"];
const upsertOnly = failedDone(ALL, []);

const SHAPES: {
  name: string;
  earlier: Record<string, unknown>[];
  end: ReturnType<typeof failedDone>;
}[] = [
  {
    name: "after an earlier upsert-only run left incomplete heads",
    earlier: [upsertOnly],
    end: failedDone([...FINISHED, ...SKIPPED], FINISHED),
  },
  {
    name: "as the first run of the connection",
    earlier: [],
    end: failedDone([...FINISHED, ...SKIPPED], FINISHED),
  },
  {
    name: "with the skipped siblings left out of the covered streams",
    earlier: [upsertOnly],
    end: failedDone(FINISHED, FINISHED),
  },
  {
    name: "after two earlier upsert-only runs",
    earlier: [upsertOnly, upsertOnly],
    end: failedDone([...FINISHED, ...SKIPPED], FINISHED),
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
      {
        outcome: "succeeded",
        coveredStreams: ALL,
        provenFullStreams: ALL,
      },
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
      failedDone(FINISHED, FINISHED),
    );
    await w.publish();
    // One cycle verifies each stream's published head.
    await w.publish();
    const reads = vi.spyOn(w.storage, "get");
    await w.publish();
    await w.publish();
    // A head blob is named by its data hash, so a verified head is never read
    // again. The storage service rejects a burst of reads, and a cycle that has
    // real work then fails before it posts anything.
    expect(reads).not.toHaveBeenCalled();
  });
});

/**
 * Storage as the dev service behaves: it serves about 25 reads in a burst and
 * then answers HTTP 500 until the rate recovers (measured against the dev
 * service: about 25 of 32 concurrent reads succeed, the rest get 500, and
 * about two reads a second are served without a failure). Time is virtual:
 * the client's backoff sleep advances the clock, so the test does not wait.
 */
function burstLimitedStorage(raw: {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, bytes: Uint8Array): Promise<void>;
}) {
  const BURST = 25;
  const REFILL_PER_SECOND = 2;
  let tokens = BURST;
  let clock = 0;
  let refilledAt = 0;
  const stats = { reads: 0, refused: 0, partUploads: 0 };
  const read = () => {
    stats.reads++;
    tokens = Math.min(
      BURST,
      tokens + ((clock - refilledAt) / 1000) * REFILL_PER_SECOND,
    );
    refilledAt = clock;
    if (tokens < 1) {
      stats.refused++;
      throw new Error(
        "vana-storage download failed: 500 Internal Server Error",
      );
    }
    tokens--;
  };
  const adapter: StorageAdapter = {
    urlForKey: (key) => key,
    async upload(key, bytes) {
      if (/-p-/.test(key)) stats.partUploads++;
      await raw.put(key, bytes);
      return key;
    },
    async download(url) {
      read();
      const bytes = await raw.get(url);
      if (bytes === null)
        throw new Error("vana-storage download failed: 404 Not Found");
      return bytes;
    },
    async exists(url) {
      read();
      return (await raw.get(url)) !== null;
    },
    async delete() {
      return true;
    },
  };
  // A fixed pseudo-random sequence keeps the jitter, and so the run, repeatable.
  let seed = 7;
  const random = () => {
    seed = (seed * 1_664_525 + 1_013_904_223) % 4_294_967_296;
    return seed / 4_294_967_296;
  };
  return {
    stats,
    blobs(over: { maxAttempts?: number } = {}) {
      return createStorageStreamSyncBlobs(adapter, {
        ...DEFAULT_STORAGE_ACCESS_POLICY,
        ...over,
        random,
        now: () => clock,
        sleep: async (ms) => {
          clock += ms;
        },
      });
    },
    /** Time passes between two sync cycles: the burst allowance returns. */
    rest: (ms: number) => {
      clock += ms;
    },
  };
}

describe("a stream of many parts publishes while storage refuses read bursts", () => {
  const ROWS = 24;
  // A part holds one or two rows at this size, so the following stream is a head of
  // about 25 parts, as in the live case.
  const PART_BYTES = 400;
  const whole = {
    outcome: "succeeded",
    coveredStreams: ALL,
    provenFullStreams: ALL,
  };

  async function twoPublishes(maxAttempts: number) {
    let storage!: ReturnType<typeof burstLimitedStorage>;
    const w = await world({
      partTargetBytes: PART_BYTES,
      blobs: (raw) => {
        storage = burstLimitedStorage(raw);
        return storage.blobs({ maxAttempts });
      },
    });
    // One cycle a minute: storage has recovered by the time the next starts.
    storage.rest(60_000);
    await w.run("first", 1_000, { profile: 1, following: ROWS }, whole, 0);
    storage.rest(60_000);
    const first = await w.cycle();
    // Every row changes, so the second publish downloads each base part.
    storage.rest(60_000);
    await w.run("second", 2_000, { profile: 1, following: ROWS }, whole, 1);
    storage.rest(60_000);
    const second = await w.cycle();
    storage.rest(60_000);
    return { w, storage, first, second };
  }

  it("publishes complete and serves 200 although reads are refused", async () => {
    const { w, storage, first, second } = await twoPublishes(6);
    // Two publishes of a head of about 25 parts need more reads than the burst
    // storage serves, so some were refused and retried.
    expect(storage.stats.partUploads).toBeGreaterThanOrEqual(2 * 20);
    expect(storage.stats.refused).toBeGreaterThan(0);
    expect(first).toEqual([null]);
    expect(second).toEqual([null]);
    expect(await w.listed()).toContain("pdpp.fixture-source.following");
    expect(await w.read("following")).toBe(200);
    expect(await w.read("profile")).toBe(200);
  });

  it("stalls the same publish when a refused read is not retried", async () => {
    const { w, storage, first, second } = await twoPublishes(1);
    expect(storage.stats.refused).toBeGreaterThan(0);
    // The failure is reported, and the stream stays at its first version.
    expect([...first, ...second].some((error) => error !== null)).toBe(true);
    expect(await w.read("following")).toBe(404);
  });
});
