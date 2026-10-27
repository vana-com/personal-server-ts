/**
 * Required regressions (oracle design §5). Each case names the defect it
 * pins. The large-blob and quarantine-write cases failed on PR #483 at
 * 555e2f94 and pass from eb98ded8.
 */
import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { createSqliteRecordStore } from "../pdpp-records-sqlite-store.js";
import { BINDINGS } from "./generator.test-utils.js";
import {
  blobPayload,
  liteDriver,
  liteMemoryPersistence,
  METHOD,
  nodeDriver,
  OWNER,
  SOURCE,
  sqliteDump,
  type BlobPayload,
  type ReplicaPortDriver,
} from "./ports.test-utils.js";

const MiB = 1024 * 1024;
const opened: ReplicaPortDriver[] = [];
afterEach(() => {
  for (const driver of opened.splice(0)) driver.close();
});

const base = (connection = "c1") => ({
  owner: OWNER,
  sourceId: SOURCE,
  connectionId: connection,
  methodId: METHOD,
  generation: 1,
});
const revision = (counter: number, operationId: string) => ({
  counter,
  writerId: "w-remote",
  operationId,
});
function blobRecord(
  blob: BlobPayload,
  key: string,
  counter: number,
): ReplicaOperation[] {
  return [
    {
      ...base(),
      kind: "blob-claim",
      blob: blob.descriptor,
      revision: revision(counter, `claim-${key}`),
    },
    {
      ...base(),
      kind: "upsert",
      declaration: BINDINGS.m,
      recordKey: key,
      emittedAt: "2026-10-20T00:00:00Z",
      data: { id: key, blob_ref: { blob_id: blob.descriptor.blobId } },
      blobs: [blob.descriptor],
      revision: revision(counter + 1, `record-${key}`),
    },
  ];
}
/** Deterministic bytes that differ in every 1 KiB block, so a misplaced chunk shows. */
function bytesOf(size: number, salt: number) {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++)
    bytes[i] = (i * 31 + (i >> 10) * 7 + salt) & 0xff;
  return bytes;
}
const sha = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");

function openNode() {
  const driver = nodeDriver({
    durable: true,
    declarations: [BINDINGS.m, BINDINGS.a],
    provisioned: ["c1", "c2"],
  });
  opened.push(driver);
  return driver;
}

describe("imported blobs stay readable from the flag-off store after reopen", () => {
  const sizes: [string, number][] = [
    ["1 MiB - 1", MiB - 1],
    ["1 MiB", MiB],
    ["1 MiB + 1", MiB + 1],
    ["2 MiB", 2 * MiB],
  ];
  for (const [label, size] of sizes)
    for (const path of ["import", "promotion"] as const)
      it(`${label} via ${path}`, async () => {
        const driver = openNode();
        const blob = blobPayload(
          bytesOf(size, size & 0xff),
          "application/octet-stream",
        );
        const ops = blobRecord(blob, "k1", 1);
        if (path === "import")
          await driver.importBatch("blob-batch", ops, [blob]);
        else {
          await driver.stage("blob-pending", ops, [blob]);
          await driver.promote("blob-pending");
        }
        // The replica reader serves the bytes before reopen.
        expect(
          sha(
            driver.receiver
              .readStore({ reader: "grant" })
              .getBlobBytes(blob.descriptor.blobId)!,
          ),
        ).toBe(sha(blob.bytes));
        driver.store.close();
        const db = new Database(driver.path);
        try {
          const plain = createSqliteRecordStore(db);
          const bytes = plain.getBlobBytes(blob.descriptor.blobId);
          expect(bytes?.length).toBe(size);
          expect(sha(bytes!)).toBe(sha(blob.bytes));
          expect(`sha256:${sha(bytes!)}`).toBe(blob.descriptor.sha256);
        } finally {
          db.close();
        }
      });
});

describe("terminal quarantine rejects every mutating path and changes nothing", () => {
  const live = (driver: ReplicaPortDriver) =>
    driver.importBatch(
      "live",
      [
        {
          ...base(),
          generation: 1,
          kind: "connection-register",
          revision: revision(1, "register"),
        } as const,
        {
          ...base(),
          kind: "upsert",
          declaration: BINDINGS.m,
          recordKey: "k1",
          emittedAt: "2026-10-20T00:00:00Z",
          data: { id: "k1", text: "before" },
          blobs: [],
          revision: revision(2, "put"),
        },
      ],
      [],
    );

  const nodeCases: [
    string,
    (driver: ReturnType<typeof openNode>) => unknown,
  ][] = [
    ["deleteConnection", (driver) => driver.store.deleteConnection("c1")],
    [
      "resetInstanceBinding",
      (driver) =>
        driver.store.resetInstanceBinding({
          instance: "c1",
          expectedMethod: METHOD,
          expectedGeneration: 1,
          nextMethod: METHOD,
        }),
    ],
    [
      "storeBlobBytesForInstance",
      (driver) =>
        driver.store.storeBlobBytesForInstance({
          instance: "c1",
          method: METHOD,
          generation: 1,
          bytes: new TextEncoder().encode("after quarantine"),
          mimeType: "text/plain",
        }),
    ],
  ];
  for (const [name, mutate] of nodeCases)
    it(`Node ${name}`, async () => {
      const driver = openNode();
      await live(driver);
      await driver.quarantineConnection("c1");
      const before = sqliteDump(driver.db);
      expect(before.pdpp_replica_quarantined_connections?.length).toBe(1);
      expect(() => mutate(driver)).toThrow();
      expect(sqliteDump(driver.db)).toEqual(before);
    });

  const blob = blobPayload(
    new TextEncoder().encode("after quarantine"),
    "text/plain",
  );
  const liteCases: [string, Record<string, unknown>][] = [
    [
      "record",
      {
        ...base(),
        kind: "upsert",
        declaration: BINDINGS.m,
        recordKey: "k2",
        emittedAt: "2026-10-22T00:00:00Z",
        data: { id: "k2", text: "after" },
        blobs: [],
      },
    ],
    [
      "lifecycle",
      {
        ...base(),
        generation: 2,
        kind: "connection-reset",
        previousGeneration: 1,
      },
    ],
    ["blob claim", { ...base(), kind: "blob-claim", blob: blob.descriptor }],
  ];
  for (const [name, draft] of liteCases)
    it(`Lite commitLocal ${name}`, async () => {
      const driver = await liteDriver({
        name: "lite-memory",
        persistence: liteMemoryPersistence(),
        declarations: [BINDINGS.m, BINDINGS.a],
        provisioned: ["c1", "c2"],
      });
      opened.push(driver);
      await live(driver);
      await driver.quarantineConnection("c1");
      const before = driver.persistence.dump();
      await expect(
        driver.store.commitLocal("after-quarantine", [draft as never]),
      ).rejects.toThrow();
      expect(driver.persistence.dump()).toEqual(before);
    });
});

/**
 * Defects the differential found on PR #483 at eb98ded8. Each case is the
 * shrinker's minimized command list and runs on both ports.
 */
describe("oracle findings on #483", () => {
  const UNIVERSE = {
    connections: ["c1", "c2", "c3"],
    streams: [{ stream: "messages" }, { stream: "events" }],
    keys: ["k0", "k1", "k2", "k3"],
  };
  const upsert = (
    connection: string,
    key: string,
    text: string,
    rev: [number, string],
  ) =>
    ({
      ...base(connection),
      kind: "upsert",
      declaration: BINDINGS.m,
      recordKey: key,
      emittedAt: "2026-10-20T00:00:49Z",
      data: { id: key, text },
      blobs: [],
      revision: revision(rev[0], rev[1]),
    }) as const satisfies ReplicaOperation;
  const ports = {
    node: async () => openNode(),
    lite: async () => {
      const driver = await liteDriver({
        name: "lite-memory",
        persistence: liteMemoryPersistence(),
        declarations: [BINDINGS.m, BINDINGS.a],
        provisioned: ["c1", "c2"],
      });
      opened.push(driver);
      return driver;
    },
  };
  const cases: [
    string,
    (open: () => Promise<ReplicaPortDriver>) => Promise<void>,
  ][] = [
    [
      // Seed 1401181199. One revision id carries different content on a
      // provisioned and an unprovisioned connection: equivocation withdraws both.
      "D1: equivocation with an unprovisioned connection withdraws the provisioned one",
      async (open) => {
        const driver = await open();
        await driver.importBatch(
          "batch-12",
          [
            upsert("c2", "k2", "t0", [1, "w-b-0"]),
            upsert("c3", "k2", "t2-changed", [1, "w-b-0"]),
          ],
          [],
        );
        const { grant } = await driver.snapshot(UNIVERSE);
        expect(grant.point).toEqual({});
        expect(grant.list).toEqual({});
      },
    ],
    [
      // Seed 387276957. Terminal quarantine is absorbing: a later import for
      // another connection must not rewrite the quarantined tombstone.
      "D2: a later import leaves a quarantined connection's tombstone unchanged",
      async (open) => {
        const driver = await open();
        await driver.importBatch(
          "batch-1",
          [
            {
              ...base(),
              kind: "delete",
              declaration: BINDINGS.m,
              recordKey: "k2",
              emittedAt: "2026-10-20T00:00:00Z",
              deletedAt: "2026-10-21T00:00:14Z",
              revision: revision(3, "w-d-2"),
            },
          ],
          [],
        );
        await driver.quarantineConnection("c1");
        const before = (await driver.snapshot(UNIVERSE)).stored;
        await driver.importBatch(
          "batch-6",
          [upsert("c2", "k0", "t2", [6, "w-b-5"])],
          [],
        );
        const after = (await driver.snapshot(UNIVERSE)).stored;
        expect(after['["c1","messages","k2"]']).toEqual(
          before['["c1","messages","k2"]'],
        );
        expect(after['["c1","messages","k2"]']).toMatchObject({
          version: 1,
          deletedAt: "2026-10-21T00:00:14Z",
        });
      },
    ],
    [
      // Seed 387276957, replayed. The upsert's blob bytes never arrive, so the
      // winner is withdrawn. Withdrawal must not rewrite the delete's tombstone.
      "D2b: a withdrawn upsert leaves an existing tombstone unchanged",
      async (open) => {
        const driver = await open();
        await driver.provision("c3");
        await driver.importBatch(
          "batch-5",
          [
            {
              ...base("c3"),
              kind: "delete",
              declaration: BINDINGS.m,
              recordKey: "k0",
              emittedAt: "2026-10-20T00:00:00Z",
              deletedAt: "2026-10-21T00:00:11Z",
              revision: revision(7, "w-c-12"),
            },
          ],
          [],
        );
        const before = (await driver.snapshot(UNIVERSE)).stored;
        const [, record] = blobRecord(
          blobPayload(new TextEncoder().encode("oracle blob d2")),
          "k0",
          11,
        );
        await driver.importBatch("batch-9", [record], []);
        expect((await driver.snapshot(UNIVERSE)).stored).toEqual(before);
      },
    ],
    [
      // Seed 147926629. Pending bytes and claim make a confirmed record
      // readable for the owner; the row is not confirmed, so it is marked.
      "D3: a row readable only through pending bytes carries the pending marker",
      async (open) => {
        const driver = await open();
        const blob = blobPayload(new TextEncoder().encode("oracle blob b0"));
        const [claim, record] = blobRecord(blob, "k3", 14);
        await driver.importBatch("batch-12", [record], []);
        await driver.stage("pending-10", [claim], [blob]);
        const { owner, grant } = await driver.snapshot(UNIVERSE);
        expect(grant.point).toEqual({});
        expect(Object.keys(owner.point)).toEqual(['["c1","messages","k3"]']);
        expect(owner.pending).toEqual(['["c1","messages","k3"]']);
      },
    ],
  ];
  for (const [name, run] of cases) {
    it(`Lite ${name}`, () => run(ports.lite));
    it(`Node ${name}`, () => run(ports.node));
  }
});
