import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { keccak256, stringToHex } from "viem";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  replicaChainCommitment,
  type ReplicaRegistrationEvidence,
  type ReplicaTransportPort,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  fragmentReplicaPayload,
  replicaDigest,
  toBase64,
  type PreparedFragment,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  approveNarrowConsent,
  openConsentIssuer,
  openReplicaResourceServer,
} from "./pdpp-replica-quarantine-fixture.js";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "../storage/pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "../storage/pdpp-replication-transport.js";

// Local finalized-evidence injection exercises the real worker, SQLite receiver,
// issuer HTTP routes and token-bearing RS reads. This is not live chain proof.
const owner = "0x000000000000000000000000000000000000008b";
const sourceId = "https://replica-journey.invalid/declaration";
const at = "2026-10-20T00:00:00.000Z";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const alternateBinding = {
  ...binding,
  schemaDigest: `sha256:${"c".repeat(64)}`,
};
const secret = "QUARANTINED-PRIOR-PAYLOAD-8b-5";
const substituted = "CONFLICTING-PAYLOAD-MUST-NEVER-APPEAR-8b-6";
const blobBytes = Buffer.from(
  "quarantined binary sentinel 8b: \x00\x01\xff",
  "latin1",
);
const blobSha =
  "6bfd9ef772743dd1bc87d1457fdffd5e4b319880cba8ba23c443b187dcee6fdd";
const blobId = `sha256:${blobSha}`;
const controlText = "unaffected finalized control 8b";
const controlBytes = Buffer.from("independent control bytes 8b");
const controlId = replicaDigest(controlBytes);
const credential = "isolated-receiver-credential";
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function finalizedNetwork() {
  const fragments = new Map<string, PreparedFragment>();
  const evidence = new Map<string, ReplicaRegistrationEvidence>();
  const observed: string[] = [];
  function register(part: PreparedFragment) {
    fragments.set(part.scope, part);
    evidence.set(part.scope, {
      head: {
        owner,
        scope: part.scope,
        version: "1",
        dataHash: part.dataHash,
        metadataHash: part.metadataHash,
        deleted: false,
      },
      chain: {
        owner,
        scope: part.scope,
        version: "1",
        currentVersion: "1",
        status: "Active",
        commitment: replicaChainCommitment(part.dataHash, part.metadataHash),
        chainId: 14800,
        registry: `0x${"2".repeat(40)}`,
        blockNumber: 123n,
        blockHash: `0x${"3".repeat(64)}`,
        blockTimestamp: 1000n,
      },
      pending: false,
    });
  }
  // Codec identity is deliberate: crypto is covered by transport tests; here
  // finalized hash bindings and the authorization/read boundary are the oracle.
  const port: ReplicaTransportPort = {
    encrypt: async (_scope, bytes) => bytes,
    decrypt: async (_scope, bytes) => bytes,
    put: async () => {},
    register: async (part) => register(part),
    get: async (scope) => fragments.get(scope)!.encrypted,
    list: async () => ({ scopes: [...fragments.keys()], cursor: null }),
    evidence: async (scope) => {
      observed.push(scope);
      return evidence.get(scope) ?? { head: null, chain: null, pending: false };
    },
  };
  return { port, evidence, observed, register, fragments };
}

type Upsert = Extract<ReplicaOperation, { kind: "upsert" }>;
function record(
  id: string,
  text: string,
  counter: number,
  bytes: Buffer,
  idOfBlob: string,
): Upsert {
  const sha = idOfBlob.slice(7);
  return {
    kind: "upsert",
    owner,
    sourceId,
    connectionId: "conn",
    methodId: "collector",
    generation: 1,
    revision: { counter, writerId: "remote", operationId: `record-${id}` },
    declaration: binding,
    recordKey: id,
    emittedAt: at,
    data: {
      id,
      text,
      collected_at: at,
      private_note: "hidden-by-consent",
      blob_ref: {
        blob_id: idOfBlob,
        sha256: sha,
        size_bytes: bytes.length,
        mime_type: "application/octet-stream",
      },
    },
    blobs: [
      {
        blobId: idOfBlob,
        sha256: idOfBlob,
        sizeBytes: bytes.length,
        mimeType: "application/octet-stream",
      },
    ],
  };
}

async function fixture() {
  const root = mkdtempSync(join(homedir(), ".tmp/8b-quarantine-"));
  let db = new Database(join(root, "replica.sqlite"));
  let store = createSqliteRecordStore(db);
  const issuer = await openConsentIssuer(root, owner, 3600);
  let resource:
    Awaited<ReturnType<typeof openReplicaResourceServer>> | undefined;
  cleanups.push(async () => {
    await resource?.close();
    if (db.open) store.close();
    await issuer.close();
    rmSync(root, { recursive: true, force: true });
  });
  store.registerConnection({
    instance: "conn",
    sourceId,
    method: "collector",
    label: "local trusted mapping",
  });
  store.replication.beginBaseline({
    owner,
    declarations: [{ sourceId, binding }],
  });
  const network = finalizedNetwork();
  const target = record("z-quarantined", secret, 20, blobBytes, blobId);
  const control = record("a-control", controlText, 10, controlBytes, controlId);
  let trustedBindings = [binding, alternateBinding];
  const receiver = () =>
    createReplicaReceiver({
      db,
      store,
      owner,
      authenticate: (value) => (value === credential ? owner : undefined),
      declarations: () =>
        trustedBindings.map((b) => ({
          sourceId,
          binding: b,
          validateData: (data) => typeof data.id === "string",
        })),
    });
  // The resource server reads through the receiver the worker uses (#438).
  let activeReceiver: ReturnType<typeof createReplicaReceiver>;
  const worker = () =>
    createReplicaTransportWorker({
      db,
      enabled: true,
      expected: () => ({
        owner,
        declarations: trustedBindings.map((b) => ({
          sourceId,
          binding: b,
        })),
      }),
      exporter: store.replication,
      receiver: (activeReceiver = receiver()),
      credential,
      transport: network.port,
      now: () => time,
    });
  // Each cycle advances a fixed clock past the one-second first error backoff.
  let time = Date.parse(at);
  const advance = () => {
    time += 10_000;
    return transport.cycle();
  };
  let transport = worker();
  let batchIndex = 0;
  async function publish(
    operations: ReplicaOperation[],
    blobs: { blobId: string; bytes: Buffer }[] = [],
    runCycle = true,
  ) {
    const batch = (++batchIndex).toString(16).padStart(32, "0");
    const parts = await fragmentReplicaPayload({
      owner,
      writer: batch,
      batch,
      sequence: 1,
      previous: null,
      collectedAt: at,
      bytes: Buffer.from(
        canonicalJson({
          envelope: {
            format: "vana-pdpp-replica",
            version: 1,
            owner,
            batchId: batch,
            operations,
          },
          blobs: blobs.map((b) => ({
            blobId: b.blobId,
            bytes: toBase64(b.bytes),
          })),
        }),
      ),
      encrypt: network.port.encrypt,
    });
    for (const part of parts) network.register(part);
    if (runCycle) await advance();
    return parts;
  }
  const claim = (r: Upsert): ReplicaOperation => ({
    kind: "blob-claim",
    owner,
    sourceId,
    connectionId: "conn",
    methodId: "collector",
    generation: 1,
    revision: {
      counter: r.revision.counter - 1,
      writerId: "remote",
      operationId: `claim-${r.recordKey}`,
    },
    blob: r.blobs[0],
  });
  await publish(
    [
      {
        kind: "connection-register",
        owner,
        sourceId,
        connectionId: "conn",
        methodId: "collector",
        generation: 1,
        revision: {
          counter: 1,
          writerId: "remote",
          operationId: "registration",
        },
      },
      claim(control),
      control,
    ],
    [{ blobId: controlId, bytes: controlBytes }],
  );
  const targetParts = await publish(
    [claim(target), target],
    [{ blobId, bytes: blobBytes }],
  );
  const consent = await approveNarrowConsent(issuer);
  const start = async () => {
    resource = await openReplicaResourceServer(store, {
      owner,
      tokens: issuer.tokens,
      reads: (reader) => activeReceiver.readStore({ reader }),
    });
  };
  await start();
  async function read(path: string, init: RequestInit = {}) {
    return fetch(resource!.origin + "/pdpp/v1" + path, {
      ...init,
      headers: { authorization: `Bearer ${consent.token}`, ...init.headers },
    });
  }
  async function json(path: string) {
    const response = await read(path);
    expect(response.status).toBe(200);
    return response.json();
  }
  async function controlWorks() {
    expect((await json("/streams/messages/records/a-control")).data.text).toBe(
      controlText,
    );
    const response = await read(`/blobs/${encodeURIComponent(controlId)}`);
    expect(response.status).toBe(200);
    expect(Buffer.from(await response.arrayBuffer())).toEqual(controlBytes);
  }
  // Independent literal expectations make fixture/import failures distinct from
  // a denial: target and control must be readable with the actual issued token.
  expect(
    (await json("/streams/messages/records/z-quarantined")).data.text,
  ).toBe(secret);
  const binary = await read(`/blobs/${encodeURIComponent(blobId)}`);
  expect(binary.status).toBe(200);
  expect(Buffer.from(await binary.arrayBuffer())).toEqual(blobBytes);
  await controlWorks();
  const list = await json("/streams/messages/records?limit=1&order=asc");
  expect(list.data.map((r: { id: string }) => r.id)).toEqual(["a-control"]);
  expect(list.next_cursor).toBeTypeOf("string");
  const changes = await json(
    "/streams/messages/records?changes_since=&limit=1",
  );
  expect(changes.data.map((r: { id: string }) => r.id)).toEqual(["a-control"]);
  expect(changes.next_cursor).toBeTypeOf("string");
  const allChanges = await json("/streams/messages/records?changes_since=");
  expect(allChanges.next_changes_since).toBeTypeOf("string");
  // Every quarantine raises the connection's integrity epoch, so a saved
  // cursor expires instead of continuing over a shifted, filtered page set
  // (finding k: offset pagination skipped clean rows after a withdrawal).
  async function assertQuarantined() {
    const savedCursorStatus = 410;
    const paths = [
      ["/streams/messages/records/z-quarantined", 404],
      ["/streams/messages/records", 200],
      ["/streams/messages/records?changes_since=", 200],
      // A page cursor binds the reader's view revision for this connection
      // and stream. Retraction changes that revision, so the saved page
      // cursor always expires instead of continuing past the retracted key.
      [
        `/streams/messages/records?order=asc&limit=1&cursor=${encodeURIComponent(list.next_cursor)}`,
        410,
      ],
      // This is the supported retained-history read; there is no invented
      // historical-revision endpoint in this API.
      [
        `/streams/messages/records?changes_since=&limit=1&cursor=${encodeURIComponent(changes.next_cursor)}`,
        savedCursorStatus,
      ],
      [
        `/streams/messages/records?changes_since=${encodeURIComponent(allChanges.next_changes_since)}`,
        savedCursorStatus,
      ],
    ] as const;
    for (const [path, expectedStatus] of paths) {
      const response = await read(path);
      const body = await response.text();
      expect.soft(response.status, path).toBe(expectedStatus);
      if (expectedStatus === 410)
        expect.soft(JSON.parse(body).error.code, path).toBe("cursor_expired");
      expect.soft(body, path).not.toContain(secret);
      expect.soft(body, path).not.toContain(substituted);
      expect.soft(body, path).not.toContain("z-quarantined");
      expect.soft(body, path).not.toContain(blobId);
      if (path.endsWith("/z-quarantined"))
        expect.soft(response.status, path).toBe(404);
      if (
        response.status === 200 &&
        path !== "/streams/messages/records/z-quarantined"
      ) {
        const value = JSON.parse(body);
        expect.soft(value.has_more, path).toBe(false);
        expect.soft(value.next_cursor, path).toBeUndefined();
        expect
          .soft(
            value.data.every((r: { id: string }) => r.id === "a-control"),
            path,
          )
          .toBe(true);
      }
    }
    for (const init of [
      {},
      { method: "HEAD" },
      { headers: { range: "bytes=0-7" } },
    ]) {
      const response = await read(`/blobs/${encodeURIComponent(blobId)}`, init);
      const bytes = Buffer.from(await response.arrayBuffer());
      expect.soft(response.status, "quarantined blob GET/HEAD/range").toBe(404);
      expect
        .soft(bytes.includes(blobBytes.subarray(0, 8)), "blob sentinel bytes")
        .toBe(false);
      expect
        .soft(response.headers.get("content-type"))
        .not.toBe("application/octet-stream");
    }
  }
  return {
    network,
    target,
    targetParts,
    publish,
    assertQuarantined,
    controlWorks,
    cycle: advance,
    withdrawDeclarations() {
      trustedBindings = [];
    },
    clearPins(scope: string) {
      db.prepare(
        "UPDATE pdpp_transport_inbox SET data_hash=NULL,metadata_hash=NULL WHERE scope=?",
      ).run(scope);
    },
    pins: (scope: string) =>
      db
        .prepare(
          "SELECT data_hash,metadata_hash FROM pdpp_transport_inbox WHERE scope=?",
        )
        .get(scope) as {
        data_hash: string | null;
        metadata_hash: string | null;
      },
    async restart() {
      await resource!.close();
      resource = undefined;
      store.close();
      db = new Database(join(root, "replica.sqlite"));
      store = createSqliteRecordStore(db);
      transport = worker();
      await start();
    },
    quarantinedConnections: () =>
      db
        .prepare("SELECT instance FROM pdpp_replica_quarantined_connections")
        .all(),
    quarantineRows: () =>
      db.prepare("SELECT * FROM pdpp_replica_quarantined_keys").all(),
    inbox: () =>
      db
        .prepare("SELECT scope,state,error FROM pdpp_transport_inbox")
        .all() as { scope: string; state: string; error: string | null }[],
  };
}

describe("replica quarantine gates actual consent-authorized app reads", () => {
  it("P0 #5: old page/change cursors cannot recover payload after validated declaration equivocation, including restart", async () => {
    const f = await fixture();
    await f.publish([
      {
        ...f.target,
        declaration: alternateBinding,
        revision: {
          ...f.target.revision,
          counter: 21,
          operationId: "conflicting-declaration",
        },
        data: { ...f.target.data, text: substituted },
      },
    ]);
    expect(f.quarantineRows()).toEqual([
      {
        instance: "conn",
        generation: 1,
        stream: "messages",
        record_key: "z-quarantined",
      },
    ]);
    await f.assertQuarantined();
    await f.restart();
    await f.assertQuarantined();
    await f.controlWorks();
  });

  it("P0 #5: validated operation-ID equivocation also fences saved history across restart", async () => {
    const f = await fixture();
    await f.publish([
      { ...f.target, data: { ...f.target.data, text: substituted } },
    ]);
    expect(f.quarantinedConnections()).toEqual([{ instance: "conn" }]);
    await f.assertQuarantined();
    await f.restart();
    await f.assertQuarantined();
  });

  // Publishes and revalidates 55 slots: about 3-4 s alone, more under full-suite load.
  it("revalidates at most 50 retained slots per cycle and reaches all 55 staged slots", async () => {
    const f = await fixture();
    const staged: PreparedFragment[] = [];
    for (let index = 0; index < 55; index++)
      staged.push(...(await f.publish([f.target], [], false)));
    await f.cycle();
    await f.cycle();
    expect(
      staged.every(
        (part) =>
          f.inbox().find((row) => row.scope === part.scope)?.state ===
          "imported",
      ),
    ).toBe(true);
    for (const part of staged) {
      const previous = f.network.evidence.get(part.scope)!;
      f.network.evidence.set(part.scope, {
        ...previous,
        chain: { ...previous.chain!, currentVersion: "9" },
      });
    }
    for (let cycle = 0; cycle < 2; cycle++) {
      f.network.observed.length = 0;
      await f.cycle();
      // Only revalidation reads of the staged slots count against its quantum;
      // the clock now advances, so the fixture's own publish wait also polls.
      const scopes = new Set(staged.map((part) => part.scope));
      expect(
        f.network.observed.filter((scope) => scopes.has(scope)).length,
      ).toBeLessThanOrEqual(50);
    }
    expect(
      staged.every(
        (part) =>
          f.inbox().find((row) => row.scope === part.scope)?.state ===
          "quarantined",
      ),
    ).toBe(true);
    await f.assertQuarantined();
    await f.controlWorks();
  }, 30_000);

  it("pins legacy retained hash pairs only from the exact fragment and finalized commitment", async () => {
    const f = await fixture();
    const part = f.targetParts[0];
    const verified = f.network.evidence.get(part.scope)!;
    f.clearPins(part.scope);
    // An optimistic head cannot supply a durable pair while finality is absent.
    f.network.evidence.set(part.scope, {
      ...verified,
      chain: null,
      pending: true,
    });
    await f.cycle();
    expect(f.pins(part.scope)).toEqual({
      data_hash: null,
      metadata_hash: null,
    });
    f.network.evidence.set(part.scope, verified);
    // Even confirmed evidence cannot pin bytes differing from retained history.
    f.network.fragments.set(part.scope, {
      ...part,
      encrypted: Buffer.from("malformed substituted bytes"),
    });
    await f.cycle();
    expect(f.pins(part.scope)).toEqual({
      data_hash: null,
      metadata_hash: null,
    });
    f.network.fragments.set(part.scope, part);
    await f.cycle();
    expect(f.pins(part.scope)).toEqual({
      data_hash: part.dataHash,
      metadata_hash: part.metadataHash,
    });
    f.network.evidence.set(part.scope, {
      ...verified,
      chain: { ...verified.chain!, commitment: `0x${"f".repeat(64)}` },
    });
    await f.cycle();
    await f.assertQuarantined();
    await f.controlWorks();
  });

  it("retracts known immutable conflicts even after the original declaration is withdrawn", async () => {
    const f = await fixture();
    f.withdrawDeclarations();
    const part = f.targetParts[0];
    const previous = f.network.evidence.get(part.scope)!;
    f.network.evidence.set(part.scope, {
      ...previous,
      chain: { ...previous.chain!, currentVersion: "9" },
    });
    await f.cycle();
    expect
      .soft(f.inbox().find((row) => row.scope === part.scope)?.state)
      .toBe("quarantined");
    await f.assertQuarantined();
  });

  it.each([
    ["finalized immutable version", { currentVersion: "9" }],
    [
      "version-one commitment mismatch",
      { commitment: `0x${"f".repeat(64)}` as const },
    ],
    [
      "version-one tombstone commitment",
      {
        commitment: replicaChainCommitment(
          keccak256(stringToHex("vana.data-point.tombstone.v1")),
          keccak256(stringToHex("vana.data-point.tombstone.metadata.v1")),
        ),
      },
    ],
  ])(
    "P0 #6: revalidates an imported slot after %s and retracts only affected app data",
    async (_label, conflict) => {
      const f = await fixture();
      for (const part of f.targetParts) {
        const previous = f.network.evidence.get(part.scope)!;
        f.network.evidence.set(part.scope, {
          ...previous,
          chain: { ...previous.chain!, ...conflict },
        });
      }
      await f.cycle();
      for (const part of f.targetParts)
        expect
          .soft(
            f.inbox().find((r) => r.scope === part.scope)?.state,
            "known immutable conflict commits quarantine",
          )
          .toBe("quarantined");
      await f.assertQuarantined();
      await f.controlWorks();
      await f.restart();
      await f.cycle();
      await f.assertQuarantined();
      await f.controlWorks();
    },
  );
});
