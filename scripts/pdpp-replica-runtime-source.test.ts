/** Offline declaration tests. Literal payloads below are NOT live connector output. */
import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseDeclaration } from "../packages/core/src/pdpp/declaration.js";
import { buildReplicaRuntimeSource } from "./pdpp-replica-runtime-source.js";

// Public declaration from strava-browser OCI
// sha256:026018b79ca78789326a6f14a88899e1f346cee04fcaba9afedc5b885f86804f;
// exact document SHA-256: 659b0e99f4a4284514c72989881dee56c0d72347f0cc77ddb5cf7fd9aa9851bb.
const document = readFileSync(
  new URL("./fixtures/strava-browser-source-declaration.json", import.meta.url),
  "utf8",
);
const sourceId = "https://registry.pdpp.dev/sources/strava";
const parsed = parseDeclaration(document, sourceId);
if (!parsed.ok) throw new Error(parsed.failure.code);
const descriptor = {
  declaration: parsed.snapshot,
  document,
  methodId: "strava-browser",
  connectionId: "strava:0x1111111111111111111111111111111111111111",
};

it("binds the exact retained Strava bytes, semantic revision and schema to the explicit connection", () => {
  const source = buildReplicaRuntimeSource(descriptor);
  expect(source.sourceId).toBe(sourceId);
  expect(source.declaration.digest).toBe(
    "659b0e99f4a4284514c72989881dee56c0d72347f0cc77ddb5cf7fd9aa9851bb",
  );
  expect(source.bindings[0].binding).toMatchObject({
    digest:
      "sha256:659b0e99f4a4284514c72989881dee56c0d72347f0cc77ddb5cf7fd9aa9851bb",
    version:
      "sha256:1cb31498813d5fc3fcd4c93c1513c3880305a939491a02047a5f0cfacbbd18e4",
    stream: "activities",
    primaryKey: ["id"],
    semantics: "mutable_state",
    schemaDigest:
      "sha256:a2d20ab840e5f73b23c05d46bc4e1688c76227859666c5588f2a97aa42558bc1",
  });
  const stream = source.declarations.forInstance(
    descriptor.connectionId,
    "activities",
  );
  expect(stream?.consentTimeField).toBe("start_date_local");
  expect(stream?.requiredFields).toEqual([
    "id",
    "start_date",
    "start_time",
    "start_time_basis",
    "freshness",
    "exported_at",
  ]);
  expect(source.declarations.forInstance("conn", "activities")).toBeUndefined();
  const literalTestPayload = {
    id: "offline-test-only",
    start_date: "2026-10-01",
    start_time: "2026-10-01T08:30:00",
    start_time_basis: "local",
    freshness: "live",
    exported_at: null,
  };
  expect(source.bindings[0].validateData(literalTestPayload)).toBe(true);
  expect(
    source.bindings[0].validateData({
      ...literalTestPayload,
      start_time_basis: "invented",
    }),
  ).toBe(false);
});

it("refuses a retained digest, schema or source changed independently of its document", () => {
  expect(() =>
    buildReplicaRuntimeSource({ ...descriptor, document: document + "\n" }),
  ).toThrow(/exact document bytes/);
  const changedSchema = structuredClone(descriptor.declaration);
  changedSchema.streams[0].schema = { type: "string" };
  expect(() =>
    buildReplicaRuntimeSource({ ...descriptor, declaration: changedSchema }),
  ).toThrow(/exact document bytes/);
  expect(() =>
    buildReplicaRuntimeSource({
      ...descriptor,
      declaration: {
        ...descriptor.declaration,
        source_id: "https://other.invalid/source",
      },
    }),
  ).toThrow(/invalid/);
  expect(() =>
    buildReplicaRuntimeSource({ ...descriptor, connectionId: "" }),
  ).toThrow(/owner-bound/);
  expect(() =>
    buildReplicaRuntimeSource({ ...descriptor, methodId: "" }),
  ).toThrow(/method/);
});

it("opens a real-source runtime without process fetch hooks and refuses fixture mutations", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { openReplicaRuntime, digest } =
    await import("./pdpp-replica-live-journey.js");
  const root = mkdtempSync(join(tmpdir(), "replica-source-test-"));
  const beforeFetch = globalThis.fetch;
  const runtime = await openReplicaRuntime({
    root,
    owner: "0x1111111111111111111111111111111111111111",
    master: Array(32).fill(1),
    serverKey: `0x${"01".repeat(32)}`,
    offlineRegistration: { serverId: `0x${"ab".repeat(32)}` },
    scriptSha256: digest(
      readFileSync(
        fileURLToPath(
          new URL("./pdpp-replica-live-journey.ts", import.meta.url),
        ),
      ),
    ),
    source: descriptor,
  });
  try {
    expect(globalThis.fetch).toBe(beforeFetch);
    expect(runtime.store.listConnections(sourceId)).toMatchObject([
      {
        instance: descriptor.connectionId,
        method: descriptor.methodId,
        generation: 1,
      },
    ]);
    expect(
      runtime.store.listConnections(
        "https://replica-journey.invalid/declaration",
      ),
    ).toEqual([]);
    expect(runtime.snapshot().ownerRows).toEqual([]);
    expect(runtime.snapshot().appRows).toEqual([]);
    expect(runtime.snapshot().canonicalRows).toEqual([]);
    for (const command of ["put", "blob", "delete", "reset"]) {
      await expect(
        runtime.call(command, { id: "never-stored", size: 1 }),
      ).rejects.toThrow(/Real-source runtime refuses synthetic/);
    }
    expect(runtime.snapshot().history).toBe(0);
    expect(runtime.snapshot().records).toEqual({});
  } finally {
    await runtime.close();
    expect(runtime.db.open).toBe(false);
    expect(globalThis.fetch).toBe(beforeFetch);
    rmSync(root, { recursive: true, force: true });
  }
});

it("runs the source descriptor through Device IPC and exposes only the separated resource server", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { Device, digest } = await import("./pdpp-replica-live-journey.js");
  const root = mkdtempSync(join(tmpdir(), "replica-source-ipc-test-"));
  const device = new Device({
    root,
    owner: "0x1111111111111111111111111111111111111111",
    master: Array(32).fill(1),
    serverKey: `0x${"01".repeat(32)}`,
    offlineRegistration: { serverId: `0x${"ab".repeat(32)}` },
    scriptSha256: digest(
      readFileSync(new URL("./pdpp-replica-live-journey.ts", import.meta.url)),
    ),
    source: descriptor,
    // No issuer is contacted: the test makes unauthenticated requests only.
    consent: {
      issuerOrigin: "http://127.0.0.1:1",
      credential: "unused-offline-test-credential",
    },
  });
  try {
    await device.start();
    const snapshot = await device.call("snapshot");
    expect(snapshot.canonicalRows).toEqual([]);
    expect(snapshot.records).toEqual({});
    expect(snapshot.history).toBe(0);
    const origin = await device.call<string>("resourceOrigin");
    expect(
      (await fetch(origin + "/pdpp/v1/owner/token", { method: "POST" })).status,
    ).toBe(404);
    expect(
      (
        await fetch(
          origin +
            "/pdpp/v1/streams/activities/records?instance=" +
            encodeURIComponent(descriptor.connectionId),
        )
      ).status,
    ).toBe(401);
    for (const command of ["put", "blob", "delete", "reset"])
      await expect(device.call(command)).rejects.toThrow(
        /Real-source runtime refuses synthetic/,
      );
  } finally {
    await device.kill();
    rmSync(root, { recursive: true, force: true });
  }
}, 15000);
