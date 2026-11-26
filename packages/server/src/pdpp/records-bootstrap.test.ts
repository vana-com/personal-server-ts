import Database from "better-sqlite3";
import pino from "pino";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { PdppAuthRouteDeps } from "../routes/pdpp-auth.js";
import {
  createPdppRecordsDeps,
  legacyScopeRecords,
} from "./records-bootstrap.js";

const SERVER_OWNER = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const;
const OTHER_SUBJECT = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const DECLARATION: DeclarationSnapshot = {
  source_id: "https://registry.pdpp.dev/connectors/spotify",
  source_kind: "connector",
  version: "2026-08-11",
  digest: "sha256:test",
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name"],
      primary_key: ["id"],
      required_fields: ["id"],
    },
  ],
};

/** Only `tokens.resolveToken` is read by `createPdppRecordsDeps`. */
function fakePdppAuth(): PdppAuthRouteDeps {
  return {
    tokens: { resolveToken: () => ({ active: false }) },
  } as unknown as PdppAuthRouteDeps;
}

describe("createPdppRecordsDeps: instancesForSubject", () => {
  let db: Database.Database;
  beforeEach(() => {
    db = new Database(":memory:");
  });
  afterEach(() => db.close());
  it("does not mount record services without both an authorization server and an owner", () => {
    const options = {
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      replication: false,
      logger: pino({ level: "silent" }),
    };
    expect(
      createPdppRecordsDeps({ ...options, pdppAuth: undefined }),
    ).toBeUndefined();
    expect(
      createPdppRecordsDeps({ ...options, serverOwner: undefined }),
    ).toBeUndefined();
  });

  it("does not mount record services when retained sources declare no streams", () => {
    const deps = createPdppRecordsDeps({
      pdppAuth: fakePdppAuth(),
      declarations: [{ ...DECLARATION, streams: [] }],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      replication: false,
      logger: pino({ level: "silent" }),
      configuredMethods: [
        { sourceId: DECLARATION.source_id, methodId: "spotify" },
      ],
    });
    expect(deps).toBeUndefined();
  });

  it("returns account one and explicitly registered connections for the owner", () => {
    const deps = createPdppRecordsDeps({
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      replication: false,
      logger: pino({ level: "silent" }),
      configuredMethods: [
        { sourceId: DECLARATION.source_id, methodId: "spotify" },
      ],
    });
    expect(deps).toBeDefined();
    const connectionId = "conn_123e4567-e89b-42d3-a456-426614174000";
    deps!.bindingStore.registerConnection({
      instance: connectionId,
      sourceId: DECLARATION.source_id,
      method: "spotify",
      label: "Personal",
    });
    expect(deps!.instancesForSubject!(SERVER_OWNER)).toEqual(
      expect.arrayContaining([`spotify:${SERVER_OWNER}`, connectionId]),
    );
    expect(deps!.instancesForSubject!(SERVER_OWNER)).toHaveLength(2);
    expect(deps!.connectionLink!(connectionId, "top_artists")).toEqual({
      connector: "spotify",
      namespace: "",
    });
    expect(
      deps!.connectionLink!(`spotify:${SERVER_OWNER}`, "top_artists"),
    ).toEqual(deps!.connectionLink!(connectionId, "top_artists"));
    expect(deps!.connectionLink!(connectionId, "unselected")).toBeNull();
    deps!.bindingStore.deleteConnection(connectionId);
    expect(deps!.connectionLink!(connectionId, "top_artists")).toBeNull();
    expect(() =>
      deps!.bindingStore.registerConnection({
        instance: connectionId,
        sourceId: DECLARATION.source_id,
        method: "spotify",
        label: "again",
      }),
    ).toThrow();
    expect(
      deps!.connectionLink!(`spotify:${SERVER_OWNER}`, "top_artists"),
    ).toEqual({ connector: "spotify", namespace: "" });
  });

  it("links a registered browser method to its actual connector key instead of the source URL basename", () => {
    const declaration = {
      ...DECLARATION,
      source_id: "https://registry.pdpp.dev/sources/github",
    };
    const auth = fakePdppAuth();
    const deps = createPdppRecordsDeps({
      pdppAuth: auth,
      declarations: [declaration],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      replication: false,
      logger: pino({ level: "silent" }),
      configuredMethods: [
        { sourceId: declaration.source_id, methodId: "github-browser" },
      ],
    })!;
    const instance = "conn_123e4567-e89b-42d3-a456-426614174000";
    deps.bindingStore.registerConnection({
      instance,
      sourceId: declaration.source_id,
      method: "github-browser",
      label: "Personal",
    });
    expect(deps.connectionLink!(instance, "top_artists")).toEqual({
      connector: "github-browser",
      namespace: "",
    });
    expect(deps.sourceIdForConnector!("github-browser")).toBe(
      declaration.source_id,
    );
    expect(auth.resolveConnectionSourceId?.("github-browser")).toBe(
      declaration.source_id,
    );
    expect(auth.resolveConnectionSourceId?.("not-a-method")).toBeUndefined();
    expect(deps.sourceIdForConnector!("github")).toBeUndefined();
    expect(deps.connectionLink!(instance, "unselected")).toBeNull();
  });

  it("refuses qualified record links when a collector method is ambiguous across sources", () => {
    const sources = ["source-a", "source-b"].map((name) => ({
      ...DECLARATION,
      source_id: `https://registry.pdpp.dev/sources/${name}`,
    }));
    const auth = fakePdppAuth();
    const deps = createPdppRecordsDeps({
      pdppAuth: auth,
      declarations: sources,
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      replication: false,
      logger: pino({ level: "silent" }),
      configuredMethods: sources.map((source) => ({
        sourceId: source.source_id,
        methodId: "github-browser",
      })),
    })!;
    expect(deps.sourceIdForConnector!("github-browser")).toBeUndefined();
    expect(auth.resolveConnectionSourceId?.("github-browser")).toBeUndefined();
    for (const source of sources) {
      const instances = deps.instancesForSource!(
        SERVER_OWNER,
        source.source_id,
      );
      expect(instances).toHaveLength(1);
      expect(deps.connectionLink!(instances[0]!, "top_artists")).toBeNull();
    }
  });

  it("normalizes the server owner's address casing the same way subjectId is derived", () => {
    const deps = createPdppRecordsDeps({
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      replication: false,
      logger: pino({ level: "silent" }),
      configuredMethods: [
        { sourceId: DECLARATION.source_id, methodId: "spotify" },
      ],
    });
    const connectionId = "conn_123e4567-e89b-42d3-a456-426614174000";
    deps!.bindingStore.registerConnection({
      instance: connectionId,
      sourceId: DECLARATION.source_id,
      method: "spotify",
      label: "Personal",
    });
    expect(deps!.instancesForSubject!(SERVER_OWNER.toUpperCase())).toEqual(
      expect.arrayContaining([`spotify:${SERVER_OWNER}`, connectionId]),
    );
    expect(deps!.instancesForSubject!(SERVER_OWNER.toUpperCase())).toHaveLength(
      2,
    );
  });

  it("returns no instances for a different subject than the configured server owner", () => {
    // This deployment has exactly one owner. A caller presenting a DIFFERENT
    // subject must not be handed this owner's instances -- regression for
    // the factory previously ignoring its subject argument entirely and
    // returning every configured instance unconditionally.
    const deps = createPdppRecordsDeps({
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      replication: false,
      logger: pino({ level: "silent" }),
      configuredMethods: [
        { sourceId: DECLARATION.source_id, methodId: "spotify" },
      ],
    });
    expect(deps).toBeDefined();
    const instances = deps!.instancesForSubject!(OTHER_SUBJECT);
    expect(instances).toEqual([]);
  });

  it("restores a registered connection's configured method after restart", () => {
    const options = {
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      replication: false,
      logger: pino({ level: "silent" }),
      configuredMethods: [
        { sourceId: DECLARATION.source_id, methodId: "spotify" },
      ],
    };
    const firstBoot = createPdppRecordsDeps(options)!;
    const connectionId = "conn_123e4567-e89b-42d3-a456-426614174000";
    firstBoot.bindingStore.registerConnection({
      instance: connectionId,
      sourceId: DECLARATION.source_id,
      method: "spotify",
      label: "Work",
    });

    const nextBoot = createPdppRecordsDeps(options)!;
    expect(nextBoot.configuredMethods.get(connectionId)).toEqual(["spotify"]);
    expect(
      nextBoot.bindingStore
        .listConnections(DECLARATION.source_id)
        .map((item) => item.instance),
    ).toContain(connectionId);
  });
});

describe("createPdppRecordsDeps: readBlobBytes", () => {
  let db: Database.Database;
  beforeEach(() => {
    db = new Database(":memory:");
  });
  afterEach(() => db.close());

  it("reads bytes back through the actual wired store, not a hand-injected reader", async () => {
    const deps = createPdppRecordsDeps({
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      replication: false,
      logger: pino({ level: "silent" }),
    });
    expect(deps).toBeDefined();

    const bytes = new Uint8Array([1, 2, 3, 4]);
    const meta = deps!.store.storeBlobBytes(bytes, "application/octet-stream");

    const readBack = await deps!.readBlobBytes!(meta.blobId);
    expect(readBack).toBeDefined();
    expect(Array.from(readBack!)).toEqual(Array.from(bytes));
  });
});

describe("legacyScopeRecords blob bytes", () => {
  function readerFor(bytes: Uint8Array | undefined) {
    const deps = {
      bindingStore: {},
      reads: () => ({ getBlobBytes: () => bytes }),
    } as unknown as Parameters<typeof legacyScopeRecords>[0];
    return legacyScopeRecords(deps);
  }

  it("does not turn an absent blob into a zero-length payload", () => {
    expect(
      readerFor(undefined).getBlobBytes("synthetic-missing"),
    ).toBeUndefined();
  });

  it("returns an independently owned copy of shared-buffer data", () => {
    const shared = new Uint8Array(new SharedArrayBuffer(3));
    shared.set([1, 2, 3]);
    const returned = readerFor(shared).getBlobBytes("synthetic-blob");
    expect(returned?.buffer).toBeInstanceOf(ArrayBuffer);
    shared[0] = 9;
    expect(Array.from(returned ?? [])).toEqual([1, 2, 3]);
  });
});
