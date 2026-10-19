import Database from "better-sqlite3";
import pino from "pino";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { PdppAuthRouteDeps } from "../routes/pdpp-auth.js";
import { createPdppRecordsDeps } from "./records-bootstrap.js";

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
  it("returns account one and explicitly registered connections for the owner", () => {
    const deps = createPdppRecordsDeps({
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
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
  });

  it("normalizes the server owner's address casing the same way subjectId is derived", () => {
    const deps = createPdppRecordsDeps({
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
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
