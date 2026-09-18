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
  it("returns this deployment's instances for the configured server owner", () => {
    const deps = createPdppRecordsDeps({
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      logger: pino({ level: "silent" }),
    });
    expect(deps).toBeDefined();
    const instances = deps!.instancesForSubject!(SERVER_OWNER);
    expect(instances).toEqual([`spotify:${SERVER_OWNER.toLowerCase()}`]);
  });

  it("normalizes the server owner's address casing the same way subjectId is derived", () => {
    const deps = createPdppRecordsDeps({
      pdppAuth: fakePdppAuth(),
      declarations: [DECLARATION],
      db,
      serverOwner: SERVER_OWNER,
      resource: "https://ps.example.com",
      logger: pino({ level: "silent" }),
    });
    const instances = deps!.instancesForSubject!(SERVER_OWNER.toUpperCase());
    expect(instances).toEqual([`spotify:${SERVER_OWNER.toLowerCase()}`]);
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
    });
    expect(deps).toBeDefined();
    const instances = deps!.instancesForSubject!(OTHER_SUBJECT);
    expect(instances).toEqual([]);
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
