import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";

// An old client's later legacy file stays recoverable, but never replaces a
// complete live view. All writes use the real legacy POST/storage path; all
// reads use the real service/importer. Only the authorization boundary is fake.
const SCOPE = "pdpp.acme.items";
const BUILDER = "0x000000000000000000000000000000000000bEEF";
const T0 = "2026-10-01T00:00:00.000Z";
// Fixture registers control at 00:00:01 and the first head at 00:00:02.
const HEAD_AT = "2026-11-01T00:00:02.000Z";
const LATER = ["2026-11-01T00:00:02.001Z", "2100-01-01T00:00:00.000Z"] as const;
const VIEW = [{ id: "shared", value: "view" }, { id: "view-only" }];
const LEGACY = [{ id: "shared", value: "legacy-new" }, { id: "legacy-only" }];
const OLD = [{ id: "pre-cutover", value: "keep-history" }];
const OTHER = [{ id: "must-not-serve", value: "foreign-or-incomplete" }];

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  const storage = createMemoryDataStorage();
  const service = await f.service();
  let now = T0;
  const authorizeBuilderRead = vi.fn(
    async ({ request }: { request: Request }) => ({
      builder: BUILDER,
      grantId: request.headers.has("x-test-grantee") ? "grant-1" : "owner",
    }),
  );
  const deps: PersonalServerDataApiDeps = {
    storage,
    streamSyncRead: service,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead,
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date(now),
    createLogId: () => "skew-log",
  };
  return {
    f,
    ns,
    storage,
    service,
    deps,
    at: (stamp: string) => {
      now = stamp;
    },
  };
}
type Rig = Awaited<ReturnType<typeof setup>>;

async function get(r: Rig, query = "", grantee = false) {
  // No connection/cursor: these are the public logical/stored/history routes.
  const response = await handlePersonalServerDataRequest(
    new Request(`https://ps.example.com/${SCOPE}${query}`, {
      headers: grantee ? { "x-test-grantee": "1" } : {},
    }),
    r.deps,
  );
  return {
    status: response.status,
    source: response.headers.get("x-vana-data-source"),
    cursor: response.headers.get("x-stream-sync-cursor"),
    body: await response.json(),
  };
}

function expectRows(
  read: Awaited<ReturnType<typeof get>>,
  source: string,
  rows: object[],
) {
  expect(read.status).toBe(200);
  expect(read.source).toBe(source);
  // Stream order is by primary-key hash, not input order. Equality of the
  // whole records array (after sorting) rejects extra rows AND wrong values.
  const ordered = (xs: object[]) =>
    [...xs].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  expect(ordered(read.body.data.records)).toEqual(ordered(rows));
}

async function stored(r: Rig, at: string) {
  const entry = r.storage.findEntry({ scope: SCOPE, at });
  expect(entry, `stored index row at ${at}`).toBeDefined();
  const envelope = await r.storage.readEnvelope(SCOPE, at);
  // MemoryDataStorage stores envelopes, not a byte-file. Digest the exact
  // serialization it uses for storage sizing; do not normalize payloads.
  const bytes = Buffer.from(JSON.stringify(envelope), "utf8");
  return {
    entry: structuredClone(entry),
    bytes: bytes.toString("base64"),
    digest: createHash("sha256").update(bytes).digest("hex"),
    data: structuredClone(envelope.data),
  };
}

async function post(r: Rig, at: string, records = LEGACY) {
  r.at(at); // Freeze the actual API ingest clock, not a forged collectedAt field.
  const response = await handlePersonalServerDataRequest(
    new Request(`https://ps.example.com/${SCOPE}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // An ordinary old-client body: no $pdpp/stream-sync metadata or supersede.
      body: JSON.stringify({ records }),
    }),
    r.deps,
  );
  expect(response.status).toBe(201);
  expect(await response.json()).toMatchObject({
    scope: SCOPE,
    collectedAt: at,
  });
  const snapshot = await stored(r, at);
  expect(snapshot.data).toEqual({ records });
  expect(snapshot.entry?.collectedAt).toBe(at);
  return snapshot;
}

async function publish(
  r: Rig,
  complete = true,
  records = VIEW,
  generation = 1,
) {
  const head = await r.f.publish({
    connector: "acme",
    ns: r.ns,
    stream: "items",
    generation,
    records,
    complete,
    observedAt: Date.parse(HEAD_AT),
  });
  await r.f.sync(r.service); // Real decrypt/verify/import/commit, not resolve mocking.
  return head;
}

function noOverlay(r: Rig) {
  expect(r.f.overlay.runs).toEqual([]);
  expect(r.f.overlay.open).toBe(0);
  expect(r.service.status().connections).toHaveLength(1);
}

async function completeThenLaterLegacy(at: string) {
  const r = await setup(91);
  // A real pre-cutover write makes accidental ingest-time history deletion
  // observable too. It is never deleted by the test or marked superseded.
  const old = await post(r, T0, OLD);
  expect(await r.f.activate("acme", r.ns)).toBe(1);
  const head = await publish(r);
  expect(head.head.complete).toBe(true);
  expect(r.f.rows.get(head.scope)?.addedAt).toBe(HEAD_AT);
  expect(r.f.overlay.acks).toContainEqual(
    expect.objectContaining({
      ns: r.ns,
      stream: "items",
      generation: 1,
      registryVersion: 1,
      dataHash: head.dataHash,
    }),
  );
  const imported = structuredClone(r.service.status());
  expect(imported.connections[0]?.streams.items).toMatchObject({
    live: true,
    complete: true,
    version: 1,
    records: VIEW.length,
  });
  const before = await get(r);
  expectRows(before, "stream-sync", VIEW);
  expect(before.cursor).not.toBeNull();
  expect(Date.parse(at)).toBeGreaterThan(head.head.observedAt);
  const later = await post(r, at);
  // Capture BEFORE logical reads, so neither reads nor POST can erase history.
  expect(await stored(r, T0)).toEqual(old);
  return { r, old, later, imported, cursor: before.cursor };
}

describe("old-client legacy writes after stream-sync cutover", () => {
  it.each(LATER)(
    "keeps a complete logical view after a newer legacy-only write (%s)",
    async (at) => {
      const { r, later, imported, cursor } = await completeThenLaterLegacy(at);
      for (const grantee of [false, true]) {
        const read = await get(r, "", grantee);
        expectRows(read, "stream-sync", VIEW);
        expect(read.cursor).toBe(cursor);
      }
      expect(r.service.status()).toEqual(imported);
      expect(await stored(r, at)).toEqual(later);
      noOverlay(r);
    },
  );

  it.each(LATER)(
    "retains the later legacy write for stored and history reads (%s)",
    async (at) => {
      // This includes the complete-view setup and actions on ONE storage instance, never a
      // separately seeded history fixture that could conceal a destructive POST.
      const { r, old, later, imported } = await completeThenLaterLegacy(at);
      for (const grantee of [false, true])
        expectRows(await get(r, "", grantee), "stream-sync", VIEW);
      // Before any stored/history read: those reads currently leave one overlay
      // snapshot open (pinned by the it.fails case below).
      noOverlay(r);
      expectRows(await get(r, "?view=stored"), "legacy", LEGACY);
      expectRows(
        await get(r, `?at=${encodeURIComponent(at)}`),
        "legacy",
        LEGACY,
      );
      expectRows(await get(r, `?at=${encodeURIComponent(T0)}`), "legacy", OLD);
      expect((await get(r, "?view=stored", true)).status).toBe(403);
      expect(await stored(r, at)).toEqual(later);
      expect(await stored(r, T0)).toEqual(old);
      expect(r.storage.countVersions(SCOPE)).toBe(2);
      expect(r.service.status()).toEqual(imported);
      expect(r.service.status().connections).toHaveLength(1);
    },
  );

  // Harm: after an owner's ?view=stored or ?at= read, one local-run snapshot
  // stays open until a later latest read, so the overlay logs it pins are not
  // released in the meantime. Served data is correct; only cleanup is deferred.
  it.fails(
    "an owner's stored-version and history reads release their overlay snapshot",
    async () => {
      const { r } = await completeThenLaterLegacy(LATER[0]);
      expectRows(await get(r, "?view=stored"), "legacy", LEGACY);
      expect(r.f.overlay.open).toBe(0);
      expectRows(
        await get(r, `?at=${encodeURIComponent(LATER[0])}`),
        "legacy",
        LEGACY,
      );
      expect(r.f.overlay.open).toBe(0);
    },
  );

  it.each(["absent", "incomplete"] as const)(
    "serves a new legacy write until a complete imported head exists (%s)",
    async (kind) => {
      const r = await setup(92);
      expect(await r.f.activate("acme", r.ns)).toBe(1);
      if (kind === "incomplete") {
        await publish(r, false, OTHER);
        expect(r.service.status().connections[0]?.streams.items).toMatchObject({
          live: true,
          complete: false,
          version: 1,
        });
      } else {
        await r.f.sync(r.service);
        expect(
          r.service.status().connections[0]?.streams.items,
        ).toBeUndefined();
      }
      const later = await post(r, LATER[0]);
      for (const grantee of [false, true])
        expectRows(await get(r, "", grantee), "legacy", LEGACY);
      await publish(r);
      for (const grantee of [false, true])
        expectRows(await get(r, "", grantee), "stream-sync", VIEW);
      expect(await stored(r, LATER[0])).toEqual(later);
      noOverlay(r);
      expectRows(await get(r, "?view=stored"), "legacy", LEGACY);
    },
  );

  it.each(["foreign-control", "foreign-head-key", "generation-2"] as const)(
    "serves legacy when the imported head is foreign or from another generation (%s)",
    async (kind) => {
      const r = await setup(93);
      const legacy = await post(r, T0);
      const foreign = await testOwnerKey(masterKey(94));
      if (kind === "foreign-control") {
        await r.f.activate("acme", r.ns, foreign);
        await r.f.publish({
          connector: "acme",
          ns: r.ns,
          stream: "items",
          generation: 1,
          records: OTHER,
          key: foreign,
        });
        await r.f.sync(r.service);
        expect(r.service.status().connections[0]?.control).toBe("foreign");
        expect(r.service.status().issues).toContainEqual(
          expect.objectContaining({
            ns: r.ns,
            stream: null,
            problem: "key_mismatch",
          }),
        );
      } else if (kind === "foreign-head-key") {
        await r.f.activate("acme", r.ns);
        await r.f.publish({
          connector: "acme",
          ns: r.ns,
          stream: "items",
          generation: 1,
          records: OTHER,
          encryptWith: foreign,
        });
        await r.f.sync(r.service);
        // The local active control cannot decrypt this foreign ciphertext.
        expect(r.service.status().issues).toContainEqual(
          expect.objectContaining({
            ns: r.ns,
            stream: "items",
            problem: "corrupt",
          }),
        );
      } else {
        await r.f.activate("acme", r.ns);
        await publish(r, true, OTHER);
        expect(r.service.status().connections[0]?.streams.items).toMatchObject({
          live: true,
          version: 1,
        });
        // Retain a genuinely imported generation-1 view, then register a newer
        // ACTIVE control (no deletion). This exercises the read-time liveness check;
        // merely rejecting a stale head during initial import would not do so.
        expect(await r.f.activate("acme", r.ns)).toBe(2);
        await r.f.sync(r.service);
      }
      for (const grantee of [false, true])
        expectRows(await get(r, "", grantee), "legacy", LEGACY);
      expect(r.service.status().connections[0]?.streams.items?.live).toBe(
        false,
      );
      expect(await stored(r, T0)).toEqual(legacy);
      noOverlay(r);
    },
  );
});
