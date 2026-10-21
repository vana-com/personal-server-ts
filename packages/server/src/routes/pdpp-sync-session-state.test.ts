/**
 * Candidate sync sessions keep their state on the server behind fixed-length
 * handles. A request scans until it has a visible page or reaches the end;
 * when its work or time budget runs out first it answers one uniform
 * retryable 429 and the next try resumes where the scan stopped.
 */
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
  type PdppRecordStore,
  type SyncSessionOptions,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type {
  Grant,
  StreamGrant,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";
import { pdppRecordsRoutes } from "./pdpp-records.js";

const CANDIDATE = "0.1.0-candidate";
const INSIDE = "2026-02-01T00:00:00Z";

type Body = {
  data: Array<{ id: string; deleted?: boolean; data?: unknown }>;
  has_more: boolean;
  next_cursor?: string;
  next_changes_since?: string;
  error?: { code: string; type?: string };
};

function grant(
  overrides: Partial<StreamGrant> = {},
  subject = "owner-a",
): Grant {
  return {
    version: CANDIDATE,
    grant_id: `G-${subject}`,
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: subject },
    client: { client_id: "client" },
    source: { kind: "connector", id: "src" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [
      {
        name: "s",
        instance_ids: ["i"],
        fields: ["id", "name"],
        required_fields: ["id"],
        time_constraint: {
          field: "t",
          type: "date-time",
          since: "2026-01-01T00:00:00Z",
        },
        ...overrides,
      },
    ],
  };
}

const opened: PdppRecordStore[] = [];
afterEach(() => {
  for (const store of opened.splice(0)) store.close();
});

function harness(
  backend: string,
  grants: Record<string, Grant>,
  syncSession: SyncSessionOptions = {},
) {
  const store =
    backend === "memory"
      ? createMemoryRecordStore()
      : createTestBoundRecordStore(new Database(":memory:"));
  opened.push(store);
  let examined = 0;
  const counting: PdppRecordStore = {
    ...store,
    readSyncWindow: (stream, request, read) =>
      store.readSyncWindow(stream, request, (window) =>
        read({
          ...window,
          changes: (direction, after) => {
            const source = window.changes(direction, after);
            return (function* () {
              for (const change of source) {
                examined += 1;
                yield change;
              }
            })();
          },
        }),
      ),
  };
  const auth = createFixtureAuthorizationService(
    Object.fromEntries(
      Object.entries(grants).map(([token, g]) => [
        token,
        {
          active: true,
          tokenKind: "client" as const,
          subjectId: g.subject.id,
          clientId: g.client.client_id,
          grant: g,
        },
      ]),
    ),
  );
  const app = pdppRecordsRoutes({
    store: counting,
    auth,
    declarations: createStreamDeclarationRegistry([
      {
        name: "s",
        semantics: "mutable_state",
        primaryKey: ["id"],
        requiredFields: ["id"],
        cursorField: "emitted_at",
      },
    ]),
    syncSession,
  });
  let clock = 0;
  return {
    examined: () => examined,
    async get(query: Record<string, string | undefined>, token = "g1") {
      const search = new URLSearchParams();
      for (const [key, value] of Object.entries(query))
        if (value !== undefined) search.set(key, value);
      const response = await app.request(`/streams/s/records?${search}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return {
        status: response.status,
        retryAfter: response.headers.get("Retry-After"),
        body: (await response.json()) as Body,
      };
    },
    put(key: string, name = "N") {
      clock += 1;
      store.ingestBatch(
        [
          {
            instance: "i",
            stream: "s",
            key,
            data: { id: key, name, t: INSIDE },
            emitted_at: new Date(
              Date.UTC(2026, 3, 1, 0, 0, clock),
            ).toISOString(),
          },
        ],
        () => "mutable_state",
        () => ["id"],
      );
    },
    remove(key: string) {
      clock += 1;
      store.deleteRecord(
        "i",
        "s",
        key,
        new Date(Date.UTC(2026, 3, 1, 0, 0, clock)).toISOString(),
        "mutable_state",
      );
    },
  };
}

type Harness = ReturnType<typeof harness>;

/** Repeats a request through 429 retries; returns every response seen. */
async function untilServed(
  h: Harness,
  query: Record<string, string | undefined>,
  token = "g1",
) {
  const responses = [];
  for (let attempt = 0; attempt < 50; attempt++) {
    const response = await h.get(query, token);
    responses.push(response);
    if (response.status !== 429) return { final: response, responses };
  }
  throw new Error("never served");
}

for (const backend of ["memory", "sqlite"])
  describe(`${backend}: server-side candidate sync sessions`, () => {
    it("never answers an empty page that says more remains", async () => {
      const h = harness(
        backend,
        { g1: grant({ resources: ["z"] }) },
        { maxExaminedPerRequest: 3 },
      );
      for (let n = 0; n < 7; n++) h.put(`hidden${n}`);
      h.put("z");
      const { final, responses } = await untilServed(h, {
        changes_since: "beginning",
        limit: "5",
        order: "asc",
      });
      for (const response of responses) {
        if (response.status === 200)
          expect(response.body.data.length > 0 || !response.body.has_more).toBe(
            true,
          );
      }
      expect(final.status).toBe(200);
      expect(final.body.data.map((r) => r.id)).toEqual(["z"]);
      expect(final.body.has_more).toBe(false);
      expect(final.body.next_changes_since).toBeTruthy();
    });

    it("answers one uniform retryable 429 when hidden rows or time run out the budget", async () => {
      const hidden = harness(
        backend,
        { g1: grant({ resources: ["z"] }) },
        { maxExaminedPerRequest: 2 },
      );
      for (let n = 0; n < 5; n++) hidden.put(`hidden${n}`);
      hidden.put("z");
      const slow = harness(backend, { g1: grant() }, { maxScanMillis: 0 });
      slow.put("a");
      const query = { changes_since: "beginning", limit: "5" };
      const a = await hidden.get(query);
      const b = await slow.get(query);
      for (const response of [a, b]) {
        expect(response.status).toBe(429);
        expect(response.retryAfter).toBe("1");
      }
      const withoutRequestId = (body: Body) => ({
        ...body,
        error: { ...body.error, request_id: undefined },
      });
      expect(withoutRequestId(a.body)).toEqual(withoutRequestId(b.body));
      expect(a.body.error?.code).toBe("rate_limit_exceeded");
    });

    it("resumes a stopped scan where it ended, never re-scanning", async () => {
      const h = harness(
        backend,
        { g1: grant({ resources: ["z"] }) },
        { maxExaminedPerRequest: 4 },
      );
      for (let n = 0; n < 20; n++) h.put(`hidden${String(n).padStart(2, "0")}`);
      h.put("z");
      const { final, responses } = await untilServed(h, {
        changes_since: "beginning",
        limit: "5",
        order: "asc",
      });
      expect(final.body.data.map((r) => r.id)).toEqual(["z"]);
      expect(responses.length).toBeGreaterThan(1);
      // 21 changed keys, each examined exactly once across all retries.
      expect(h.examined()).toBe(21);
    });

    it("issues handles of one length whatever the key length or carry", async () => {
      const lengths = new Set<number>();
      for (const key of ["k", "k".repeat(300), "鍵".repeat(300)]) {
        const h = harness(backend, { g1: grant() });
        for (const suffix of ["1", "2", "3"]) h.put(`${key}${suffix}`);
        const session = {
          changes_since: "beginning",
          order: "asc",
          limit: "1",
        };
        const first = await h.get(session);
        lengths.add(first.body.next_cursor!.length);
        // A withheld record rides in the session, not in the handle.
        h.remove(`${key}2`);
        h.put(`${key}2`);
        let page = await h.get({ ...session, cursor: first.body.next_cursor });
        while (page.body.next_cursor) {
          lengths.add(page.body.next_cursor.length);
          page = await h.get({ ...session, cursor: page.body.next_cursor });
        }
        lengths.add(page.body.next_changes_since!.length);
      }
      expect(lengths.size).toBe(1);
    });

    it("carries a record deleted and re-added between pages into the next session", async () => {
      const h = harness(backend, { g1: grant() });
      for (const key of ["a", "b", "c"]) h.put(key);
      const session = { changes_since: "beginning", order: "asc" };
      const first = await h.get({ ...session, limit: "1" });
      h.remove("b");
      h.put("b");
      const second = await h.get({
        ...session,
        cursor: first.body.next_cursor,
      });
      expect(second.body.data.map((r) => r.id)).toEqual(["c"]);
      const next = await h.get({
        changes_since: second.body.next_changes_since,
        order: "asc",
      });
      expect(next.body.data).toEqual([
        expect.objectContaining({ id: "b", data: { id: "b", name: "N" } }),
      ]);
    });

    it("expires a handle after its time to live", async () => {
      let now = 1_000_000;
      const h = harness(
        backend,
        { g1: grant() },
        { now: () => now, pageTtlMs: 1000 },
      );
      for (const key of ["a", "b"]) h.put(key);
      const first = await h.get({ changes_since: "beginning", limit: "1" });
      now += 1001;
      const late = await h.get({
        changes_since: "beginning",
        limit: "1",
        cursor: first.body.next_cursor,
      });
      expect(late.status).toBe(410);
      expect(late.body.error?.code).toBe("cursor_expired");
    });

    it("caps stored session state per owner, expiring the oldest first", async () => {
      const h = harness(
        backend,
        { g1: grant({}, "owner-a"), g2: grant({}, "owner-b") },
        { maxStatesPerOwner: 2 },
      );
      for (const key of ["a", "b"]) h.put(key);
      const query = { changes_since: "beginning", limit: "1" };
      const oldest = await h.get(query);
      await h.get(query);
      await h.get(query);
      // Another owner's sessions do not count against owner-a.
      const other = await h.get(query, "g2");
      await h.get(query, "g2");
      await h.get(query, "g2");
      expect(
        (await h.get({ ...query, cursor: oldest.body.next_cursor })).status,
      ).toBe(410);
      expect(
        (await h.get({ ...query, cursor: other.body.next_cursor }, "g2"))
          .status,
      ).toBe(410);
    });
  });
