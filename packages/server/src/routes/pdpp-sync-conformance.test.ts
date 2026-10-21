import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type {
  Grant,
  StreamGrant,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";
import { pdppRecordsRoutes, type PdppAccessLogPort } from "./pdpp-records.js";

// Black-box sync conformance over the public HTTP surface. Class A cases run
// under both the current and the candidate grant profile; class B cases run
// under the candidate profile only, because they change wire behavior that
// current clients rely on (docs/pdpp-sync-session.md).
const CURRENT = "0.1.0";
const CANDIDATE = "0.1.0-candidate";
const INSIDE = "2026-02-01T00:00:00Z";
const OUTSIDE = "2025-06-01T00:00:00Z";

type Body = {
  data: Array<{
    id: string;
    instance_id?: string;
    deleted?: boolean;
    data?: Record<string, unknown>;
  }>;
  has_more: boolean;
  next_cursor?: string;
  next_changes_since?: string;
  error?: { code: string };
};

function streamGrant(
  version: string,
  overrides: Partial<StreamGrant> = {},
): StreamGrant {
  return {
    name: "s",
    instance_ids: ["i"],
    fields: ["id", "name"],
    ...(version === CANDIDATE ? { required_fields: ["id"] } : {}),
    time_constraint: {
      field: "t",
      ...(version === CANDIDATE ? { type: "date-time" as const } : {}),
      since: "2026-01-01T00:00:00Z",
    },
    ...overrides,
  };
}

function grant(version: string, id: string, streams: StreamGrant[]): Grant {
  return {
    version,
    grant_id: id,
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "subject" },
    client: { client_id: "client" },
    source: { kind: "connector", id: "src" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams,
  };
}

const opened: PdppRecordStore[] = [];
afterEach(() => {
  for (const store of opened.splice(0)) store.close();
});

interface HarnessOptions {
  accessLog?: PdppAccessLogPort;
  syncPageBudget?: number;
}

function harness(
  backend: string,
  grants: Record<string, Grant>,
  db = new Database(":memory:"),
  options: HarnessOptions = {},
) {
  const store =
    backend === "memory"
      ? createMemoryRecordStore()
      : createTestBoundRecordStore(db);
  opened.push(store);
  const declarations = createStreamDeclarationRegistry(
    ["s", "u"].map((name) => ({
      name,
      semantics: "mutable_state" as const,
      primaryKey: ["id"],
      requiredFields: ["id"],
      cursorField: "emitted_at",
    })),
  );
  return serve(store, grants, declarations, db, options);
}

function serve(
  store: PdppRecordStore,
  grants: Record<string, Grant>,
  declarations: ReturnType<typeof createStreamDeclarationRegistry>,
  db: Database.Database,
  options: HarnessOptions = {},
) {
  const auth = createFixtureAuthorizationService(
    Object.fromEntries(
      Object.entries(grants).map(([token, g]) => [
        token,
        {
          active: true,
          tokenKind: "client" as const,
          subjectId: "subject",
          clientId: g.client.client_id,
          grant: g,
        },
      ]),
    ),
  );
  const app = pdppRecordsRoutes({ store, auth, declarations, ...options });
  let clock = 0;
  return {
    store,
    db,
    declarations,
    async get(path: string, token = "g1") {
      const response = await app.request(path, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return { status: response.status, body: (await response.json()) as Body };
    },
    put(
      key: string,
      data: Record<string, unknown>,
      { instance = "i", stream = "s" } = {},
    ) {
      clock += 1;
      const result = store.ingestBatch(
        [
          {
            instance,
            stream,
            key,
            data: { id: key, ...data },
            emitted_at: new Date(
              Date.UTC(2026, 3, 1, 0, 0, clock),
            ).toISOString(),
          },
        ],
        () => "mutable_state",
        () => ["id"],
      );
      expect(result.accepted).toBe(1);
    },
    remove(key: string, instance = "i") {
      clock += 1;
      expect(
        store.deleteRecord(
          instance,
          "s",
          key,
          new Date(Date.UTC(2026, 3, 1, 0, 0, clock)).toISOString(),
          "mutable_state",
        ),
      ).toBe(true);
    },
  };
}

type Harness = ReturnType<typeof harness>;

const begin = (version: string) => (version === CANDIDATE ? "beginning" : "");

function records(
  stream = "s",
  query: Record<string, string | undefined> = {},
): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query))
    if (value !== undefined) search.set(key, value);
  return `/streams/${stream}/records?${search}`;
}

async function checkpoint(h: Harness, version: string, token = "g1") {
  const response = await h.get(
    records("s", { changes_since: begin(version) }),
    token,
  );
  expect(response.status).toBe(200);
  expect(response.body.has_more).toBe(false);
  expect(response.body.next_changes_since).toBeTruthy();
  return response.body.next_changes_since!;
}

function ids(body: Body) {
  return body.data.map((row) => row.id);
}

function decodesAsJson(token: string): boolean {
  try {
    JSON.parse(Buffer.from(token, "base64url").toString("utf8"));
    return true;
  } catch {
    return false;
  }
}

for (const backend of ["memory", "sqlite"]) {
  describe(`${backend}: class A sync defects, every profile`, () => {
    for (const version of [CURRENT, CANDIDATE]) {
      const terminalOnlyAuthorized = async (
        resources: string[] | undefined,
        seed: (h: Harness) => void,
        expected: string[],
      ) => {
        const h = harness(backend, {
          g1: grant(version, "G1", [
            streamGrant(version, resources ? { resources } : {}),
          ]),
        });
        const baseline = await checkpoint(h, version);
        seed(h);
        const page = await h.get(
          records("s", { changes_since: baseline, limit: "1" }),
        );
        expect(page.status).toBe(200);
        expect(ids(page.body)).toEqual(expected);
        expect(page.body.has_more).toBe(false);
        expect(page.body.next_cursor).toBeUndefined();
        expect(page.body.next_changes_since).toBeTruthy();
      };

      it(`04 a resource-hidden row does not consume a page (${version})`, () =>
        terminalOnlyAuthorized(
          ["b"],
          (h) => {
            h.put("a", { name: "A", t: INSIDE });
            h.put("b", { name: "B", t: INSIDE });
          },
          ["b"],
        ));

      it(`05 a time-hidden row does not consume a page (${version})`, () =>
        terminalOnlyAuthorized(
          undefined,
          (h) => {
            h.put("a", { name: "A", t: OUTSIDE });
            h.put("b", { name: "B", t: INSIDE });
          },
          ["b"],
        ));

      it(`06 a hidden suffix does not add an empty page (${version})`, () =>
        terminalOnlyAuthorized(
          ["a"],
          (h) => {
            h.put("a", { name: "A", t: INSIDE });
            h.put("b", { name: "B", t: INSIDE });
          },
          ["a"],
        ));

      it(`07 a resource-hidden-only session is one empty terminal page (${version})`, () =>
        terminalOnlyAuthorized(
          ["c"],
          (h) => {
            h.put("a", { name: "A", t: INSIDE });
            h.put("b", { name: "B", t: INSIDE });
          },
          [],
        ));

      it(`08 a time-hidden-only session is one empty terminal page (${version})`, () =>
        terminalOnlyAuthorized(
          undefined,
          (h) => {
            h.put("a", { name: "A", t: OUTSIDE });
            h.put("b", { name: "B", t: OUTSIDE });
          },
          [],
        ));

      it(`23 discovery lists a granted stream that never held records (${version})`, async () => {
        const h = harness(backend, {
          g1: grant(version, "G1", [
            streamGrant(version),
            streamGrant(version, { name: "u" }),
          ]),
        });
        h.put("a", { name: "A", t: INSIDE });
        const listed = await h.get("/streams");
        expect(listed.status).toBe(200);
        const streams = (
          listed.body as unknown as {
            data: Array<{ name: string; record_count: number }>;
          }
        ).data;
        expect(streams.map((s) => s.name).sort()).toEqual(["s", "u"]);
        expect(streams.find((s) => s.name === "u")!.record_count).toBe(0);
      });

      it(`24 a tombstone-only stream stays discoverable so its deletion syncs (${version})`, async () => {
        const h = harness(backend, {
          g1: grant(version, "G1", [streamGrant(version)]),
        });
        h.put("a", { name: "A", t: INSIDE });
        const baseline = await checkpoint(h, version);
        h.remove("a");
        const listed = await h.get("/streams");
        expect(
          (
            listed.body as unknown as { data: Array<{ name: string }> }
          ).data.map((s) => s.name),
        ).toEqual(["s"]);
        const sync = await h.get(records("s", { changes_since: baseline }));
        expect(sync.status).toBe(200);
        expect(sync.body.data).toEqual([
          expect.objectContaining({ id: "a", deleted: true }),
        ]);
      });

      const deleteBetweenPages = async (recreate: boolean) => {
        const h = harness(backend, {
          g1: grant(version, "G1", [streamGrant(version)]),
        });
        for (const key of ["a", "b", "c"])
          h.put(key, { name: key.toUpperCase(), t: INSIDE });
        const session = { changes_since: begin(version), order: "asc" };
        const first = await h.get(records("s", { ...session, limit: "1" }));
        expect(ids(first.body)).toEqual(["a"]);
        h.remove("b");
        if (recreate) h.put("b", { name: "B", t: INSIDE });
        const second = await h.get(
          records("s", { ...session, cursor: first.body.next_cursor }),
        );
        const next = second.body.next_changes_since
          ? await h.get(
              records("s", {
                changes_since: second.body.next_changes_since,
                order: "asc",
              }),
            )
          : undefined;
        return { second, next };
      };

      for (const recreate of [false, true])
        it(`a record deleted${recreate ? " and recreated" : ""} after page 1 follows the profile's rule (${version})`, async () => {
          const { second, next } = await deleteBetweenPages(recreate);
          expect(second.status).toBe(200);
          expect(second.body.has_more).toBe(false);
          if (version === CANDIDATE) {
            // Never served after its deletion, and the rest of the session
            // continues. The next session returns it as of its own horizon,
            // even when a recreate left its projection unchanged.
            expect(ids(second.body)).toEqual(["c"]);
            expect(next!.body.data).toEqual([
              recreate
                ? expect.objectContaining({
                    id: "b",
                    data: { id: "b", name: "B" },
                  })
                : expect.objectContaining({ id: "b", deleted: true }),
            ]);
            return;
          }
          // Current: the page stays at the session horizon, as the current
          // contract requires, and the next session carries the change.
          expect(second.body.data).toEqual([
            expect.objectContaining({ id: "b", data: { id: "b", name: "B" } }),
            expect.objectContaining({ id: "c" }),
          ]);
          expect(next!.body.data).toEqual(
            recreate
              ? []
              : [expect.objectContaining({ id: "b", deleted: true })],
          );
        });

      if (version === CANDIDATE) {
        it("a withheld record is carried through later pages into the checkpoint", async () => {
          const h = harness(backend, {
            g1: grant(version, "G1", [streamGrant(version)]),
          });
          for (const key of ["a", "b", "c", "d"])
            h.put(key, { name: key.toUpperCase(), t: INSIDE });
          const session = {
            changes_since: begin(version),
            order: "asc",
            limit: "1",
          };
          let page = await h.get(records("s", session));
          h.remove("b");
          h.put("b", { name: "B", t: INSIDE });
          const seen = ids(page.body);
          while (page.body.next_cursor) {
            page = await h.get(
              records("s", { ...session, cursor: page.body.next_cursor }),
            );
            expect(page.status).toBe(200);
            seen.push(...ids(page.body));
          }
          expect(seen).toEqual(["a", "c", "d"]);
          const next = await h.get(
            records("s", {
              changes_since: page.body.next_changes_since!,
              order: "asc",
            }),
          );
          expect(ids(next.body)).toEqual(["b"]);
          // Carried once: the session after that compares projections again.
          const after = await h.get(
            records("s", {
              changes_since: next.body.next_changes_since!,
              order: "asc",
            }),
          );
          expect(after.body.data).toEqual([]);
        });

        it("measures the carry in UTF-8 bytes, so non-ASCII keys cannot exceed it", async () => {
          const h = harness(backend, {
            g1: grant(version, "G1", [streamGrant(version)]),
          });
          // About 820 UTF-16 code units of identity JSON, but about 2,460
          // UTF-8 bytes: over the 2 KiB carry.
          const wide = ["一", "二"].map((c) => c.repeat(400));
          for (const key of ["0", ...wide])
            h.put(key, { name: "N", t: INSIDE });
          const session = {
            changes_since: begin(version),
            order: "asc",
            limit: "1",
          };
          const first = await h.get(records("s", session));
          expect(ids(first.body)).toEqual(["0"]);
          for (const key of wide) h.remove(key);
          const second = await h.get(
            records("s", { ...session, cursor: first.body.next_cursor }),
          );
          expect(second.status).toBe(410);
          expect(second.body.error?.code).toBe("cursor_expired");
        });

        it("expires a session whose withheld records exceed what a token can carry", async () => {
          const h = harness(backend, {
            g1: grant(version, "G1", [streamGrant(version)]),
          });
          const keys = Array.from(
            { length: 200 },
            (_, i) => `key-${String(i).padStart(4, "0")}-${"x".repeat(40)}`,
          );
          for (const key of keys) h.put(key, { name: "N", t: INSIDE });
          const session = {
            changes_since: begin(version),
            order: "asc",
            limit: "1",
          };
          const first = await h.get(records("s", session));
          for (const key of keys.slice(1)) h.remove(key);
          const second = await h.get(
            records("s", { ...session, cursor: first.body.next_cursor }),
          );
          expect(second.status).toBe(410);
          expect(second.body.error?.code).toBe("cursor_expired");
        });
      }

      it(`F1 refuses to serve one key from two instances under one id (${version})`, async () => {
        const h = harness(backend, {
          g1: grant(version, "G1", [
            streamGrant(version, { instance_ids: ["i", "j"] }),
          ]),
        });
        for (const instance of ["i", "j"])
          h.put("a", { name: instance, t: INSIDE }, { instance });
        h.put("b", { name: "B", t: INSIDE }, { instance: "j" });
        const lists = [
          records("s", { changes_since: begin(version) }),
          records("s", {
            changes_since: begin(version),
            limit: "1",
            order: "asc",
          }),
          records("s", {}),
        ];
        // A candidate record is named by its instance and key together, so
        // a list or sync page can serve both. A detail read names a key
        // alone, so it stays ambiguous in every profile.
        for (const path of version === CANDIDATE
          ? ["/streams/s/records/a"]
          : [...lists, "/streams/s/records/a"]) {
          const response = await h.get(path);
          expect(response.status).toBe(403);
          expect(response.body.error?.code).toBe("disclosure_unavailable");
        }
        if (version === CANDIDATE) {
          for (const path of [lists[0], lists[2]]) {
            const response = await h.get(path);
            expect(response.status).toBe(200);
            const ids = response.body.data
              .map((row) => `${row.instance_id}/${row.id}`)
              .sort();
            expect(ids).toEqual(["i/a", "j/a", "j/b"]);
          }
        }
        // A key held by one instance stays readable.
        expect((await h.get("/streams/s/records/b")).status).toBe(200);
      });

      it(`F1 a same-key record the grant hides is not a conflict (${version})`, async () => {
        const h = harness(backend, {
          g1: grant(version, "G1", [
            streamGrant(version, { instance_ids: ["j", "i"] }),
          ]),
        });
        h.put("a", { name: "visible", t: INSIDE }, { instance: "i" });
        h.put("a", { name: "hidden", t: OUTSIDE }, { instance: "j" });
        const detail = await h.get("/streams/s/records/a");
        expect(detail.status).toBe(200);
        expect(detail.body.data).toEqual({ id: "a", name: "visible" });
        const listed = await h.get(records("s", {}));
        expect(listed.body.data.map((row) => row.data?.name)).toEqual([
          "visible",
        ]);
        const synced = await h.get(
          records("s", { changes_since: begin(version) }),
        );
        expect(synced.body.data.map((row) => row.data?.name)).toEqual([
          "visible",
        ]);
        // Deleting the visible one is a plain deletion of `a`.
        h.remove("a", "i");
        const next = await h.get(
          records("s", { changes_since: synced.body.next_changes_since }),
        );
        expect(next.body.data).toEqual([
          expect.objectContaining({ id: "a", deleted: true }),
        ]);
      });

      it(`F1 a later change cannot make two records share an id (${version})`, async () => {
        const h = harness(backend, {
          g1: grant(version, "G1", [
            streamGrant(version, { instance_ids: ["i", "j"] }),
          ]),
        });
        h.put("a", { name: "i", t: INSIDE }, { instance: "i" });
        h.put("a", { name: "j", t: OUTSIDE }, { instance: "j" });
        const baseline = await checkpoint(h, version);
        h.put("a", { name: "j2", t: INSIDE }, { instance: "j" });
        const sync = await h.get(records("s", { changes_since: baseline }));
        if (version === CANDIDATE) {
          expect(sync.status).toBe(200);
          expect(sync.body.data).toEqual([
            expect.objectContaining({
              id: "a",
              instance_id: "j",
              data: { id: "a", name: "j2" },
            }),
          ]);
        } else {
          expect(sync.status).toBe(403);
          expect(sync.body.error?.code).toBe("disclosure_unavailable");
        }
      });

      it(`F5 every successful sync page is one completed access event (${version})`, async () => {
        const events: Array<{ outcome: string; grantId: string }> = [];
        const h = harness(
          backend,
          { g1: grant(version, "G1", [streamGrant(version)]) },
          new Database(":memory:"),
          { accessLog: { record: async (entry) => void events.push(entry) } },
        );
        for (const key of ["a", "b", "c"]) h.put(key, { name: key, t: INSIDE });
        let cursor: string | undefined;
        let pages = 0;
        do {
          const page = await h.get(
            records("s", { changes_since: begin(version), limit: "1", cursor }),
          );
          expect(page.status).toBe(200);
          pages += 1;
          cursor = page.body.next_cursor;
        } while (cursor);
        expect(pages).toBe(3);
        expect(events).toEqual(
          Array.from({ length: 3 }, () =>
            expect.objectContaining({ outcome: "completed", grantId: "G1" }),
          ),
        );
      });

      it(`F6 a page stops after its work budget, revealing no hidden key (${version})`, async () => {
        const h = harness(
          backend,
          {
            g1: grant(version, "G1", [
              streamGrant(version, { resources: ["z"] }),
            ]),
          },
          new Database(":memory:"),
          { syncPageBudget: 3 },
        );
        for (let n = 0; n < 7; n++)
          h.put(`hidden${n}`, { name: "H", t: INSIDE });
        h.put("z", { name: "Z", t: INSIDE });
        const seen: string[] = [];
        let cursor: string | undefined;
        let pages = 0;
        do {
          const page = await h.get(
            records("s", {
              changes_since: begin(version),
              limit: "5",
              order: "asc",
              cursor,
            }),
          );
          expect(page.status).toBe(200);
          pages += 1;
          seen.push(...ids(page.body));
          cursor = page.body.next_cursor;
          if (cursor) {
            expect(decodesAsJson(cursor)).toBe(false);
            expect(
              Buffer.from(cursor, "base64url").toString("latin1"),
            ).not.toContain("hidden");
          }
        } while (cursor);
        // Eight changed keys, three examined per page.
        expect(pages).toBe(3);
        expect(seen).toEqual(["z"]);
      });
      it(`fixed horizon: writes after page 1 wait for the next session (${version})`, async () => {
        const h = harness(backend, {
          g1: grant(version, "G1", [streamGrant(version)]),
        });
        h.put("a", { name: "A", t: INSIDE });
        h.put("b", { name: "B1", t: INSIDE });
        const first = await h.get(
          records("s", {
            changes_since: begin(version),
            limit: "1",
            order: "asc",
          }),
        );
        h.put("b", { name: "B2", t: INSIDE });
        h.put("c", { name: "C", t: INSIDE });
        const second = await h.get(
          records("s", {
            changes_since: begin(version),
            limit: "5",
            order: "asc",
            cursor: first.body.next_cursor,
          }),
        );
        expect(second.body.data).toEqual([
          expect.objectContaining({ id: "b", data: { id: "b", name: "B1" } }),
        ]);
        const next = await h.get(
          records("s", {
            changes_since: second.body.next_changes_since,
            order: "asc",
          }),
        );
        expect(ids(next.body).sort()).toEqual(["b", "c"]);
      });
    }

    it("18 (current) a legacy checkpoint ahead of the store clock expires", async () => {
      const h = harness(backend, {
        g1: grant(CURRENT, "G1", [streamGrant(CURRENT)]),
      });
      h.put("a", { name: "A", t: INSIDE });
      const baseline = await checkpoint(h, CURRENT);
      const payload = JSON.parse(
        Buffer.from(baseline, "base64url").toString("utf8"),
      );
      const ahead =
        backend === "memory" ? "2099-01-01T00:00:00.000Z" : "900000000";
      const forged = Buffer.from(
        JSON.stringify({ ...payload, horizon: ahead }),
      ).toString("base64url");
      h.put("a", { name: "A2", t: INSIDE });
      const sync = await h.get(records("s", { changes_since: forged }));
      expect(sync.status).toBe(410);
      expect(sync.body.error?.code).toBe("cursor_expired");
    });

    it("(current) a readable page cursor from before sealed cursors expires", async () => {
      const h = harness(backend, {
        g1: grant(CURRENT, "G1", [streamGrant(CURRENT)]),
      });
      for (const key of ["a", "b", "c"]) h.put(key, { name: key, t: INSIDE });
      const first = await h.get(
        records("s", { changes_since: "", limit: "1" }),
      );
      // Page cursors are sealed now; a readable one has the old shape: the
      // checkpoint's fields plus the raw offset of the next page.
      expect(decodesAsJson(first.body.next_cursor!)).toBe(false);
      const checkpointPayload = JSON.parse(
        Buffer.from(await checkpoint(h, CURRENT), "base64url").toString("utf8"),
      );
      const old = Buffer.from(
        JSON.stringify({
          ...checkpointPayload,
          sinceHorizon: null,
          offset: 1,
        }),
      ).toString("base64url");
      const resumed = await h.get(
        records("s", { changes_since: "", limit: "1", cursor: old }),
      );
      expect(resumed.status).toBe(410);
      expect(resumed.body.error?.code).toBe("cursor_expired");
    });

    it("current profile keeps its readable checkpoint format", async () => {
      const h = harness(backend, {
        g1: grant(CURRENT, "G1", [streamGrant(CURRENT)]),
      });
      h.put("a", { name: "A", t: INSIDE });
      const baseline = await checkpoint(h, CURRENT);
      expect(decodesAsJson(baseline)).toBe(true);
      h.put("a", { name: "A2", t: INSIDE });
      const sync = await h.get(records("s", { changes_since: baseline }));
      expect(ids(sync.body)).toEqual(["a"]);
    });
  });

  describe(`${backend}: class B sync rules, candidate profile`, () => {
    const g = (id: string, overrides: Partial<StreamGrant> = {}) =>
      grant(CANDIDATE, id, [streamGrant(CANDIDATE, overrides)]);

    async function pageCursor(
      h: Harness,
      token = "g1",
      query: Record<string, string> = {},
    ) {
      for (const key of ["a", "b", "c"])
        h.put(key, { name: key.toUpperCase(), t: INSIDE });
      const first = await h.get(
        records("s", { changes_since: "beginning", limit: "1", ...query }),
        token,
      );
      expect(first.status).toBe(200);
      expect(first.body.has_more).toBe(true);
      return first.body.next_cursor!;
    }

    async function expectInvalidCursor(h: Harness, path: string, token = "g1") {
      const response = await h.get(path, token);
      expect(response.status).toBe(400);
      expect(response.body.error?.code).toBe("invalid_cursor");
      expect(response.body.data).toBeUndefined();
    }

    it("01 a hidden-field-only exit from the time window emits a removal", async () => {
      const h = harness(backend, { g1: g("G1") });
      h.put("a", { name: "A", t: INSIDE });
      const baseline = await checkpoint(h, CANDIDATE);
      h.put("a", { name: "A", t: OUTSIDE });
      const sync = await h.get(records("s", { changes_since: baseline }));
      expect(sync.body.data).toEqual([
        {
          object: "record",
          id: "a",
          instance_id: "i",
          stream: "s",
          deleted: true,
        },
      ]);
    });

    it("02 a hidden-field-only entry into the time window emits the record", async () => {
      const h = harness(backend, { g1: g("G1") });
      h.put("a", { name: "A", t: OUTSIDE });
      const baseline = await checkpoint(h, CANDIDATE);
      h.put("a", { name: "A", t: INSIDE });
      const sync = await h.get(records("s", { changes_since: baseline }));
      expect(sync.body.data).toEqual([
        expect.objectContaining({ id: "a", data: { id: "a", name: "A" } }),
      ]);
    });

    it("03 a visible change that leaves the window emits a removal, never the new value", async () => {
      const h = harness(backend, { g1: g("G1") });
      h.put("a", { name: "A", t: INSIDE });
      const baseline = await checkpoint(h, CANDIDATE);
      h.put("a", { name: "Secret", t: OUTSIDE });
      const sync = await h.get(records("s", { changes_since: baseline }));
      expect(sync.body.data).toEqual([
        {
          object: "record",
          id: "a",
          instance_id: "i",
          stream: "s",
          deleted: true,
        },
      ]);
    });

    it("09 writes to an ungranted stream leave no readable trace in the checkpoint", async () => {
      const h = harness(backend, { g1: g("G1") });
      h.put("a", { name: "A", t: INSIDE });
      const baseline = await checkpoint(h, CANDIDATE);
      const quiet = await h.get(records("s", { changes_since: baseline }));
      const quietAgain = await h.get(records("s", { changes_since: baseline }));
      for (let n = 0; n < 5; n++)
        h.put(`u${n}`, { name: "U", t: INSIDE }, { stream: "u" });
      const busy = await h.get(records("s", { changes_since: baseline }));
      for (const response of [quiet, quietAgain, busy]) {
        expect(response.body.data).toEqual([]);
        expect(decodesAsJson(response.body.next_changes_since!)).toBe(false);
      }
      // Fresh per issue, constant length: neither equality nor size can
      // signal the hidden writes.
      expect(quiet.body.next_changes_since).not.toBe(
        quietAgain.body.next_changes_since,
      );
      expect(busy.body.next_changes_since!.length).toBe(
        quiet.body.next_changes_since!.length,
      );
    });

    it("10 hidden-field writes produce no event and no readable counter", async () => {
      const h = harness(backend, { g1: g("G1") });
      h.put("a", { name: "A", t: INSIDE, secret: 0 });
      const baseline = await checkpoint(h, CANDIDATE);
      const control = await h.get(records("s", { changes_since: baseline }));
      for (let n = 1; n <= 5; n++)
        h.put("a", { name: "A", t: INSIDE, secret: n });
      const sync = await h.get(records("s", { changes_since: baseline }));
      expect(sync.body.data).toEqual([]);
      expect(decodesAsJson(sync.body.next_changes_since!)).toBe(false);
      expect(sync.body.next_changes_since!.length).toBe(
        control.body.next_changes_since!.length,
      );
    });

    it("11 a page cursor cannot be replayed under another grant", async () => {
      const h = harness(backend, { g1: g("G1"), g2: g("G2") });
      const cursor = await pageCursor(h);
      await expectInvalidCursor(
        h,
        records("s", { changes_since: "beginning", cursor }),
        "g2",
      );
    });

    it("12 a checkpoint cannot seed a session under another grant", async () => {
      const h = harness(backend, { g1: g("G1"), g2: g("G2") });
      h.put("a", { name: "A", t: INSIDE });
      const baseline = await checkpoint(h, CANDIDATE);
      await expectInvalidCursor(
        h,
        records("s", { changes_since: baseline }),
        "g2",
      );
    });

    it("13 a page cursor cannot move to another instance set", async () => {
      const h = harness(backend, {
        g1: g("G1", { instance_ids: ["i"] }),
        g2: g("G1", { instance_ids: ["j"] }),
      });
      for (const key of ["a", "b"])
        h.put(key, { name: key, t: INSIDE }, { instance: "j" });
      const cursor = await pageCursor(h);
      await expectInvalidCursor(
        h,
        records("s", { changes_since: "beginning", cursor }),
        "g2",
      );
    });

    it("14 a page cursor cannot move to another resource set", async () => {
      const h = harness(backend, {
        g1: g("G1", { resources: ["a", "b", "c"] }),
        g2: g("G1", { resources: ["b", "c"] }),
      });
      const cursor = await pageCursor(h);
      await expectInvalidCursor(
        h,
        records("s", { changes_since: "beginning", cursor }),
        "g2",
      );
    });

    it("15 a page cursor cannot change the requested fields", async () => {
      const h = harness(backend, {
        g1: g("G1", { fields: ["id", "name", "secret"] }),
      });
      const cursor = await pageCursor(h, "g1", { fields: "id,name" });
      await expectInvalidCursor(
        h,
        records("s", {
          changes_since: "beginning",
          cursor,
          fields: "id,secret",
        }),
      );
    });

    it("16 a checkpoint cannot widen the requested fields", async () => {
      const h = harness(backend, { g1: g("G1") });
      h.put("a", { name: "A", t: INSIDE });
      const first = await h.get(
        records("s", { changes_since: "beginning", fields: "id" }),
      );
      await expectInvalidCursor(
        h,
        records("s", {
          changes_since: first.body.next_changes_since,
          fields: "id,name",
        }),
      );
    });

    it("17 an altered page cursor is rejected", async () => {
      const h = harness(backend, { g1: g("G1") });
      const cursor = await pageCursor(h);
      const middle = Math.floor(cursor.length / 2);
      const altered =
        cursor.slice(0, middle) +
        (cursor[middle] === "A" ? "B" : "A") +
        cursor.slice(middle + 1);
      await expectInvalidCursor(
        h,
        records("s", { changes_since: "beginning", cursor: altered }),
      );
    });

    it("18 an altered or legacy-format checkpoint is rejected", async () => {
      const h = harness(backend, { g1: g("G1") });
      h.put("a", { name: "A", t: INSIDE });
      const baseline = await checkpoint(h, CANDIDATE);
      const altered =
        baseline.slice(0, -2) + (baseline.endsWith("A") ? "BB" : "AA");
      await expectInvalidCursor(h, records("s", { changes_since: altered }));
      const legacy = Buffer.from(
        JSON.stringify({
          kind: "changes_since",
          stream: "s",
          horizon: "900000000",
          sinceHorizon: null,
          offset: 0,
        }),
      ).toString("base64url");
      await expectInvalidCursor(h, records("s", { changes_since: legacy }));
    });

    it("19 a checkpoint is bound to its stream", async () => {
      const h = harness(backend, {
        g1: grant(CANDIDATE, "G1", [
          streamGrant(CANDIDATE),
          streamGrant(CANDIDATE, { name: "u" }),
        ]),
      });
      h.put("a", { name: "A", t: INSIDE });
      const baseline = await checkpoint(h, CANDIDATE);
      await expectInvalidCursor(h, records("u", { changes_since: baseline }));
    });

    it("20 a page cursor is bound to its session baseline", async () => {
      const h = harness(backend, { g1: g("G1") });
      const cursor = await pageCursor(h);
      const other = await checkpoint(h, CANDIDATE);
      await expectInvalidCursor(
        h,
        records("s", { changes_since: other, cursor }),
      );
    });

    it("21 a page cursor is not a checkpoint", async () => {
      const h = harness(backend, { g1: g("G1") });
      const cursor = await pageCursor(h);
      await expectInvalidCursor(h, records("s", { changes_since: cursor }));
    });

    it("22 a checkpoint is not a page cursor", async () => {
      const h = harness(backend, { g1: g("G1") });
      h.put("a", { name: "A", t: INSIDE });
      const baseline = await checkpoint(h, CANDIDATE);
      await expectInvalidCursor(
        h,
        records("s", { changes_since: "beginning", cursor: baseline }),
      );
    });

    it("25 a page cursor reveals no readable position", async () => {
      const h = harness(backend, { g1: g("G1") });
      const cursor = await pageCursor(h);
      expect(decodesAsJson(cursor)).toBe(false);
    });

    it("26 a session follows and binds the requested order", async () => {
      const h = harness(backend, { g1: g("G1") });
      const cursor = await pageCursor(h, "g1", { order: "asc" });
      const next = await h.get(
        records("s", {
          changes_since: "beginning",
          cursor,
          order: "asc",
          limit: "5",
        }),
      );
      expect(ids(next.body)).toEqual(["b", "c"]);
      await expectInvalidCursor(
        h,
        records("s", { changes_since: "beginning", cursor, order: "desc" }),
      );
      const descending = await h.get(
        records("s", { changes_since: "beginning" }),
      );
      expect(ids(descending.body)).toEqual(["c", "b", "a"]);
    });

    it("an empty changes_since is not a candidate token", async () => {
      const h = harness(backend, { g1: g("G1") });
      await expectInvalidCursor(h, records("s", { changes_since: "" }));
    });

    it("control: a fresh token for the same grant, a new limit and a retry continue the session", async () => {
      const h = harness(backend, { g1: g("G1"), g1b: g("G1") });
      const cursor = await pageCursor(h);
      const path = records("s", {
        changes_since: "beginning",
        cursor,
        limit: "5",
      });
      const first = await h.get(path, "g1b");
      const retry = await h.get(path, "g1b");
      expect(first.status).toBe(200);
      expect(ids(first.body)).toEqual(["b", "a"]);
      expect(retry.body.data).toEqual(first.body.data);
    });

    if (backend === "sqlite") {
      it("control: a checkpoint survives a restart and expires after a reset", async () => {
        const h = harness(backend, { g1: g("G1") });
        h.put("a", { name: "A", t: INSIDE });
        const baseline = await checkpoint(h, CANDIDATE);
        const restarted = serve(
          createTestBoundRecordStore(h.db),
          { g1: g("G1") },
          h.declarations,
          h.db,
        );
        const resumed = await restarted.get(
          records("s", { changes_since: baseline }),
        );
        expect(resumed.status).toBe(200);
        const store = h.store as ReturnType<typeof createTestBoundRecordStore>;
        store.resetInstanceBinding({
          instance: "i",
          expectedMethod: "test_method",
          expectedGeneration: 1,
          nextMethod: "test_method",
        });
        const expired = await restarted.get(
          records("s", { changes_since: baseline }),
        );
        expect(expired.status).toBe(410);
        expect(expired.body.error?.code).toBe("cursor_expired");
      });
    }
  });
}
