/**
 * The own-writes state table (own-writes-state-table.md), one case per row.
 *
 * Every row drives the real `StreamSyncWriter` and reads through the writer's
 * own overlay source, so the descriptors are the ones the producer emits. A
 * row says what the owner reads, and what the writer then does; the
 * assertions are the table's columns:
 *
 * - fold: rows visible, completeness, withheld markers (resolve, owner);
 * - scan: the same, for a legacy name that needs several streams;
 * - success response: the API answer when a view or the legacy body serves;
 * - refusal response: the API answer on a missing body and on a named
 *   connection that does not exist.
 *
 * Whatever the row, a grant reads only what is published and is told nothing,
 * and no run the writer refuses is ever shown.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "../api/index.js";
import type { PersonalServerDataApiDeps } from "../api/index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import type { ReadDecision } from "./service.js";
import {
  CONNECTOR,
  Rig,
  type OptionalDescriptorField,
  type RunSpec,
  type SeedRows,
} from "./writer-rig.js";

const run = (spec: Partial<RunSpec> & { runId: string }): RunSpec => ({
  key: "id",
  version: "1.0.0",
  rows: [],
  full: false,
  ...spec,
});

const A = { id: "a", v: 1 };
const B = { id: "b", v: 1 };
const baseRun = (over: Partial<RunSpec> = {}): RunSpec =>
  run({
    runId: "base",
    full: true,
    rows: [A, B],
    ...over,
  });

interface Row {
  readonly id: string;
  readonly title: string;
  readonly connector?: string;
  readonly scope?: string;
  readonly seed?: SeedRows;
  /** Published and imported before the case starts. */
  readonly base: readonly RunSpec[];
  readonly runs: readonly RunSpec[];
  readonly omit?: readonly OptionalDescriptorField[];
  readonly expect: {
    /** Row ids the owner reads before the writer publishes; null = no view. */
    readonly rows: readonly string[] | null;
    /** The owner's connection view is complete. */
    readonly complete: boolean | null;
    /** Runs the owner is told are withheld, before publish. */
    readonly withheld: readonly string[];
    /** Runs the owner is told are withheld, after publish and import. */
    readonly withheldAfter: readonly string[];
    /** Local runs holding records that a legacy body does not supersede. */
    readonly pending?: number;
  };
}

const ROWS: readonly Row[] = [
  {
    id: "S1",
    title: "same key, a new row",
    base: [baseRun()],
    runs: [run({ runId: "r1", rows: [{ id: "c", v: 1 }] })],
    expect: {
      rows: ["a", "b", "c"],
      complete: true,
      withheld: [],
      withheldAfter: [],
    },
  },
  {
    id: "S2",
    title: "a run with no record",
    base: [baseRun()],
    runs: [run({ runId: "r1" })],
    expect: {
      rows: ["a", "b"],
      complete: true,
      withheld: [],
      withheldAfter: [],
    },
  },
  {
    id: "S3",
    title: "a newer connector changes the key, full run",
    base: [baseRun()],
    runs: [
      run({
        runId: "r1",
        key: "uid",
        version: "2.0.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
    ],
    expect: {
      rows: ["u1"],
      complete: true,
      withheld: [],
      withheldAfter: [],
    },
  },
  {
    id: "S4",
    title: "a newer connector changes the key, partial run",
    base: [baseRun()],
    runs: [
      run({
        runId: "r1",
        key: "uid",
        version: "2.0.0",
        rows: [{ uid: "u1" }],
      }),
    ],
    expect: {
      rows: ["u1"],
      complete: false,
      withheld: [],
      withheldAfter: [],
      pending: 1,
    },
  },
  {
    id: "S5",
    title: "a run resumed from another namespace's checkpoint",
    base: [baseRun()],
    runs: [
      run({
        runId: "r1",
        otherNamespace: true,
        rows: [{ id: "c", v: 1 }],
      }),
    ],
    expect: {
      rows: ["c"],
      complete: false,
      withheld: [],
      withheldAfter: [],
      pending: 1,
    },
  },
  {
    id: "S6",
    title: "an older connector meets a changed key: the writer refuses",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({
        runId: "r1",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
    ],
    expect: {
      rows: ["a", "b"],
      complete: true,
      withheld: ["r1"],
      withheldAfter: ["r1"],
    },
  },
  {
    id: "S7",
    title: "A lowers the profile, B changes the key, C is older than B",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({ runId: "rA", version: "1.0.0", rows: [{ id: "x", v: 1 }] }),
      run({
        runId: "rB",
        key: "uid",
        version: "1.5.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
      run({
        runId: "rC",
        version: "1.4.0",
        full: true,
        rows: [{ id: "z", v: 1 }],
      }),
    ],
    expect: {
      // B may or may not be publishable by what the overlay can see: it and
      // everything after it are withheld, never merged.
      rows: ["a", "b", "x"],
      complete: true,
      withheld: ["rB", "rC"],
      withheldAfter: ["rC"],
    },
  },
  {
    id: "S8",
    title: "the key changes and changes back",
    base: [baseRun()],
    runs: [
      run({
        runId: "r1",
        key: "uid",
        version: "2.0.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
      run({
        runId: "r2",
        version: "3.0.0",
        full: true,
        rows: [{ id: "c", v: 1 }],
      }),
    ],
    expect: {
      rows: ["c"],
      complete: true,
      withheld: [],
      withheldAfter: [],
    },
  },
  {
    id: "S9",
    title: "an older empty run, then an older changed key",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({ runId: "r1", version: "1.0.0" }),
      run({
        runId: "r2",
        key: "uid",
        version: "1.5.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
    ],
    expect: {
      rows: ["a", "b"],
      complete: true,
      withheld: ["r2"],
      withheldAfter: ["r2"],
    },
  },
  {
    id: "S10",
    title: "a newer empty run, then a changed key the writer publishes",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({ runId: "r1", version: "3.0.0" }),
      run({
        runId: "r2",
        key: "uid",
        version: "2.5.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
    ],
    expect: {
      rows: ["u1"],
      complete: true,
      withheld: [],
      withheldAfter: [],
    },
  },
  {
    id: "S11",
    title: "S10 with recordCount absent: the fold cannot tell the run is empty",
    base: [baseRun({ version: "2.0.0" })],
    omit: ["recordCount"],
    runs: [
      run({ runId: "r1", version: "3.0.0" }),
      run({
        runId: "r2",
        key: "uid",
        version: "2.5.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
    ],
    expect: {
      // r1 may hold records, so r2 may be refused: it is withheld although
      // the writer publishes it.
      rows: ["a", "b"],
      complete: true,
      withheld: ["r2"],
      withheldAfter: [],
    },
  },
  {
    id: "S12",
    title: "S5 with incompleteOverBase absent: never claims complete",
    base: [baseRun()],
    omit: ["incompleteOverBase"],
    runs: [
      run({
        runId: "r1",
        otherNamespace: true,
        rows: [{ id: "c", v: 1 }],
      }),
    ],
    expect: {
      rows: ["c"],
      complete: false,
      withheld: [],
      withheldAfter: [],
      pending: 1,
    },
  },
  {
    id: "S13",
    title: "S1 with incompleteOverBase absent: takes the incomplete side",
    base: [baseRun()],
    omit: ["incompleteOverBase"],
    runs: [run({ runId: "r1", rows: [{ id: "c", v: 1 }] })],
    expect: {
      // The writer publishes a complete head; without the field the overlay
      // cannot tell this run from S12's, so it does not claim complete.
      rows: ["c"],
      complete: false,
      withheld: [],
      withheldAfter: [],
      pending: 1,
    },
  },
  {
    id: "S14",
    title: "an incomplete imported base and a refused full run",
    base: [baseRun({ version: "2.0.0", full: false, otherNamespace: true })],
    runs: [
      run({
        runId: "r1",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
    ],
    expect: {
      rows: null,
      complete: false,
      withheld: ["r1"],
      withheldAfter: ["r1"],
    },
  },
  {
    id: "S15",
    title: "a seed merged at the first publish",
    base: [],
    seed: { key: "id", version: "1.0.0", rows: [{ id: "seed" }] },
    runs: [run({ runId: "r1", rows: [{ id: "c", v: 1 }] })],
    expect: {
      // The writer publishes a complete head; the seed is read at publish
      // time. No connection is imported yet, so there is no connection view.
      rows: ["c"],
      complete: null,
      withheld: [],
      withheldAfter: [],
      pending: 1,
    },
  },
  {
    id: "S16",
    title: "two streams of a legacy name: one has no run, one is refused",
    connector: "meta",
    scope: "instagram.posts",
    base: [
      baseRun({
        stream: "posts",
        runId: "basePosts",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
      baseRun({
        stream: "post_likes",
        runId: "baseLikes",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
    ],
    runs: [
      run({
        runId: "r1",
        stream: "post_likes",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
    ],
    expect: {
      rows: null,
      complete: false,
      withheld: ["r1"],
      withheldAfter: ["r1"],
    },
  },
  {
    id: "S17",
    title: "two streams of a legacy name, both refused: both are reported",
    connector: "meta",
    scope: "instagram.posts",
    base: [
      baseRun({
        stream: "posts",
        runId: "basePosts",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
      baseRun({
        stream: "post_likes",
        runId: "baseLikes",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
    ],
    runs: [
      run({
        runId: "r1",
        stream: "posts",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [{ uid: "u1" }],
      }),
      run({
        runId: "r2",
        stream: "post_likes",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [{ uid: "u2" }],
      }),
    ],
    expect: {
      rows: null,
      complete: false,
      withheld: ["r1", "r2"],
      withheldAfter: ["r1", "r2"],
    },
  },
];

// ---------------------------------------------------------------------------

const BUILDER = "0x000000000000000000000000000000000000bEEF";

function rowScope(row: Row): string {
  return row.scope ?? `pdpp.${row.connector ?? CONNECTOR}.items`;
}

async function open(row: Row): Promise<Rig> {
  const rig = new Rig(row.seed, row.connector);
  await rig.open();
  if (row.base.length > 0) {
    for (const spec of row.base) await rig.collect(spec);
    await rig.publish();
    await rig.sync();
  }
  for (const field of row.omit ?? []) rig.omit.add(field);
  for (const spec of row.runs) await rig.collect(spec);
  return rig;
}

function ids(body: unknown): string[] {
  const records = (
    body as { data: { records: Record<string, unknown>[] } }
  ).data.records.map((r) => String(r["id"] ?? r["uid"]));
  return records.sort();
}

async function readIds(decision: ReadDecision): Promise<string[] | null> {
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return null;
  }
  return ids(JSON.parse(await new Response(decision.body).text()));
}

function withheldOf(decision: ReadDecision): string[] {
  const notes = decision as { withheld?: readonly { runId: string }[] };
  return (notes.withheld ?? []).map((w) => w.runId).sort();
}

function resolve(
  rig: Rig,
  row: Row,
  input: { owner: boolean; legacyFile?: boolean; connection?: string },
) {
  return rig.service.resolve({
    scope: rowScope(row),
    connection: input.connection ?? null,
    cursor: null,
    legacyFile: input.legacyFile ?? false,
    isOwnerView: input.owner,
  });
}

async function connectionComplete(
  rig: Rig,
  row: Row,
): Promise<boolean | undefined> {
  const connector = row.connector ?? CONNECTOR;
  const snapshot = await rig.overlay.snapshot(connector);
  try {
    return rig.service
      .connectionViews(connector, snapshot)
      .find((c) => c.ns === rig.ns)?.streams["items"]?.complete;
  } finally {
    snapshot.release();
  }
}

interface Api {
  readonly status: number;
  readonly source: string | null;
  readonly header: string | null;
  readonly bodyWithheld: string[] | null;
}

async function api(
  rig: Rig,
  row: Row,
  input: { builder: boolean; file: boolean; connection?: boolean },
): Promise<Api> {
  const storage = createMemoryDataStorage();
  if (input.file) {
    const envelope = {
      version: "1.0" as const,
      scope: rowScope(row),
      collectedAt: "2026-10-01T00:00:00.000Z",
      data: { records: [{ id: "stored" }] },
    };
    const written = await storage.writeEnvelope(envelope);
    storage.insertEntry({
      fileId: null,
      path: written.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: written.sizeBytes,
    } as never);
  }
  const deps: PersonalServerDataApiDeps = {
    storage,
    streamSyncRead: rig.service,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async ({ request }: { request: Request }) =>
        request.headers.get("x-test-builder")
          ? { builder: BUILDER, grantId: "grant-1" }
          : { builder: BUILDER, grantId: "owner" },
      ),
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
  };
  const query = input.connection ? "?connection=" : "";
  const response = await handlePersonalServerDataRequest(
    new Request(`https://ps.example.com/${rowScope(row)}${query}`, {
      headers: input.builder ? { "x-test-builder": "1" } : {},
    }),
    deps,
  );
  const body = (await response.json().catch(() => null)) as {
    withheld?: { runId: string }[];
  } | null;
  return {
    status: response.status,
    source: response.headers.get("x-vana-data-source"),
    header: response.headers.get("x-stream-sync-withheld"),
    bodyWithheld: body?.withheld
      ? body.withheld.map((w) => w.runId).sort()
      : null,
  };
}

describe("own-writes state table", () => {
  for (const row of ROWS) {
    const { expect: want } = row;
    describe(`${row.id} ${row.title}`, () => {
      it("fold and scan: the owner reads what the table says", async () => {
        const rig = await open(row);
        const decision = await resolve(rig, row, { owner: true });
        expect(await readIds(decision)).toEqual(want.rows);
        if (row.scope === undefined) {
          expect(await connectionComplete(rig, row)).toBe(
            want.complete ?? undefined,
          );
        }
        expect(withheldOf(decision)).toEqual(want.withheld);
        // With a stored body: a complete view still wins; otherwise the body
        // answers, the same runs are reported, and pending runs that hold
        // records are named.
        const legacy = await resolve(rig, row, {
          owner: true,
          legacyFile: true,
        });
        expect(withheldOf(legacy)).toEqual(want.withheld);
        if (want.complete === true) {
          expect(legacy.kind).toBe("view");
        } else {
          // `pass` when the registry has never seen the connector (S15): the
          // existing path answers all the same.
          expect(["legacy", "pass"]).toContain(legacy.kind);
          expect((legacy as { pending?: { runs: number } }).pending?.runs).toBe(
            want.pending,
          );
        }
      });

      it("a grant reads only what is published and is told nothing", async () => {
        const rig = await open(row);
        const decision = await resolve(rig, row, { owner: false });
        expect(withheldOf(decision)).toEqual([]);
        expect((decision as { pending?: unknown }).pending ?? null).toBeNull();
        const published = await readIds(decision);
        if (row.base.length > 0 && row.scope === undefined) {
          const baseComplete = row.base.every((b) => b.full);
          expect(published).toEqual(baseComplete ? ["a", "b"] : null);
        }
        for (const file of [false, true]) {
          for (const connection of [false, true]) {
            const read = await api(rig, row, {
              builder: true,
              file,
              connection,
            });
            expect(read.header).toBeNull();
            expect(read.bodyWithheld).toBeNull();
          }
        }
      });

      it("every owner response carries the withheld runs", async () => {
        const rig = await open(row);
        const owner = await resolve(rig, row, { owner: true });
        const viewServes = (await readIds(owner)) !== null;
        const reads: Api[] = [
          await api(rig, row, { builder: false, file: false }),
          await api(rig, row, { builder: false, file: true }),
          await api(rig, row, {
            builder: false,
            file: false,
            connection: true,
          }),
        ];
        for (const read of reads) {
          if (want.withheld.length === 0) {
            expect(read.header).toBeNull();
            expect(read.bodyWithheld).toBeNull();
          } else {
            expect(read.header).toBe("connector_update_required");
            expect(read.bodyWithheld).toEqual(want.withheld);
          }
        }
        if (!viewServes) {
          // No view: no file is a missing-body error, a named connection
          // that has no view is a refusal, a file is the legacy body.
          expect(reads[0]!.status).toBe(404);
          expect(reads[1]!.source).toBe("legacy");
          expect(reads[2]!.status).toBe(404);
        }
      });

      it("the writer publishes no run the owner was shown, and marks every run it refuses", async () => {
        const rig = await open(row);
        const before = await resolve(rig, row, { owner: true });
        const shown = await readIds(before);
        const statuses = await rig.publish();
        await rig.sync();
        const refused = statuses
          .filter((s) =>
            Object.values(s.streams).some(
              (st) => st.problem === "connector_update_required",
            ),
          )
          .map((s) => s.runId)
          .sort();
        // Every refused run is withheld before publish, and none of its rows
        // is shown.
        for (const id of refused) expect(want.withheld).toContain(id);
        if (shown) {
          for (const spec of row.runs.filter((r) =>
            refused.includes(r.runId),
          )) {
            for (const r of spec.rows) {
              expect(shown).not.toContain(String(r["id"] ?? r["uid"]));
            }
          }
        }
        const after = await resolve(rig, row, { owner: true });
        expect(withheldOf(after)).toEqual(want.withheldAfter);
        // What a complete view showed before is a view of what was published.
        const published = await readIds(after);
        if (shown && published && want.complete && want.withheld.length === 0) {
          expect(published).toEqual(shown);
        }
        // A grant now reads what was published, whatever the owner reads.
        if (published && want.withheldAfter.length === 0) {
          const grant = await readIds(
            await resolve(rig, row, { owner: false }),
          );
          expect(grant).toEqual(published);
        }
      });
    });
  }
});

describe("own-writes-state-table.md", () => {
  it("has a row for every case", () => {
    const doc = readFileSync(
      new URL("./own-writes-state-table.md", import.meta.url),
      "utf8",
    );
    for (const row of ROWS)
      expect(doc).toMatch(new RegExp(`^\\| ${row.id}\\s`, "m"));
  });
});
