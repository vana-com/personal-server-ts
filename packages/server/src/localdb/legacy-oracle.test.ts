/**
 * The oracle for the switch from legacy files: read every stream the way the
 * old store holds it, switch, read what the database holds, and compare. Every
 * difference must be in the report, with a reason. Nothing here trusts the
 * importer's own counts: the expected key set and bodies come from the old
 * store's rows alone.
 */
import { join } from "node:path";
import { rm } from "node:fs/promises";
import { afterEach, expect, it } from "vitest";
import { initializeDatabase } from "../storage/index-schema.js";
import { openRecordStore } from "../pdpp/records-bootstrap.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  INSTANCE,
  SOURCE_ID,
  STREAMS,
  direct,
  rowsOf,
  scratch,
  writeLegacyStore,
} from "./legacy-migration-fixture.test-utils.js";

const closers: Array<() => Promise<void>> = [];
const directories: string[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

const ARCHIVE = "github-archive";
const STREAM = "repositories";

/**
 * Damages the `repositories` stream of the fixture, one way per row:
 * - `-0` is stored text that is not a JSON object;
 * - `-1` has no `id` in its body, so no identity;
 * - `-2` is deleted;
 * and an older live instance of the same source holds `-1`, `-2` and a key
 * (`-9`) the newer instance never had. Only the newest live instance is
 * imported: the older one is excluded and counted, never merged.
 */
function damage(root: string) {
  const db = initializeDatabase(join(root, "index.db"));
  try {
    const store = openRecordStore(db, false);
    store.registerConnection({
      instance: ARCHIVE,
      sourceId: SOURCE_ID,
      method: CONNECTOR,
      label: "Older copy",
    });
    const older = [
      ...rowsOf(STREAM, "older").slice(1),
      { id: `${STREAM}-9`, n: 9, text: "older only" },
    ];
    store.ingestBatch(
      older.map((row) => ({
        instance: ARCHIVE,
        stream: STREAM,
        key: row.id,
        data: row,
        emitted_at: "2024-01-01T00:00:00.000Z",
      })),
      () => "mutable_state",
      () => ["id"],
      { method: CONNECTOR, generation: 1 },
    );
    const set = db.prepare(
      "UPDATE pdpp_records SET data = ? WHERE instance = ? AND stream = ? AND record_key = ?",
    );
    set.run("[1,2]", INSTANCE, STREAM, `${STREAM}-0`);
    set.run('{"n":1}', INSTANCE, STREAM, `${STREAM}-1`);
    db.prepare(
      "UPDATE pdpp_records SET deleted = 1 WHERE instance = ? AND stream = ? AND record_key = ?",
    ).run(INSTANCE, STREAM, `${STREAM}-2`);
  } finally {
    db.close();
  }
}

/** What the old store holds, read straight from its rows: every live row, and
 * the keys deleted. */
function legacyRows(root: string) {
  const db = initializeDatabase(join(root, "index.db"));
  try {
    const live = db
      .prepare(
        "SELECT instance, stream, record_key, data FROM pdpp_records WHERE deleted = 0 ORDER BY stream, record_key",
      )
      .all() as {
      instance: string;
      stream: string;
      record_key: string;
      data: string;
    }[];
    const deleted = db
      .prepare(
        "SELECT instance, stream, record_key FROM pdpp_records WHERE deleted = 1",
      )
      .all() as { instance: string; stream: string; record_key: string }[];
    return { live, deleted };
  } finally {
    db.close();
  }
}

/** The bodies the database should hold: per stream and id, the body of the
 * newest instance's live row. A row with no `id`, or that is not an object, has
 * no identity. */
function expectedBodies(root: string) {
  const { live } = legacyRows(root);
  const out = new Map<string, Record<string, unknown>>();
  for (const row of live) {
    if (row.instance !== INSTANCE) continue;
    const body: unknown = JSON.parse(row.data);
    if (!body || typeof body !== "object" || Array.isArray(body)) continue;
    const id = (body as Record<string, unknown>)["id"];
    if (typeof id !== "string") continue;
    out.set(`${row.stream}/${id}`, body as Record<string, unknown>);
  }
  return out;
}

async function stored(h: Awaited<ReturnType<typeof direct>>) {
  const rows = await h.local.query<{
    stream: string;
    record_key: string;
    body: string;
  }>(
    "SELECT stream, record_key, body FROM records WHERE connection_id = ? ORDER BY stream, record_key",
    [CONNECTION_ID],
  );
  return new Map(
    rows.map((row) => {
      const body = JSON.parse(row.body) as Record<string, unknown>;
      return [`${row.stream}/${String(body["id"])}`, body] as const;
    }),
  );
}

it("oracle: every difference between the old store and the database is in the report, with a reason", async () => {
  const base = await scratch("legacy-oracle-");
  directories.push(base);
  const root = join(base, "root");
  writeLegacyStore(root);
  damage(root);
  const expected = expectedBodies(root);
  const { live } = legacyRows(root);
  const newest = live.filter((row) => row.instance === INSTANCE);
  const older = live.filter((row) => row.instance === ARCHIVE);

  const h = await direct(base, root);
  closers.push(h.close);
  await h.run();

  // The same keys and the same bodies.
  const got = await stored(h);
  expect([...got.keys()].sort()).toEqual([...expected.keys()].sort());
  for (const [name, body] of expected) expect(got.get(name)).toEqual(body);

  // Every row of the newest instance is imported or reported under a reason;
  // the older instance is excluded whole, and counted.
  const report = h.runner.report()!;
  expect(report.refused).toEqual([]);
  expect(report.excluded).toContainEqual({
    reason: "older_instance",
    streams: 1,
    rows: older.length,
  });
  expect(report.rows.legacy).toBe(newest.length);
  const quarantined = Object.values(report.rows.quarantined).reduce(
    (a, b) => a + b,
    0,
  );
  expect(report.rows.imported + report.rows.blocked + quarantined).toBe(
    newest.length,
  );
  expect(report.rows.imported).toBe(expected.size);
  expect(report.rows.quarantined).toEqual({
    not_an_object: 1,
    missing_key_field: 1,
  });
  // A key deleted in the newest instance stays out, and nothing of the older
  // instance fills it, or the key its damaged row could not claim.
  expect(got.has(`${STREAM}/${STREAM}-2`)).toBe(false);
  expect(got.has(`${STREAM}/${STREAM}-1`)).toBe(false);
  expect(got.has(`${STREAM}/${STREAM}-9`)).toBe(false);
  // The streams nothing damaged import whole.
  for (const stream of STREAMS.filter((s) => s !== STREAM))
    expect(
      [...got.keys()].filter((k) => k.startsWith(`${stream}/`)),
    ).toHaveLength(3);

  // A second run reads nothing new and the report says the same.
  await h.run();
  const again = h.runner.report()!;
  expect(again.alreadyImported).toBe(STREAMS.length);
  expect(again.rows).toEqual(report.rows);
  expect(await stored(h)).toEqual(got);
}, 120_000);
