/**
 * S11: the server imports and then retires its OWN legacy store (`index.db`
 * and `data/`) for a switched owner. No host supplies a port. Most tests boot
 * the real server over a real legacy store and drive it only through the
 * Account's answer, as a host does; the ones that take a seam away build the
 * server's runner directly with every input spelled out.
 */
import { existsSync, mkdirSync } from "node:fs";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ServerContext } from "../bootstrap.js";
import { initializeDatabase } from "../storage/index-schema.js";
import {
  HEADERS,
  STREAMS,
  ROWS_PER_STREAM,
  boot,
  direct,
  filesLeft,
  lineOf,
  readIndex,
  readLocal,
  rowsOf,
  scratch,
  storedRows,
  switchOn,
  watchRun,
  writeDeclared,
  writeLegacyStore,
  type Declared,
} from "./legacy-migration-fixture.test-utils.js";

const contexts: ServerContext[] = [];
const closers: Array<() => Promise<void>> = [];
const directories: string[] = [];
afterEach(async () => {
  for (const context of contexts.splice(0)) await context.cleanup();
  for (const close of closers.splice(0)) await close();
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

async function world() {
  const base = await scratch("legacy-migration-");
  directories.push(base);
  const root = join(base, "root");
  const declared = await writeDeclared(join(base, "declared"));
  return { base, root, declared };
}

async function start(
  root: string,
  declared: Declared | null,
  options: Parameters<typeof boot>[2] = {},
) {
  const booted = await boot(root, declared, options);
  contexts.push(booted.context);
  return booted;
}

async function stop(context: ServerContext) {
  await context.cleanup();
  contexts.splice(contexts.indexOf(context), 1);
}

/** The legacy store's own counts: current rows, retained versions, indexed files. */
const legacyCounts = (root: string) =>
  readIndex(root, (db) => ({
    rows: db.prepare("SELECT count(*) AS n FROM pdpp_records").get(),
    versions: db.prepare("SELECT count(*) AS n FROM pdpp_record_changes").get(),
    files: db.prepare("SELECT count(*) AS n FROM data_files").get(),
  }));

const localCounts = (root: string) =>
  readLocal(root, (db) => ({
    changes: db
      .prepare(
        "SELECT count(*) AS n, coalesce(max(seq), 0) AS seq FROM record_changes",
      )
      .get(),
    records: db.prepare("SELECT count(*) AS n FROM records").get(),
  }));

describe("legacy-migration-nine-stream-real-db", () => {
  it("imports every key and body, replays identically, keeps the old versions, and survives a same-root reopen", async () => {
    const { root, declared } = await world();
    writeLegacyStore(root);
    const before = legacyCounts(root);
    // Each key was written twice: the store retains both versions.
    expect(before.versions).toEqual({
      n: STREAMS.length * ROWS_PER_STREAM * 2,
    });
    expect(filesLeft(root)).toHaveLength(6);

    const first = await start(root, declared, { retireLegacy: true });
    const run = await switchOn(first.context);
    expect((await run.finished).message).toBe("legacy retirement finished");
    expect(lineOf(run.lines, "legacy store import finished")).toEqual({
      imported: 9,
      stopped: false,
    });
    expect(lineOf(run.lines, "legacy retirement finished")).toMatchObject({
      mode: "delete",
      files: 6,
      deleted: 6,
      unimported: 1,
      readbackFailures: 0,
    });

    // Key and body read-back for each of the nine streams.
    expect(STREAMS).toHaveLength(9);
    const readAll = async (context: ServerContext) =>
      Object.fromEntries(
        await Promise.all(
          STREAMS.map(async (stream) => [
            stream,
            await storedRows(context, stream),
          ]),
        ),
      );
    const stored = await readAll(first.context);
    for (const stream of STREAMS) {
      expect(stored[stream]!.map((r) => r.key).sort(), stream).toEqual(
        rowsOf(stream).map((r) => r.id),
      );
      for (const row of rowsOf(stream))
        expect(
          stored[stream]!.find((r) => r.key === row.id)?.body,
          stream,
        ).toEqual(row);
    }
    expect(
      readLocal(root, (db) =>
        db
          .prepare(
            "SELECT state, count(*) AS n FROM import_ledger GROUP BY state",
          )
          .all(),
      ),
    ).toEqual([{ state: "retired", n: 9 }]);

    // Old files are gone; the retained versions of the old store are not.
    expect(filesLeft(root)).toEqual([]);
    expect(legacyCounts(root)).toEqual({ ...before, files: { n: 0 } });

    // Identical replay, on a same-root reopen: nothing is read again, and the
    // database holds the same rows and the same change log.
    const changes = localCounts(root);
    await stop(first.context);
    const second = await start(root, declared, { retireLegacy: true });
    const again = watchRun(second.context);
    await second.context.startBackgroundServices();
    expect((await again.finished).message).toBe("legacy retirement finished");
    expect(lineOf(again.lines, "legacy store import finished")).toEqual({
      "already-imported": 9,
      stopped: false,
    });
    expect(await readAll(second.context)).toEqual(stored);
    expect(localCounts(root)).toEqual(changes);
  }, 180_000);
});

/** A staged host upload for one stream: the seed route a Desktop host uses. */
async function uploadSeed(
  context: ServerContext,
  stream: string,
  rows: object[],
) {
  const response = await context.app.request(
    `/v1/stream-sync/seed/github/${stream}`,
    {
      method: "PUT",
      headers: { ...HEADERS, "Content-Type": "application/x-ndjson" },
      body: [
        JSON.stringify({
          primaryKey: ["id"],
          profile: { key: "github", version: "1" },
          records: rows.length,
        }),
        ...rows.map((row) => JSON.stringify(row)),
        "",
      ].join("\n"),
    },
  );
  expect(response.status).toBe(202);
}

/**
 * A stream the host already seeded from an upload, then a legacy store that
 * holds an older copy of the same key and two more keys. Both imports stamp
 * `(0, 'seed')`; the merge keeps the row it has for an equal stamp
 * (`merge.ts`: "A strictly newer stamp (o, then r) wins; an equal or older one
 * changes no stamped fields"), so the first import of a key stays.
 */
async function seededThenLegacy(options: { windowClosed: boolean }) {
  const { root, declared } = await world();
  const one = await start(root, declared, { retireLegacy: true });
  await (
    await switchOn(one.context)
  ).finished;
  const seedRows = [
    { id: "repositories-0", n: 0, text: "seed" },
    { id: "seed-only", n: 9, text: "seed" },
  ];
  await uploadSeed(one.context, "repositories", seedRows);
  await stop(one.context);

  writeLegacyStore(root, { repositories: rowsOf("repositories") });
  if (options.windowClosed)
    // A real write already owns the stream: `floor_o` is set by run end.
    readLocal(
      root,
      (db) =>
        db
          .prepare(
            "UPDATE stream_state SET floor_o = 1 WHERE stream = 'repositories'",
          )
          .run(),
      true,
    );
  const two = await start(root, declared, { retireLegacy: true });
  const run = watchRun(two.context);
  await two.context.startBackgroundServices();
  await run.finished;
  return { root, context: two.context, run, seedRows };
}

describe("legacy-migration-seed-first", () => {
  it("a seed already in the database survives an older legacy copy; the store only adds the keys the database lacks", async () => {
    const { root, context, run, seedRows } = await seededThenLegacy({
      windowClosed: false,
    });
    const rows = await storedRows(context, "repositories");
    expect(Object.fromEntries(rows.map((r) => [r.key, r.body]))).toEqual({
      "repositories-0": seedRows[0],
      "seed-only": seedRows[1],
      "repositories-1": rowsOf("repositories")[1],
      "repositories-2": rowsOf("repositories")[2],
    });
    expect(lineOf(run.lines, "legacy store import finished")).toMatchObject({
      imported: 9,
    });
    expect(filesLeft(root)).toEqual([]);
  }, 180_000);

  it("a stream that a real write already owns refuses the legacy copy; it is counted and its file still retires", async () => {
    const { root, context, run, seedRows } = await seededThenLegacy({
      windowClosed: true,
    });
    const rows = await storedRows(context, "repositories");
    expect(
      rows.map((r) => r.body).sort((a, b) => a.id.localeCompare(b.id)),
    ).toEqual([seedRows[0], seedRows[1]]);
    expect(lineOf(run.lines, "legacy store import finished")).toMatchObject({
      "refused:seed_window_closed": 1,
      imported: 8,
    });
    expect(filesLeft(root)).toEqual([]);
  }, 180_000);
});

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("legacy-migration-switched-owner-only", () => {
  it("an owner with no answer, or an Off answer, imports and retires nothing, at boot or on the answer", async () => {
    const { root, declared } = await world();
    writeLegacyStore(root);
    const { context } = await start(root, declared, { retireLegacy: true });
    const watch = watchRun(context);
    watch.finished.catch(() => undefined);

    await context.startBackgroundServices();
    await sleep(300);
    await context.accountModeAuthority.submitEvidence({
      owner: context.serverOwner!,
      state: "off",
    });
    await sleep(300);

    expect(watch.lines.filter((l) => /legacy/i.test(l.message))).toEqual([]);
    expect(filesLeft(root)).toHaveLength(6);
    expect(existsSync(join(root, "localdb"))).toBe(false);
    expect(legacyCounts(root).files).toEqual({ n: 6 });

    // The same store imports once the owner is switched.
    const switched = watchRun(context);
    await context.accountModeAuthority.submitEvidence({
      owner: context.serverOwner!,
      state: "on",
    });
    expect((await switched.finished).message).toBe(
      "legacy retirement finished",
    );
    expect(filesLeft(root)).toEqual([]);
  }, 180_000);

  it("the runner itself refuses an owner that is not switched, before reading or erasing", async () => {
    const { base, root } = await world();
    writeLegacyStore(root);
    const h = await direct(base, root, {
      verdict: () => "allow",
      retireLegacy: true,
    });
    closers.push(h.close);
    await expect(h.run()).rejects.toThrow("legacy_access_unavailable");
    expect(filesLeft(root)).toHaveLength(6);
    expect(await h.receipts()).toEqual([]);
    expect(h.lines).toEqual([]);
  }, 60_000);
});

describe("legacy-migration-no-old-writer", () => {
  it("a legacy write in flight finishes before the switch lands, and none starts after it", async () => {
    const { root, declared } = await world();
    writeLegacyStore(root);
    const { context } = await start(root, declared, { retireLegacy: true });
    const owner = context.serverOwner!;
    await context.accountModeAuthority.submitEvidence({ owner, state: "off" });

    // A legacy write is under way when the Account answers On.
    let release!: () => void;
    let finishedWrite = false;
    const inFlight = context.legacyWriteSeal.commit(
      () =>
        new Promise<void>((resolve) => {
          release = () => {
            finishedWrite = true;
            resolve();
          };
        }),
    );
    const watch = watchRun(context);
    const answered = context.accountModeAuthority.submitEvidence({
      owner,
      state: "on",
    });
    let landed = false;
    void answered.then(() => (landed = true));
    await sleep(200);
    expect(landed).toBe(false);
    expect(watch.lines.filter((l) => /legacy/i.test(l.message))).toEqual([]);

    release();
    await inFlight;
    await answered;
    expect(finishedWrite).toBe(true);

    // No old writer starts while the import runs, or after it.
    let ran = 0;
    const attempt = () =>
      context.legacyWriteSeal.commit(() => void ran++).catch((error) => error);
    expect(await attempt()).toMatchObject({
      name: "LegacyWriteRefusedError",
      verdict: "switched",
    });
    expect((await watch.finished).message).toBe("legacy retirement finished");
    expect(await attempt()).toMatchObject({ name: "LegacyWriteRefusedError" });
    expect(ran).toBe(0);
  }, 180_000);

  it("shutdown stops the run: no further source is read and no file is erased", async () => {
    const { base, root } = await world();
    writeLegacyStore(root);

    // Stopped before it starts: nothing is read.
    const early = await direct(base, root, { retireLegacy: true });
    closers.push(early.close);
    const stopped = new AbortController();
    stopped.abort();
    await early.run(stopped.signal);
    expect(await early.receipts()).toEqual([]);
    expect(lineOf(early.lines, "legacy retirement finished")).toBeUndefined();
    expect(filesLeft(root)).toHaveLength(6);

    // Stopped as the import ends: the sources are kept, no file is erased.
    mkdirSync(join(base, "b"));
    const controller = new AbortController();
    const late = await direct(join(base, "b"), root, {
      retireLegacy: true,
      onLog: (message) => {
        if (message === "legacy store import finished") controller.abort();
      },
    });
    closers.push(late.close);
    await late.run(controller.signal);
    expect(lineOf(late.lines, "legacy store import finished")).toMatchObject({
      imported: 9,
    });
    expect(lineOf(late.lines, "legacy retirement finished")).toBeUndefined();
    expect(await late.receipts()).toHaveLength(9);
    expect(filesLeft(root)).toHaveLength(6);
  }, 120_000);

  it("an owner that leaves the switched state mid-run stops the run: no file is erased", async () => {
    const { base, root } = await world();
    writeLegacyStore(root);
    let verdict: "switched" | "allow" = "switched";
    const h = await direct(base, root, {
      verdict: () => verdict,
      retireLegacy: true,
    });
    closers.push(h.close);
    // A legacy writer would be admitted from the moment the import ends.
    const push = h.lines.push.bind(h.lines);
    h.lines.push = (...lines) => {
      if (lines.some((l) => l.message === "legacy store import finished"))
        verdict = "allow";
      return push(...lines);
    };
    await h.run();
    expect(filesLeft(root)).toHaveLength(6);
    expect(h.lines.map((l) => l.message)).toContain(
      "legacy retirement failed; it runs again at the next import run",
    );
    expect(await h.receipts()).toEqual(
      Array.from({ length: 9 }, () => ({ state: "imported" })),
    );
  }, 60_000);
});

describe("legacy-migration-missing-seam-fails", () => {
  it("fails closed, reading and erasing nothing, when a seam is missing", async () => {
    const { base, root } = await world();
    writeLegacyStore(root);
    const other = await world();
    writeLegacyStore(other.root);

    // The owner's database is unavailable (stream mode cannot open it).
    const noDb = await direct(base, root, {
      retireLegacy: true,
      getDeps: async () => {
        throw new Error("STREAM_READ_UNAVAILABLE");
      },
    });
    closers.push(noDb.close);
    await expect(noDb.run()).rejects.toThrow("STREAM_READ_UNAVAILABLE");

    // The handle is not this root's index.db: the binding is not proven.
    const wrong = initializeDatabase(join(other.root, "index.db"));
    closers.push(async () => wrong.close());
    mkdirSync(join(base, "b"));
    mkdirSync(join(base, "c"));
    const bound = await direct(join(base, "b"), root, {
      retireLegacy: true,
      index: wrong,
    });
    closers.push(bound.close);
    await expect(bound.run()).rejects.toThrow("legacy_identity_mismatch");

    // The registry does not answer: the import cannot start, nothing retires.
    const offline = await direct(join(base, "c"), root, {
      retireLegacy: true,
      registryDown: true,
    });
    closers.push(offline.close);
    await expect(offline.run()).rejects.toThrow("registry_unreachable");

    expect(filesLeft(root)).toHaveLength(6);
    expect(filesLeft(other.root)).toHaveLength(6);
    for (const h of [noDb, bound, offline])
      expect(await h.receipts()).toEqual([]);
    expect(await offline.records("repositories")).toEqual([]);
  }, 120_000);

  it("an imported store needs no registry on a later run, and its retirement still runs", async () => {
    const { base, root } = await world();
    writeLegacyStore(root);
    const first = await direct(base, root);
    await first.run();
    await first.close();
    expect(filesLeft(root)).toHaveLength(6);

    const later = await direct(base, root, {
      retireLegacy: true,
      registryDown: true,
    });
    closers.push(later.close);
    await later.run();
    expect(lineOf(later.lines, "legacy store import finished")).toMatchObject({
      "already-imported": 9,
    });
    expect(lineOf(later.lines, "legacy retirement finished")).toMatchObject({
      mode: "delete",
      deleted: 6,
    });
    expect(filesLeft(root)).toEqual([]);
  }, 120_000);

  it("a missing verified manifest imports nothing; with removal off the files stay", async () => {
    const { base, root } = await world();
    writeLegacyStore(root);
    const h = await direct(base, root, { undeclared: true });
    closers.push(h.close);
    await h.run();
    expect(lineOf(h.lines, "legacy store import finished")).toMatchObject({
      "excluded:undeclared_source": 9,
    });
    expect(await h.receipts()).toEqual([]);
    expect(filesLeft(root)).toHaveLength(6);
    expect(lineOf(h.lines, "legacy retirement finished")).toMatchObject({
      mode: "readback-only",
      deleted: 0,
    });
  }, 60_000);
});
