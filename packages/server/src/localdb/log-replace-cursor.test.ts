import { appendFile } from "node:fs/promises";
import { afterEach, expect, it, vi } from "vitest";
import { closeWorldDrivers, sName, world } from "./log-world.test-utils.js";
afterEach(closeWorldDrivers);
it.each([100, 1000])(
  "replacement preflight bounds raw body pages at %i keys",
  async (count) => {
    const w = await world({ streams: 1, partTargetBytes: 16384 });
    const a = await w.device("a");
    const s = sName(0);
    await a.run(
      "r1",
      Array.from({ length: count }, (_, id) => ({
        stream: s,
        id,
        v: 1,
        pad: 100,
      })),
    );
    await a.cycle();
    await a.run(
      "r2",
      Array.from({ length: Math.floor(count * 0.75) }, (_, id) => ({
        stream: s,
        id,
        pad: 100,
      })),
      { observedAt: 5000 },
    );
    const query = a.db.query.bind(a.db);
    let maxBodies = 0,
      maxBodyBytes = 0,
      maxPageBytes = 0,
      maxEncodedPageBytes = 0,
      maxStatements = 0;
    const batch = a.db.batch.bind(a.db);
    vi.spyOn(a.db, "batch").mockImplementation((statements) => {
      maxStatements = Math.max(maxStatements, statements.length);
      return batch(statements);
    });
    vi.spyOn(a.db, "query").mockImplementation(async (sql, params) => {
      const rows = await query(sql, params);
      for (const row of rows)
        if (typeof row.page === "string")
          maxEncodedPageBytes = Math.max(
            maxEncodedPageBytes,
            Buffer.byteLength(row.page),
          );
      if (
        /FROM records/.test(sql) &&
        rows.some((r) => typeof r.body === "string")
      ) {
        maxBodies = Math.max(maxBodies, rows.length);
        maxPageBytes = Math.max(
          maxPageBytes,
          rows.reduce(
            (n, r) =>
              n + (typeof r.body === "string" ? Buffer.byteLength(r.body) : 0),
            0,
          ),
        );
        maxBodyBytes = Math.max(
          maxBodyBytes,
          ...rows.map((r) =>
            typeof r.body === "string" ? Buffer.byteLength(r.body) : 0,
          ),
        );
      }
      return rows;
    });
    await a.cycle();
    const beforeOmissions = await a.position();
    await a.run("r3", [{ stream: s, id: 0, v: 3, pad: 100 }], {
      observedAt: 6000,
    });
    await a.cycle();
    const fragments = [...(await w.segments()).values()]
      .filter((segment) => segment.position > beforeOmissions)
      .sort((a, b) => a.position - b.position);
    expect(
      Math.max(
        ...fragments.map((fragment) =>
          Buffer.byteLength(JSON.stringify(fragment.operations)),
        ),
      ),
    ).toBeLessThanOrEqual(16384);
    const completion = fragments.map(
      (segment) => segment.streams.find((meta) => meta.stream === s)!.complete,
    );
    expect(completion).toEqual([
      ...completion.slice(0, -1).map(() => false),
      true,
    ]);
    if (count === 1000) expect(fragments.length).toBeGreaterThan(1);
    expect(
      fragments
        .flatMap((segment) => segment.operations)
        .flatMap((op) => (op.kind === "complete" ? op.omitted : [])),
    ).toHaveLength(Math.floor(count * 0.75) - 1);
    expect(maxBodies).toBeLessThanOrEqual(1);
    expect(maxEncodedPageBytes).toBeGreaterThan(0);
    expect(maxEncodedPageBytes).toBeLessThanOrEqual(2 * 16384 + 65536);
    expect(maxPageBytes).toBeLessThanOrEqual(16384);
    expect(maxStatements).toBeLessThanOrEqual(32);
    if (process.env.LOG_REPLACEMENT_RECEIPTS)
      await appendFile(
        process.env.LOG_REPLACEMENT_RECEIPTS,
        JSON.stringify({
          count,
          maxBodies,
          maxBodyBytes,
          maxPageBytes,
          maxEncodedPageBytes,
          maxStatements,
        }) + "\n",
      );
    const b = await w.device("b");
    await b.cycle();
    expect(await b.rows()).toEqual(await a.rows());
  },
  120000,
);

it("keeps an oversized omission admission failure durable without advancing publication", async () => {
  const w = await world({ streams: 1 }),
    a = await w.device("a"),
    stream = sName(0);
  await a.run("initial", [{ stream, id: "x".repeat(70 * 1024), v: 1 }]);
  await a.cycle();
  const before = await a.position();
  await a.run("omission", [], { observedAt: 5000 });
  await expect(a.cycle()).rejects.toThrow("admission");
  expect(await a.position()).toBe(before);
  expect(
    await a.db.query(
      "SELECT state,reason FROM workspace_attempts WHERE state='failed' AND reason='admission'",
    ),
  ).not.toHaveLength(0);
  expect(await a.db.query("SELECT job FROM workspace_jobs")).not.toHaveLength(
    0,
  );
}, 120000);
