// The fake registry keeps the real registry's connection-log fence: a stream
// row of a connection that keeps its data in a log loses, whatever else the
// request does with the log row. These cases are the real registry's own
// (a gap, a stale version, a failed head condition, a replay, a refresh).
import { describe, expect, it } from "vitest";
import { createFakeGateway } from "./fake-gateway.js";

const OWNER = `0x${"22".repeat(20)}` as const;
const TOMBSTONE = "tombstone";
const STREAM = "pdpp.fixture~.tracks";
const LOG = "pdpp.fixture~.~log";
const OTHER_STREAM = "pdpp.other~.runs";

const hash = (s: string) =>
  `0x${Buffer.from(s).toString("hex").padEnd(64, "0")}`;
const row = (
  scope: string,
  version: number,
  tag = "a",
  extra: Record<string, unknown> = {},
) => ({
  scope,
  expectedVersion: String(version),
  dataHash: hash(`${scope}:${version}:${tag}`),
  metadataHash: hash(`meta:${scope}:${version}:${tag}`),
  ...extra,
});

function gateway(refresh = false) {
  return createFakeGateway({
    owner: OWNER,
    connectionLogFence: true,
    refresh,
    isTombstone: (v) => v.dataHash === TOMBSTONE,
  });
}
const seed = (g: ReturnType<typeof gateway>, r: ReturnType<typeof row>) =>
  g.write(r.scope, { dataHash: r.dataHash, metadataHash: r.metadataHash });

async function batch(g: ReturnType<typeof gateway>, rows: unknown[]) {
  const response = await g.fetch("https://gateway.test/v1/data/batch", {
    method: "POST",
    body: JSON.stringify({ rows, requires: [] }),
  });
  return (await response.json()).results as Array<{
    scope: string;
    status: number;
    reason?: string;
  }>;
}
const byScope = (results: Array<{ scope: string }>) =>
  new Map(results.map((r) => [r.scope, r]));

describe("the fake registry's connection-log fence, in a batch", () => {
  it("fences a stream row of a connection that has a log row", async () => {
    const g = gateway();
    seed(g, row(LOG, 1));
    const out = await batch(g, [row(STREAM, 1), row(OTHER_STREAM, 1)]);
    expect(out.map((r) => [r.status, r.reason ?? null])).toEqual([
      [409, "log-exists"],
      // All or nothing: the row beside the loser is not written.
      [424, null],
    ]);
    expect(g.rowsOf(STREAM)).toBe(0);
    expect(g.rowsOf(OTHER_STREAM)).toBe(0);
  });

  for (const order of ["log first", "stream first"] as const) {
    const arrange = (log: unknown, stream: unknown) =>
      order === "log first" ? [log, stream] : [stream, log];

    it(`${order}: a log row at a gap version does not exempt the stream row`, async () => {
      const g = gateway();
      seed(g, row(LOG, 1));
      const out = byScope(await batch(g, arrange(row(LOG, 3), row(STREAM, 1))));
      expect(out.get(LOG)).toMatchObject({ status: 409, reason: "gap" });
      expect(out.get(STREAM)).toMatchObject({
        status: 409,
        reason: "log-exists",
      });
      expect(g.rowsOf(STREAM)).toBe(0);
    });

    it(`${order}: a stale log row does not exempt the stream row`, async () => {
      const g = gateway();
      seed(g, row(LOG, 1));
      seed(g, row(LOG, 2));
      const out = byScope(
        await batch(g, arrange(row(LOG, 1, "b"), row(STREAM, 1))),
      );
      expect(out.get(LOG)).toMatchObject({ status: 409, reason: "stale" });
      expect(out.get(STREAM)).toMatchObject({
        status: 409,
        reason: "log-exists",
      });
      expect(g.rowsOf(STREAM)).toBe(0);
    });

    it(`${order}: a log row whose head condition fails does not exempt the stream row`, async () => {
      const g = gateway();
      seed(g, row(LOG, 1));
      const failing = row(LOG, 2, "a", {
        expectedHeadDataHash: hash("not-the-head"),
      });
      const out = byScope(await batch(g, arrange(failing, row(STREAM, 1))));
      expect(out.get(LOG)).toMatchObject({
        status: 409,
        reason: "head-mismatch",
      });
      expect(out.get(STREAM)).toMatchObject({
        status: 409,
        reason: "log-exists",
      });
      expect(g.rowsOf(STREAM)).toBe(0);
    });

    it(`${order}: a replay of a stored log version does not exempt a new stream row`, async () => {
      const g = gateway(false);
      const stored = row(LOG, 1);
      seed(g, stored);
      const replaying = createFakeGateway({
        owner: OWNER,
        connectionLogFence: true,
        replay: "created",
        isTombstone: (v) => v.dataHash === TOMBSTONE,
      });
      seed(replaying, stored);
      const out = byScope(
        await batch(replaying, arrange(stored, row(STREAM, 1))),
      );
      expect(out.get(LOG)).toMatchObject({ status: 201 });
      expect(out.get(STREAM)).toMatchObject({
        status: 409,
        reason: "log-exists",
      });
      expect(replaying.rowsOf(STREAM)).toBe(0);
    });

    it(`${order}: a batch that creates the log row refuses the stream row too`, async () => {
      const g = gateway();
      const out = byScope(await batch(g, arrange(row(LOG, 1), row(STREAM, 1))));
      // The stream row loses, so the request writes nothing: not the log row
      // either.
      expect(out.get(LOG)).toMatchObject({ status: 424 });
      expect(out.get(STREAM)).toMatchObject({
        status: 409,
        reason: "log-exists",
      });
      expect(g.rowsOf(STREAM)).toBe(0);
      expect(g.rowsOf(LOG)).toBe(0);
    });
  }

  it("fences a refresh of a pending stream head, as it fences an append", async () => {
    const g = gateway(true);
    const before = row(STREAM, 1, "before");
    seed(g, before);
    seed(g, row(LOG, 1));
    const [out] = await batch(g, [row(STREAM, 1, "after")]);
    expect(out).toMatchObject({ status: 409, reason: "log-exists" });
    expect(g.versions.get(STREAM)?.[0]?.dataHash).toBe(before.dataHash);
  });

  it("lets a tombstone through", async () => {
    const g = gateway();
    seed(g, row(LOG, 1));
    const [out] = await batch(g, [
      { ...row(STREAM, 1), dataHash: TOMBSTONE, metadataHash: TOMBSTONE },
    ]);
    expect(out).toMatchObject({ status: 201 });
  });
});
