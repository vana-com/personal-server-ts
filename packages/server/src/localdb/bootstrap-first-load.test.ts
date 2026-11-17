import { afterEach, describe, expect, it, vi } from "vitest";
import type * as StreamSync from "@opendatalabs/personal-server-ts-stream-sync";
import {
  applyConnection,
  type LocalSyncDeps,
} from "../../../core/src/localdb/index.js";
import { createLocalListing } from "../../../core/src/localdb/listing.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import {
  pkHash,
  encodeSegment,
  digestSegment,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { bootstrapSchema } from "../../../core/src/localdb/bootstrap-swap.js";
import { copyBootstrapRecords } from "../../../core/src/localdb/bootstrap-copy.js";
import { firstOwnerRow } from "./bench/owner-row.test-utils.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  LOG,
  closeWorldDrivers,
  world,
  sName,
} from "./log-world.test-utils.js";

const writer = vi.hoisted(() => ({ lie: false }));
vi.mock("@opendatalabs/personal-server-ts-stream-sync", async (original) => {
  const real = await original<typeof StreamSync>();
  return {
    ...real,
    segmentRemoves: (ops: Parameters<typeof real.segmentRemoves>[0]) =>
      writer.lie ? false : real.segmentRemoves(ops),
  };
});
afterEach(async () => {
  writer.lie = false;
  await closeWorldDrivers();
});
type World = Awaited<ReturnType<typeof world>>;
type Device = Awaited<ReturnType<World["device"]>>;
const scope = `pdpp.${CONNECTOR}.${sName(0)}`;
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
};
async function connect(
  w: World,
  name: string,
  beforeGet?: (key: string) => Promise<void>,
) {
  const d = await w.device(name, {
    progressiveFirstLoad: true,
    keyedFirstLoad: false,
    beforeGet,
  });
  Object.assign(d.deps, { bootstrapFirstLoad: true });
  await d.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
  return d;
}
async function ownerSnapshot(d: Device) {
  const queue = connectionQueue(),
    done = deferred();
  const held = queue.run(CONNECTION_ID, "apply", () => done.promise);
  try {
    if (
      !(
        await d.db.query("SELECT 1 FROM stream_partial WHERE connection_id=?", [
          CONNECTION_ID,
        ])
      ).length
    ) {
      done.resolve();
      await held;
    }
    const deps = { ...d.deps, queue } as LocalSyncDeps;
    const result = await createLocalResolver(deps, {
      query: createRecordQuery(d.db),
    }).resolve({
      scope,
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    });
    if (result.kind !== "view") return { kind: result.kind, ids: [] };
    const body = await new Response(result.body).json();
    return {
      kind: result.kind,
      ids: body.data.records.map((r: { id: string }) => r.id).sort(),
    };
  } finally {
    done.resolve();
    await held;
  }
}
async function history(w: World) {
  const p = await w.device("publisher");
  const publish = async (
    id: string,
    ids: string[],
    o: number,
    remove = false,
  ) => {
    await p.run(
      id,
      ids.map((id) => ({
        stream: sName(0),
        id,
        ...(remove ? { remove: true } : {}),
      })),
      { full: id === "one", observedAt: o },
    );
    await p.cycle();
  };
  await publish("one", ["safe", "victim"], 10);
  await publish("two", ["b"], 20);
  await publish("three", ["victim"], 30, true);
  await publish("four", ["c"], 40);
  await publish("five", ["d"], 50);
  return p;
}
describe("disk-backed bootstrap swap", () => {
  it("starts tail reads after preview commits and overlaps them with a heap commit", async () => {
    const w = await world({ streams: 1 });
    const p = await history(w);
    const keys = await w.segmentKeys();
    const reached = deferred(),
      release = deferred(),
      ahead = deferred();
    let previewAtTail = false;
    const d = await connect(w, "overlap", async (key) => {
      if (key === keys.get(4)) {
        previewAtTail =
          (
            await d.db.query<{ preview_done: number }>(
              "SELECT preview_done FROM bootstrap_load",
            )
          )[0]?.preview_done === 1;
        ahead.resolve();
      }
    });
    const governor = d.deps.blobs.governor;
    const reserve = governor.reserve.bind(governor);
    let held = 0;
    vi.spyOn(governor, "reserve").mockImplementation(async (...args) => {
      const reservation = await reserve(...args);
      held++;
      return Object.assign(
        () => {
          held--;
          reservation();
        },
        { shrink: reservation.shrink },
      );
    });
    const batch = d.db.batch.bind(d.db);
    d.db.batch = async (statements) => {
      if (
        statements.some(
          (s) =>
            s.sql.includes("INSERT INTO bootstrap_segments") &&
            s.params?.[0] === 2,
        )
      ) {
        reached.resolve();
        await release.promise;
      }
      return batch(statements);
    };
    const applying = applyConnection(d.deps, CONNECTION_ID);
    try {
      await reached.promise;
      await expect.poll(() => previewAtTail, { timeout: 2000 }).toBe(true);
      await ahead.promise;
      expect(held).toBeGreaterThan(0);
    } finally {
      release.resolve();
      await applying;
    }
    await expect.poll(() => held).toBe(0);
    expect(await d.rows()).toEqual(await p.rows());
  });
  it("returns an owner row before a held tail; listing counts only returned keys; final rows match the publication", async () => {
    const w = await world({ streams: 1 });
    const p = await history(w);
    const keys = await w.segmentKeys();
    const reached = deferred(),
      release = deferred();
    const d = await connect(w, "reader", async (key) => {
      if (key === keys.get(4)) {
        reached.resolve();
        await release.promise;
      }
    });
    const applying = applyConnection(d.deps, CONNECTION_ID);
    let firstRow: unknown;
    const earlyRead = (async () => {
      // Before the source is seeded, an owner read can return no data. Retry
      // that decision; a read waiting on the preview must wake before the tail.
      do {
        firstRow = await firstOwnerRow(d.deps, scope);
      } while (firstRow === null);
    })();
    try {
      await Promise.race([reached.promise, applying]);
      await expect.poll(() => firstRow).toMatchObject({ id: "safe" });
      expect(await firstOwnerRow(d.deps, scope)).toMatchObject({ id: "safe" });
      await expect(
        d.db.batch([
          { sql: "DELETE FROM write_ctx" },
          { sql: "UPDATE records SET body='unclassified write'" },
        ]),
      ).rejects.toThrow("bootstrap_busy");
      expect(await ownerSnapshot(d)).toMatchObject({ ids: ["safe"] });
      const listed = await createLocalListing(d.deps).listScopes({
        canRead: () => true,
        includeLoading: true,
      });
      expect(listed.find((s) => s.scope === scope)?.records).toBe(1);
      expect(await d.db.query("SELECT count(*) n FROM records")).toEqual([
        { n: 2 },
      ]);
      expect(
        await createLocalListing(d.deps).listScopes({ canRead: () => true }),
      ).toEqual([]);
    } finally {
      release.resolve();
      await applying;
      await earlyRead;
    }
    expect(await d.rows()).toEqual(await p.rows());
    expect((await ownerSnapshot(d)).ids).toEqual(["b", "c", "d", "safe"]);
    expect(await d.position()).toBe(5);
    expect(await d.db.query("SELECT * FROM bootstrap_load")).toEqual([]);
    expect(await d.db.query("SELECT * FROM stream_partial")).toEqual([]);
  });

  it("hides all exposed preview keys when a false non-removal declaration is rejected", async () => {
    writer.lie = true;
    const w = await world({ streams: 1 });
    await history(w);
    writer.lie = false;
    const keys = await w.segmentKeys(),
      reached = deferred(),
      release = deferred();
    const d = await connect(w, "reader", async (key) => {
      if (key === keys.get(3)) {
        reached.resolve();
        await release.promise;
      }
    });
    const applying = applyConnection(d.deps, CONNECTION_ID);
    const rejected = expect(applying).rejects.toThrow(/removes a key/);
    try {
      await reached.promise;
      expect((await ownerSnapshot(d)).ids).toEqual(["safe", "victim"]);
    } finally {
      release.resolve();
      await rejected;
    }
    expect((await ownerSnapshot(d)).ids).toEqual([]);
    expect(await d.db.query("SELECT failed FROM stream_partial")).toEqual([
      { failed: 1 },
    ]);
    expect(await d.position()).toBe(0);
  });

  it("marks prerequisite removal-fetch failure before preview as stopped", async () => {
    const w = await world({ streams: 1 });
    await history(w);
    const bad = (await w.segmentKeys()).get(3)!;
    const d = await connect(w, "reader", async (key) => {
      if (key === bad) throw new Error("missing prerequisite");
    });
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow(
      "missing prerequisite",
    );
    expect(await d.db.query("SELECT failed FROM stream_partial")).toEqual([
      { failed: 1 },
    ]);
    expect(await d.db.query("SELECT 1 FROM records")).toEqual([]);
  });

  it("retries a failed tail GET from durable receipts without advancing the cursor", async () => {
    const w = await world({ streams: 1 });
    const p = await history(w);
    const keys = await w.segmentKeys();
    let fail = true;
    const d = await connect(w, "retry-get", async (key) => {
      if (fail && key === keys.get(4)) throw new Error("tail unavailable");
    });
    const governor = d.deps.blobs.governor;
    const reserve = governor.reserve.bind(governor);
    let held = 0;
    vi.spyOn(governor, "reserve").mockImplementation(async (...args) => {
      const reservation = await reserve(...args);
      held++;
      return Object.assign(
        () => {
          held--;
          reservation();
        },
        { shrink: reservation.shrink },
      );
    });
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow(
      "tail unavailable",
    );
    await expect.poll(() => held).toBe(0);
    expect(await d.position()).toBe(0);
    expect(await d.db.query("SELECT failed FROM stream_partial")).toEqual([
      { failed: 1 },
    ]);
    expect(await d.db.query("SELECT preview_done FROM bootstrap_load")).toEqual(
      [{ preview_done: 1 }],
    );
    expect(
      await d.db.query(
        "SELECT position FROM bootstrap_segments ORDER BY position",
      ),
    ).toEqual([{ position: 1 }, { position: 2 }, { position: 3 }]);
    fail = false;
    await applyConnection(d.deps, CONNECTION_ID);
    expect(await d.rows()).toEqual(await p.rows());
    expect(await d.position()).toBe(5);
  });

  it("resumes receipted prerequisites when preview publication fails", async () => {
    const w = await world({ streams: 1 });
    const p = await history(w);
    const d = await connect(w, "retry-preview");
    const batch = d.db.batch.bind(d.db);
    let fail = true;
    d.db.batch = async (statements) => {
      if (
        fail &&
        statements.some((s) =>
          s.sql.includes("UPDATE bootstrap_load SET preview_done=1"),
        )
      ) {
        fail = false;
        throw new Error("preview failure");
      }
      return batch(statements);
    };
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow(
      "preview failure",
    );
    expect(await d.db.query("SELECT preview_done FROM bootstrap_load")).toEqual(
      [{ preview_done: 0 }],
    );
    expect(
      await d.db.query(
        "SELECT position FROM bootstrap_segments ORDER BY position",
      ),
    ).toEqual([{ position: 1 }, { position: 3 }]);
    expect(await d.position()).toBe(0);
    await applyConnection(d.deps, CONNECTION_ID);
    expect(await d.rows()).toEqual(await p.rows());
  });

  it("does not publish a bootstrap after its connection is deleted during a tail GET", async () => {
    const w = await world({ streams: 1 });
    await history(w);
    const keys = await w.segmentKeys();
    const reached = deferred(),
      release = deferred();
    const d = await connect(w, "deleted", async (key) => {
      if (key === keys.get(4)) {
        reached.resolve();
        await release.promise;
      }
    });
    const applying = applyConnection(d.deps, CONNECTION_ID);
    const rejected = expect(applying).rejects.toThrow();
    try {
      await reached.promise;
      await d.db.batch([
        {
          sql: "UPDATE connections SET control_state='deleted',deleted_at=1 WHERE connection_id=?",
          params: [CONNECTION_ID],
        },
      ]);
    } finally {
      release.resolve();
      await rejected;
    }
    expect(await d.position()).toBe(0);
  });
  it.each(["swap", "copy"] as const)(
    "advances the visible view token when the %s finish publishes",
    async (mode) => {
      const w = await world({ streams: 1 });
      const peer = await history(w);
      const d = await connect(w, `view-${mode}`);
      if (mode === "copy")
        Object.assign(d.deps, { bootstrapFirstLoadFinish: "copy" });
      const token = async () =>
        (
          await d.db.query<{ version: number }>(
            "SELECT version FROM view_versions WHERE connection_id=?",
            [CONNECTION_ID],
          )
        )[0]?.version ?? 0;
      const initial = await token();
      expect((await ownerSnapshot(d)).ids).toEqual([]);
      const batch = d.db.batch.bind(d.db);
      let beforeFinish = -1;
      let afterFinish = -1;
      let sawSwap = false;
      d.db.batch = async (statements) => {
        const finish = statements.some(
          (statement) => statement.sql === "DELETE FROM bootstrap_load",
        );
        if (!finish) return batch(statements);
        sawSwap = statements.some(
          (statement) => statement.sql === "DROP TABLE records",
        );
        beforeFinish = await token();
        const result = await batch(statements);
        afterFinish = await token();
        return result;
      };
      await applyConnection(d.deps, CONNECTION_ID);
      expect(sawSwap).toBe(mode === "swap");
      expect(beforeFinish).toBeGreaterThanOrEqual(initial);
      expect(afterFinish).toBeGreaterThan(beforeFinish);
      expect((await ownerSnapshot(d)).ids).toEqual(["b", "c", "d", "safe"]);
      expect(await d.rows()).toEqual(await peer.rows());
    },
  );

  it("blocks a foreign insert after the swap decision while bootstrap owns records", async () => {
    const w = await world({ streams: 1 });
    const peer = await history(w);
    const d = await connect(w, "swap-race");
    const other = "pdpp.fixture~1111111111111111";
    await d.db.batch([
      {
        sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES(?,'fixture','1111111111111111',1,'active',1)",
        params: [other],
      },
    ]);
    const batch = d.db.batch.bind(d.db);
    let attempted = false;
    d.db.batch = async (statements) => {
      if (
        !attempted &&
        statements.some((statement) => statement.sql === "DROP TABLE records")
      ) {
        attempted = true;
        await expect(
          batch([
            { sql: "UPDATE write_ctx SET origin='remote' WHERE id=1" },
            {
              sql: `INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,first_o)
            SELECT ?,stream,pk_hash,record_key,stamp_o,stamp_r,?,'foreign-hash',first_o FROM records
            WHERE connection_id=? AND stream='s0' AND record_key='safe'`,
              params: [
                other,
                JSON.stringify({ id: "safe", source: "B" }),
                CONNECTION_ID,
              ],
            },
            { sql: "UPDATE write_ctx SET origin='local' WHERE id=1" },
          ]),
        ).rejects.toThrow("bootstrap_busy");
        expect(
          await d.db.query("SELECT body FROM records WHERE connection_id=?", [
            other,
          ]),
        ).toEqual([]);
      }
      return batch(statements);
    };
    await applyConnection(d.deps, CONNECTION_ID);
    expect(attempted).toBe(true);
    expect(await d.rows()).toEqual(await peer.rows());
    expect(await d.position()).toBe(5);
  });

  it("rolls back a SQL failure after DROP records and resumes from durable segment receipts", async () => {
    const w = await world({ streams: 1 });
    const p = await history(w);
    const d = await connect(w, "reader");
    const batch = d.db.batch.bind(d.db);
    let fail = true,
      before: unknown;
    d.db.batch = async (statements) => {
      const at = statements.findIndex((s) => s.sql === "DROP TABLE records");
      if (fail && at >= 0) {
        fail = false;
        before = await d.db.query(
          "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name",
        );
        return batch([
          ...statements.slice(0, at + 1),
          { sql: "SELECT impossible_column FROM missing_bootstrap_fault" },
          ...statements.slice(at + 1),
        ]);
      }
      return batch(statements);
    };
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow(
      /missing_bootstrap_fault/,
    );
    expect(
      await d.db.query(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name",
      ),
    ).toEqual(before);
    expect(await d.position()).toBe(0);
    expect(
      await d.db.query("SELECT count(*) n FROM bootstrap_segments"),
    ).toEqual([{ n: 5 }]);
    expect(await d.db.query("SELECT failed FROM stream_partial")).toEqual([
      { failed: 1 },
    ]);
    await applyConnection(d.deps, CONNECTION_ID);
    expect(await d.rows()).toEqual(await p.rows());
    expect(await d.position()).toBe(5);
  });

  it("rolls back every swap statement before the outer failure marker, then resumes", async () => {
    const w = await world({ streams: 1 }),
      p = await history(w),
      d = await connect(w, "each-fault");
    const schema = await bootstrapSchema(d.db);
    const control = await connect(w, "trace"),
      controlBatch = control.db.batch.bind(control.db);
    let program: string[] = [];
    control.db.batch = (statements) => {
      if (statements.some((st) => st.sql === "DROP TABLE records"))
        program = statements.map((st) => st.sql);
      return controlBatch(statements);
    };
    await applyConnection(control.deps, CONNECTION_ID);
    expect(program.length).toBeGreaterThan(0);
    const batch = d.db.batch.bind(d.db);
    const snapshot = async () => {
      const master = await d.db.query<{ name: string }>(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
      );
      const tables = [];
      for (const { name } of master)
        tables.push([
          name,
          await d.db.query(`SELECT * FROM "${name.replaceAll('"', '""')}"`),
        ]);
      const tempTables = [];
      for (const { name } of await d.db.query<{ name: string }>(
        "SELECT name FROM sqlite_temp_master WHERE type='table' ORDER BY name",
      ))
        tempTables.push([
          name,
          await d.db.query(
            `SELECT * FROM temp."${name.replaceAll('"', '""')}"`,
          ),
        ]);
      return {
        tempMaster: await d.db.query(
          "SELECT type,name,tbl_name,sql FROM sqlite_temp_master ORDER BY type,name",
        ),
        tempTables,
        master: await d.db.query(
          "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name",
        ),
        tables,
      };
    };
    let checked = 0;
    for (let failAt = 0; failAt < program.length; failAt++) {
      let armed = true;
      d.db.batch = async (statements) => {
        const swap = statements.some((st) => st.sql === "DROP TABLE records");
        if (!swap || !armed) return batch(statements);
        expect(statements.map((st) => st.sql)).toEqual(program);
        armed = false;
        const before = await snapshot(),
          at = failAt;
        try {
          return await batch([
            ...statements.slice(0, at + 1),
            { sql: "SELECT invalid_column FROM swap_fault" },
            ...statements.slice(at + 1),
          ]);
        } catch (error) {
          expect(await snapshot()).toEqual(before);
          checked++;
          throw error;
        }
      };
      await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow(
        /swap_fault/,
      );
      expect(armed).toBe(false);
      expect(await d.position()).toBe(0);
    }
    expect(checked).toBe(program.length);
    d.db.batch = batch;
    await applyConnection(d.deps, CONNECTION_ID);
    expect(await d.rows()).toEqual(await p.rows());
    expect(
      await d.db.query(
        "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='records' ORDER BY name",
      ),
    ).toEqual([...schema.triggers].sort((a, b) => (a.name < b.name ? -1 : 1)));
    await p.run("after-swap", [{ stream: sName(0), id: "safe", v: 123 }], {
      full: false,
      observedAt: 100,
    });
    await p.cycle();
    await applyConnection(d.deps, CONNECTION_ID);
    expect(await d.rows()).toEqual(await p.rows());
  });

  it("discards a staged prefix when the head is rewritten and converges on retry", async () => {
    const w = await world({ streams: 1 });
    await history(w);
    const d = await connect(w, "rewritten");
    const batch = d.db.batch.bind(d.db);
    let fail = true;
    d.db.batch = async (statements) => {
      if (
        fail &&
        statements.some(
          (statement) =>
            statement.sql.includes("INSERT INTO bootstrap_segments") &&
            statement.params?.[0] === 2,
        )
      ) {
        fail = false;
        throw new Error("stop after prefix");
      }
      return batch(statements);
    };
    await expect(d.cycle()).rejects.toThrow("stop after prefix");
    expect(
      await d.db.query(
        "SELECT position FROM bootstrap_segments WHERE position=1",
      ),
    ).toEqual([{ position: 1 }]);
    expect(await d.position()).toBe(0);
    const segments = await w.segments();
    const first = segments.get(1)!;
    const replacement = {
      ...first,
      operations: first.operations.map((op) =>
        op.kind === "upsert"
          ? { ...op, value: { ...(op.value as object), revised: true } }
          : op,
      ),
    };
    const firstBytes = encodeSegment(replacement);
    const firstHash = await digestSegment(
      async (bytes) => keccak_256(bytes),
      firstBytes,
    );
    await w.innerBlobs.put(`${LOG}/${firstHash.blobName}`, firstBytes);
    const head = segments.get(5)!;
    const rewritten = {
      ...head,
      refs: head.refs.map((ref) =>
        ref.position === 1
          ? { ...ref, dataHash: firstHash.dataHash, bytes: firstBytes.length }
          : ref,
      ),
    };
    const headBytes = encodeSegment(rewritten);
    const headHash = await digestSegment(
      async (bytes) => keccak_256(bytes),
      headBytes,
    );
    await w.innerBlobs.put(`${LOG}/${headHash.blobName}`, headBytes);
    const metadataHash = w.gateway.versions.get(LOG)!.at(-1)!.metadataHash;
    w.gateway.replaceHead(LOG, { dataHash: headHash.dataHash, metadataHash });
    await d.cycle();
    const fresh = await connect(w, "fresh-rewritten");
    await fresh.cycle();
    expect(await d.rows()).toEqual(await fresh.rows());
    expect((await d.rows()).join(" ")).toContain("revised");
    expect(await d.position()).toBe(await fresh.position());
    expect(await d.position()).toBeGreaterThanOrEqual(5);
    expect(await d.db.query("SELECT * FROM bootstrap_load")).toEqual([]);
    await d.cycle();
    expect(await d.rows()).toEqual(await fresh.rows());
  });

  it("finishes a prefix-only stream after an advanced-head retry, with SQL-layer append rollback", async () => {
    const w = await world({ streams: 2 }),
      p = await w.device("publisher");
    const publish = async (run: string, s: number, id: string, full = true) => {
      await p.run(run, [{ stream: sName(s), id }], {
        selected: [sName(s)],
        covered: [sName(s)],
        full,
      });
      await p.cycle();
    };
    await publish("one", 0, "a");
    await publish("two", 1, "b");
    await publish("three", 1, "c", false);
    const d = await connect(w, "reader"),
      batch = d.db.batch.bind(d.db);
    let fail = true;
    d.db.batch = async (statements) => {
      if (
        fail &&
        statements.some(
          (s) =>
            s.sql.includes("INSERT INTO bootstrap_segments") &&
            s.params?.[0] === 2,
        )
      ) {
        fail = false;
        return batch([
          ...statements.slice(0, -1),
          { sql: "SELECT impossible_column FROM append_fault" },
          ...statements.slice(-1),
        ]);
      }
      return batch(statements);
    };
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow(
      /append_fault/,
    );
    expect(await d.db.query("SELECT position FROM bootstrap_segments")).toEqual(
      [{ position: 1 }],
    );
    expect(await d.position()).toBe(0);
    await publish("four", 1, "d", false);
    await applyConnection(d.deps, CONNECTION_ID);
    const fresh = await connect(w, "fresh");
    await applyConnection(fresh.deps, CONNECTION_ID);
    expect(await d.rows()).toEqual(await fresh.rows());
    expect(
      await d.db.query(
        "SELECT stream,complete FROM stream_state ORDER BY stream",
      ),
    ).toEqual([
      { stream: "s0", complete: 1 },
      { stream: "s1", complete: 1 },
    ]);
    expect(await d.db.query("SELECT * FROM stream_partial")).toEqual([]);
    expect(await d.db.query("SELECT * FROM partial_hidden")).toEqual([]);
    expect(await d.position()).toBe(4);
  });

  it.each([true, false])(
    "preserves other-connection evidence under the %s swap fact, including churn",
    async (swap) => {
      const w = await world({ streams: 1 }),
        p = await history(w);
      await p.run("change", [{ stream: sName(0), id: "safe", v: 2 }], {
        full: false,
        observedAt: 60,
      });
      await p.cycle();
      await p.run("delete-b", [{ stream: sName(0), id: "b", remove: true }], {
        full: false,
        observedAt: 70,
      });
      await p.cycle();
      await p.run(
        "resurrect",
        [
          { stream: sName(0), id: "victim", v: 99 },
          { stream: sName(0), id: "omitted" },
        ],
        { full: false, observedAt: 80 },
      );
      await p.cycle();
      await p.run(
        "full",
        [
          { stream: sName(0), id: "safe", v: 2 },
          { stream: sName(0), id: "c" },
          { stream: sName(0), id: "d" },
          { stream: sName(0), id: "victim", v: 99 },
        ],
        { full: true, observedAt: 90 },
      );
      await p.cycle();
      const d = await connect(w, "preserve"),
        other = "pdpp.fixture~1111111111111111",
        hash = await pkHash(async (bytes) => sha256(bytes), { id: "foreign" }, [
          "id",
        ]);
      await d.db.batch([
        {
          sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES(?,'fixture','1111111111111111',1,'active',1)",
          params: [other],
        },
        {
          sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,first_o) VALUES(?,'s0',?,'foreign',1,'other',?,'foreign-hash',1)",
          params: [other, hash, JSON.stringify({ id: "foreign" })],
        },
      ]);
      if (swap)
        await d.db.batch([
          { sql: "DELETE FROM records WHERE connection_id=?", params: [other] },
        ]);
      await d.db.batch([
        {
          sql: "INSERT INTO blob_refs(blob_id,connection_id,stream,pk_hash) VALUES('foreign-blob',?,'s0',?)",
          params: [other, hash],
        },
      ]);
      const snapshot = async () => ({
        rows: await d.db.query("SELECT * FROM records WHERE connection_id=?", [
          other,
        ]),
        changes: await d.db.query(
          "SELECT * FROM record_changes WHERE connection_id=? ORDER BY seq",
          [other],
        ),
        views: await d.db.query(
          "SELECT * FROM view_versions WHERE connection_id=?",
          [other],
        ),
        refs: await d.db.query(
          "SELECT * FROM blob_refs WHERE connection_id=?",
          [other],
        ),
      });
      const before = await snapshot(),
        root = await d.db.query(
          "SELECT rootpage FROM sqlite_master WHERE type='table' AND name='records'",
        );
      const triggers = await d.db.query(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('trigger','index') AND tbl_name='records' ORDER BY type,name",
      );
      expect(
        triggers.filter((row) => row.type === "index").map((row) => row.name),
      ).toEqual([
        "records_by_first",
        "records_by_key",
        "records_by_observation",
        "records_key",
        "records_size",
      ]);
      expect(
        triggers
          .filter(
            (row) =>
              row.type === "trigger" &&
              !String(row.name).startsWith("records_bootstrap_"),
          )
          .map((row) => row.name),
      ).toEqual([
        "records_ad",
        "records_ai",
        "records_au",
        "records_key_type_conflict",
        "view_records_ad",
        "view_records_ai",
        "view_records_au",
      ]);
      const realBatch = d.db.batch.bind(d.db);
      let stagingCommits = 0;
      d.db.batch = (statements) => {
        if (
          !swap &&
          statements.some((st) => st.sql === "DROP TABLE bootstrap_records")
        )
          expect(
            statements.filter((st) =>
              st.sql.startsWith("INSERT INTO records("),
            ),
          ).toHaveLength(1);
        if (
          statements.some((st) =>
            st.sql.includes("INSERT INTO bootstrap_segments"),
          )
        )
          stagingCommits++;
        return realBatch(statements);
      };
      await applyConnection(d.deps, CONNECTION_ID);
      expect(stagingCommits).toBeGreaterThan(0);
      const afterRoot = await d.db.query(
        "SELECT rootpage FROM sqlite_master WHERE type='table' AND name='records'",
      );
      if (swap) expect(afterRoot).not.toEqual(root);
      else expect(afterRoot).toEqual(root);
      expect(await snapshot()).toEqual(before);
      expect(
        await d.db.query(
          "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('trigger','index') AND tbl_name='records' ORDER BY type,name",
        ),
      ).toEqual(triggers);
      const ordinary = await w.device("ordinary", { keyedFirstLoad: false });
      await ordinary.db.batch([
        {
          sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES(?,?,'',1,'active',1)",
          params: [CONNECTION_ID, CONNECTOR],
        },
      ]);
      await applyConnection(ordinary.deps, CONNECTION_ID);
      const canonical = (reader: Device) =>
        reader.db.query(
          "SELECT connection_id,stream,pk_hash,record_key,body,body_sha256,stamp_o,stamp_r,stamp_n,first_o,seen_o,seen_r,body_bytes FROM records WHERE connection_id=? ORDER BY connection_id,stream,pk_hash",
          [CONNECTION_ID],
        );
      expect(await canonical(d)).toEqual(await canonical(ordinary));
      const target = (
        await d.db.query(
          "SELECT stream,record_key,body,stamp_o,stamp_r,stamp_n,first_o FROM records WHERE connection_id=? ORDER BY stream,record_key",
          [CONNECTION_ID],
        )
      ).map((row) => JSON.stringify(row));
      expect(target).toEqual(await p.rows());
      expect(
        (
          await d.db.query<{ body: string }>(
            "SELECT body FROM records WHERE connection_id=? ORDER BY record_key",
            [CONNECTION_ID],
          )
        )
          .map((r) => JSON.parse(r.body).id)
          .sort(),
      ).toEqual(["c", "d", "safe", "victim"]);
    },
  );

  it.each([
    { first: "delete", a: 10, second: "upsert", b: 5, live: false },
    {
      first: "delete",
      a: 10,
      second: "upsert",
      b: 5,
      live: false,
      unknown: true,
    },
    { first: "upsert", a: 10, second: "delete", b: 5, live: true },
    { first: "delete", a: 10, second: "upsert", b: 10, live: false },
    { first: "delete", a: 10, second: "upsert", b: 11, live: true },
  ])(
    "orders stamps rather than positions: $first $a, then $second $b",
    async (test) => {
      const w = await world({ streams: 1 }),
        d = await connect(w, "stamps");
      const hash = await pkHash(async (bytes) => sha256(bytes), { id: "k" }, [
        "id",
      ]);
      const op = (kind: string, o: number) =>
        kind === "upsert"
          ? {
              kind,
              stream: sName(0),
              pkHash: hash,
              stamp: { o, r: "same-writer" },
              value: { id: "k", v: o },
              firstSeen: o,
            }
          : {
              kind,
              stream: sName(0),
              pkHash: hash,
              stamp: { o, r: "same-writer" },
              key: ["k"],
            };
      const publisher = await w.device("stamp-publisher");
      await publisher.run("seed-control", [{ stream: sName(0), id: "seed" }]);
      await publisher.cycle();
      const template = (await w.segments()).get(1)!;
      const metadataHash = w.gateway.versions.get(LOG)!.at(-1)!.metadataHash;
      const refs: StreamSync.SegmentRef[] = [];
      for (const [i, operation] of [
        op(test.first, test.a),
        op(test.second, test.b),
      ].entries()) {
        const segment = {
          ...template,
          position: i + 1,
          operations: [operation],
          refs: [...refs],
        } as StreamSync.Segment;
        const bytes = encodeSegment(segment);
        const { dataHash, blobName } = await digestSegment(
          async (b) => keccak_256(b),
          bytes,
        );
        await w.innerBlobs.put(`${LOG}/${blobName}`, bytes);
        if (i === 0) w.gateway.replaceHead(LOG, { dataHash, metadataHash });
        else w.gateway.write(LOG, { dataHash, metadataHash });
        refs.push({
          position: i + 1,
          dataHash,
          bytes: bytes.length,
          ...(test.unknown && i === 0
            ? {}
            : { removes: operation.kind === "delete" }),
        });
      }
      await applyConnection(d.deps, CONNECTION_ID);
      const rows = await d.db.query<{ body: string; stamp_o: number }>(
        "SELECT body,stamp_o FROM records",
      );
      expect(rows.map((r) => JSON.parse(r.body))).toEqual(
        test.live ? [{ id: "k", v: Math.max(test.a, test.b) }] : [],
      );
      expect(await d.db.query("SELECT 1 FROM partial_hidden")).toEqual([]);
      expect(await d.position()).toBe(2);
    },
  );

  it("copies through sorted key pointers and rowid lookups without a body sorter", async () => {
    const w = await world({ streams: 1 });
    const d = await connect(w, "copy-plan");
    const schema = await bootstrapSchema(d.db);
    await d.db.batch([
      { sql: schema.table },
      ...["b", "a"].map((key) => ({
        sql: "INSERT INTO bootstrap_records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES(?,'s0',?,?,1,'writer',?,'hash')",
        params: [CONNECTION_ID, key, key, JSON.stringify({ id: key })],
      })),
    ]);
    const statements = await copyBootstrapRecords(d.db, schema, [
      {
        connectionId: CONNECTION_ID,
        stream: "s0",
        keys: [
          ["a", 2, 0],
          ["b", 1, 0],
        ],
      },
    ]);
    const at = statements.findIndex((st) =>
      st.sql.startsWith("INSERT INTO records("),
    );
    expect(at).toBeGreaterThan(0);
    await d.db.batch(statements.slice(0, at));
    const plan = await d.db.query<{ detail: string }>(
      "EXPLAIN QUERY PLAN " + statements[at]!.sql,
    );
    expect(plan.some((row) => row.detail.includes("USE TEMP B-TREE"))).toBe(
      false,
    );
    expect(
      plan.some((row) => /SEARCH b USING INTEGER PRIMARY KEY/.test(row.detail)),
    ).toBe(true);
    await d.db.batch(statements.slice(at));
    expect(
      await d.db.query("SELECT pk_hash FROM records ORDER BY rowid"),
    ).toEqual([{ pk_hash: "a" }, { pk_hash: "b" }]);
  });

  it.each(["view", "trigger", "foreign key"])(
    "refuses a swap with an external %s reference",
    async (kind) => {
      const w = await world({ streams: 1 });
      const d = await connect(w, "reader");
      const sql =
        kind === "view"
          ? "CREATE VIEW records_consumer AS SELECT * FROM records"
          : kind === "trigger"
            ? "CREATE TRIGGER external_consumer AFTER INSERT ON connections BEGIN SELECT count(*) FROM records; END"
            : "CREATE TABLE records_consumer(key TEXT REFERENCES records(pk_hash))";
      await d.db.batch([{ sql }]);
      await expect(bootstrapSchema(d.db)).rejects.toThrow(/external records/);
    },
  );
});
