// The join gate: a device that never collected an existing connection is
// asked once (`join_required`) before its first run. Nothing is written for
// the run until the host sends `join: true` after the user accepted.
import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { MIGRATIONS } from "../../../core/src/localdb/schema.js";
import { RegistryUnavailableError } from "../../../core/src/stream-sync/ports.js";
import {
  CONNECTOR,
  OWNER,
  closeWorldDrivers,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const request = (extra: Record<string, unknown> = {}) => ({
  connector: CONNECTOR,
  artifactDigest: CONNECTOR,
  owner: { address: OWNER, leaseId: null },
  observedAt: 1000,
  ...extra,
});

/** A world where device `d1` created the connection and published it. */
async function existing() {
  const w = await world({ streams: 1 });
  const d1 = await w.device("d1");
  await d1.run("r1", [{ stream: "s0", id: "a" }]);
  await d1.cycle();
  return { w, d1 };
}

const count = async (
  d: { db: { query: (sql: string) => Promise<unknown[]> } },
  table: string,
) => (await d.db.query(`SELECT 1 FROM ${table}`)).length;

describe("begin join gate", () => {
  it("asks a second device to join, and writes nothing for the run", async () => {
    const { w, d1 } = await existing();
    const d2 = await w.device("d2");
    await expect(d2.sync.intake.begin("r2", request())).rejects.toMatchObject({
      code: "join_required",
      status: 409,
    });
    expect(await count(d2, "runs")).toBe(0);
    expect(await count(d2, "run_streams")).toBe(0);
    expect(await count(d2, "connection_participation")).toBe(0);
    expect(await count(d1, "connection_participation")).toBe(1);
  });

  it("accepts the same begin with join: true and records the join", async () => {
    const { w } = await existing();
    const d2 = await w.device("d2");
    const begun = await d2.sync.intake.begin("r2", request({ join: true }));
    expect(begun.status).toBe("collecting");
    expect(await count(d2, "runs")).toBe(1);
    expect(
      await d2.db.query("SELECT connection_id FROM connection_participation"),
    ).toHaveLength(1);
    // Joined once, so the next foreground run needs no answer.
    await d2.sync.intake.abort("r2", "cancelled");
    await expect(d2.sync.intake.begin("r3", request())).resolves.toMatchObject({
      status: "collecting",
    });
  });

  it("does not ask the creator", async () => {
    const w = await world({ streams: 1 });
    const d1 = await w.device("d1");
    await expect(d1.sync.intake.begin("r1", request())).resolves.toMatchObject({
      status: "collecting",
    });
    expect(await count(d1, "connection_participation")).toBe(1);
  });

  it("accepts join: true from the creator and from a joined device", async () => {
    const w = await world({ streams: 1 });
    const d1 = await w.device("d1");
    await d1.sync.intake.begin("r1", request({ join: true }));
    await d1.sync.intake.abort("r1", "cancelled");
    await d1.sync.intake.begin("r2", request({ join: true }));
    expect(await count(d1, "connection_participation")).toBe(1);
  });

  it("does not ask a device that collected the connection before the gate existed", async () => {
    const { w } = await existing();
    const d2 = await w.device("d2");
    await d2.run("r2", [{ stream: "s0", id: "b" }]); // joined by the helper
    // A database from before the gate: the run and checkpoint are there, the
    // participation table is not.
    await d2.db.batch([{ sql: "DELETE FROM connection_participation" }]);
    expect(await d2.db.query("SELECT 1 FROM runs")).not.toEqual([]);
    const old = new Database(":memory:");
    const gate = MIGRATIONS.findIndex((m) =>
      m.some((sql) => sql.includes("connection_participation")),
    );
    expect(gate).toBeGreaterThanOrEqual(0);
    for (const sql of MIGRATIONS.slice(0, gate).flat()) old.exec(sql);
    old.exec(
      "INSERT INTO connections(connection_id,connector,ns,checkpoint) VALUES ('pdpp.a~','a','','{}'),('pdpp.b~','b','',NULL),('pdpp.c~','c','',NULL),('pdpp.d~','d','',NULL)",
    );
    old.exec(
      "INSERT INTO runs(run_id,connection_id,o,artifact_version,collection_mode,state) VALUES ('x','pdpp.b~',1,'1','full_refresh','ended')",
    );
    for (const sql of MIGRATIONS[gate]!) old.exec(sql);
    expect(
      old
        .prepare(
          "SELECT connection_id FROM connection_participation ORDER BY 1",
        )
        .all(),
    ).toEqual([{ connection_id: "pdpp.a~" }, { connection_id: "pdpp.b~" }]);
    old.close();
  });

  it("refuses with control_basis_unavailable when the registry is down and the device never joined", async () => {
    const { w } = await existing();
    const d2 = await w.device("d2");
    vi.spyOn(d2.deps.registry, "read").mockRejectedValue(
      new RegistryUnavailableError("offline fixture"),
    );
    await expect(d2.sync.intake.begin("r2", request())).rejects.toMatchObject({
      code: "control_basis_unavailable",
      status: 503,
    });
    expect(await count(d2, "runs")).toBe(0);
  });

  it("still collects offline on a device that joined", async () => {
    const { d1 } = await existing();
    vi.spyOn(d1.deps.registry, "read").mockRejectedValue(
      new RegistryUnavailableError("offline fixture"),
    );
    await expect(d1.sync.intake.begin("r2", request())).resolves.toMatchObject({
      status: "collecting",
    });
  });

  it("asks a device that never collected even when connect: true and its cache says absent", async () => {
    const { w } = await existing();
    const d2 = await w.device("d2");
    await expect(
      d2.sync.intake.begin("r2", request({ connect: true })),
    ).rejects.toMatchObject({ code: "join_required" });
    expect(await count(d2, "runs")).toBe(0);
  });

  it("joins the device that deletes a connection and explicitly connects it again", async () => {
    const { d1 } = await existing();
    await d1.sync.deleter.requestConnectionDelete(CONNECTOR);
    await d1.sync.deleter.resumeDeletes();
    expect(await count(d1, "connection_participation")).toBe(0);
    await expect(
      d1.sync.intake.begin("r2", request({ connect: true })),
    ).resolves.toMatchObject({ status: "collecting" });
    expect(await count(d1, "connection_participation")).toBe(1);
  });

  it("asks a device that saw the connection deleted and recreated elsewhere", async () => {
    const { w, d1 } = await existing();
    const d2 = await w.device("d2");
    await d2.run("r2", [{ stream: "s0", id: "b" }]);
    await d2.cycle();
    await d1.cycle();
    await d1.sync.deleter.requestConnectionDelete(CONNECTOR);
    await d1.sync.deleter.resumeDeletes();
    await d1.run("r3", [{ stream: "s0", id: "c" }], { connect: true });
    await d1.cycle();
    await d2.cycle(); // sees the deletion and the new lifetime
    expect(await count(d2, "connection_participation")).toBe(0);
    await expect(d2.sync.intake.begin("r4", request())).rejects.toMatchObject({
      code: "join_required",
    });
  });

  it("asks a device that joined but stopped before its first batch and never saw the deletion", async () => {
    // d1 created the connection but published no data yet.
    const w = await world({ streams: 1 });
    const d1 = await w.device("d1");
    await d1.begin("r1");
    await d1.cycle();
    const d2 = await w.device("d2");
    await d2.begin("r2", { join: true });
    expect(await count(d2, "connection_participation")).toBe(1);
    await d1.sync.deleter.requestConnectionDelete(CONNECTOR);
    await d1.sync.deleter.resumeDeletes();
    await d1.run("r3", [{ stream: "s0", id: "c" }], { connect: true });
    await d1.cycle();
    await d2.cycle(); // sees only the new lifetime
    expect(await count(d2, "connection_participation")).toBe(0);
    await expect(d2.sync.intake.begin("r4", request())).rejects.toMatchObject({
      code: "join_required",
    });
  });

  it("asks a device that joined but stopped before its first batch when the connection was deleted and recreated elsewhere", async () => {
    // d1 created the connection but published no data yet.
    const w = await world({ streams: 1 });
    const d1 = await w.device("d1");
    await d1.begin("r1");
    await d1.cycle();
    const d2 = await w.device("d2");
    // Join, then stop: a participation row, but no records, run rows, blob
    // refs or checkpoint for the purge to find.
    await d2.begin("r2", { join: true });
    for (const table of ["records", "run_rows", "blob_refs"])
      expect(await count(d2, table)).toBe(0);
    expect(await count(d2, "connection_participation")).toBe(1);
    await d1.sync.deleter.requestConnectionDelete(CONNECTOR);
    await d1.sync.deleter.resumeDeletes();
    await d2.cycle(); // sees the deletion
    expect(await count(d2, "connection_participation")).toBe(0);
    await d1.run("r3", [{ stream: "s0", id: "c" }], { connect: true });
    await d1.cycle();
    await d2.cycle(); // sees the new lifetime
    await expect(d2.sync.intake.begin("r4", request())).rejects.toMatchObject({
      code: "join_required",
    });
  });
});
