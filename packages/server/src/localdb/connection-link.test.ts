import { afterEach, describe, expect, it } from "vitest";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  createLinkedRecordQuery,
  openLocalDb,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const opened: SqlDriver[] = [];
const run = (db: SqlDriver, sql: string, params: (string | number)[] = []) =>
  db.batch([{ sql, params }]);
afterEach(async () => {
  for (const db of opened.splice(0)) await db.close();
});
async function fixture() {
  const db = openBetterSqlite3(":memory:");
  opened.push(db);
  await openLocalDb(db, {
    owner: "0xabc",
    network: "moksha",
    deviceId: "test",
  });
  const id = controlScope("fixture", "");
  await run(
    db,
    "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?, 'fixture', '', 1, 'active', 1)",
    [id],
  );
  for (const [stream, key] of [
    ["selected", "allowed"],
    ["private", "secret"],
  ]) {
    await run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,?,?,?,1,'run','{}','hash')",
      [id, stream!, key!, key!],
    );
  }
  const deleted = new Set<string>();
  const query = createLinkedRecordQuery(db, (instance, stream) =>
    !deleted.has(instance) &&
    ["handle-a", "handle-b"].includes(instance) &&
    stream === "selected"
      ? { connector: "fixture", namespace: "" }
      : null,
  );
  return { db, id, deleted, query };
}
describe("host-authorized connection links", () => {
  it("two handles of one source read the same selected stream", async () => {
    const { query } = await fixture();
    const a = await query.listRecords({
      connectionId: "handle-a",
      stream: "selected",
    });
    expect(a.records.map((r) => r.recordKey)).toEqual(["allowed"]);
    expect(
      await query.listRecords({ connectionId: "handle-b", stream: "selected" }),
    ).toEqual(a);
  });
  it("does not read outside the link's stream selection", async () => {
    const { query } = await fixture();
    expect(
      (await query.listRecords({ connectionId: "handle-a", stream: "private" }))
        .records,
    ).toEqual([]);
    expect(
      await query.getRecord({
        connectionId: "handle-a",
        stream: "private",
        recordKey: "secret",
      }),
    ).toBeNull();
  });
  it("deleted binding stays unreadable even after sync reconnect", async () => {
    const { query, deleted, db, id } = await fixture();
    deleted.add("handle-a");
    await run(db, "UPDATE connections SET generation=3 WHERE connection_id=?", [
      id,
    ]);
    expect(
      (
        await query.listRecords({
          connectionId: "handle-a",
          stream: "selected",
        })
      ).records,
    ).toEqual([]);
    expect(
      (
        await query.listRecords({
          connectionId: "handle-b",
          stream: "selected",
        })
      ).records,
    ).toHaveLength(1);
  });
  it("unresolvable namespaces read nothing", async () => {
    const { query } = await fixture();
    expect(
      (
        await query.listRecords({
          connectionId: "unresolved",
          stream: "selected",
        })
      ).records,
    ).toEqual([]);
    expect(
      await query.changesSince({
        connectionId: "unresolved",
        stream: "selected",
        cursor: 0,
      }),
    ).toBe("gone");
  });
  it("a deleted sync connection reads nothing", async () => {
    const { db, id, query } = await fixture();
    await run(
      db,
      "UPDATE connections SET control_state='deleted' WHERE connection_id=?",
      [id],
    );
    expect(
      (
        await query.listRecords({
          connectionId: "handle-a",
          stream: "selected",
        })
      ).records,
    ).toEqual([]);
  });
});
