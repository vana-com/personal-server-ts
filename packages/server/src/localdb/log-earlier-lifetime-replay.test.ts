// A log of an earlier lifetime holds none of this one (core localdb/log-apply.ts).
// Seeing it at the position this device already holds must not rewrite the
// device's lineage: the device applied nothing from it, so its cursor,
// reference set and snapshot stay as they were. Real publisher, real gateway
// adapter, real SQLite (log-world.test-utils.ts).
import { afterEach, expect, it } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  controlHashes,
  deriveKeyCheck,
  logScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { applyLog } from "../../../core/src/localdb/index.js";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

it("an earlier-lifetime log seen at the current position leaves the cursor, references and snapshot unchanged", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  await a.run("r1", [{ stream: sName(0), id: "x" }]);
  await a.cycle();
  const b = await w.device("b");
  await b.cycle();
  expect(await b.position()).toBe(1);
  // The reader's last applied ref names another hash at the position the log
  // is at, so the duplicate return does not apply.
  const [state] = await b.db.query<{ refs: string }>(
    "SELECT refs FROM log_state WHERE connection_id = ?",
    [CONNECTION_ID],
  );
  const refs = JSON.parse(state!.refs) as { dataHash: string }[];
  refs[refs.length - 1]!.dataHash = `0x${"ab".repeat(32)}`;
  await b.db.batch([
    {
      sql: "UPDATE log_state SET refs = ? WHERE connection_id = ?",
      params: [JSON.stringify(refs), CONNECTION_ID],
    },
  ]);
  const before = await b.db.query("SELECT * FROM log_state");
  const rowsBefore = await b.rows();

  // The connection is at generation 2; the log's newest segment is of 1.
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (x) => keccak_256(x), keyCheck);
  const read = await b.deps.registry.read(logScope("fixture", ""));
  if (!read.found) throw new Error("the log has no registry row");
  const result = await applyLog(b.deps, CONNECTION_ID, {
    connector: "fixture",
    ns: "",
    generation: 2,
    keyCheck,
    hashes,
    read,
  });

  expect(result.applied).toBe(0);
  expect(await b.db.query("SELECT * FROM log_state")).toEqual(before);
  expect(await b.rows()).toEqual(rowsBefore);
});
