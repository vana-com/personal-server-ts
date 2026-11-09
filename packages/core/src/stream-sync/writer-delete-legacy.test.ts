/**
 * A connection delete also erases this device's legacy scope files of the
 * connector (the writer's `eraseLegacy` port). The port runs last in the purge:
 * after the stream tombstones landed, and also when the registry lists nothing
 * of the connector. A failure leaves the delete open for the next publish pass.
 */
import { expect, it } from "vitest";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  CONNECTOR,
  Rig,
  type RunSpec,
} from "../stream-sync-read/writer-rig.js";

const spec = (runId: string): RunSpec => ({
  runId,
  key: "id",
  version: "1.0.0",
  rows: [{ id: runId }],
  full: true,
});
/** The control row's version: a delete's tombstone is the version after the pin. */
const controlVersion = async (r: Rig) =>
  (await r.gateway.read(controlScope(CONNECTOR, ""))).version;

it("the connection delete erases the legacy files after its tombstones landed ", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  const seen: unknown[] = [];
  r.eraseLegacyHook = async (connector) => {
    expect(connector).toBe(CONNECTOR);
    seen.push(await controlVersion(r));
  };
  await r.writer.deleteConnection(CONNECTOR);
  expect(seen).toEqual([2]);
});

it("a legacy erase that throws leaves the delete open; the next publish pass runs it again", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  let calls = 0;
  r.eraseLegacyHook = async () => {
    calls += 1;
    if (calls === 1) throw new Error("legacy file busy");
  };
  await expect(r.writer.deleteConnection(CONNECTOR)).rejects.toThrow(
    "legacy file busy",
  );
  await r.publish();
  expect(calls).toBe(2);
  expect(await controlVersion(r)).toBe(2);
});

it("a delete of a connector the registry lists nothing of still erases its legacy files", async () => {
  const r = new Rig(undefined, CONNECTOR, []);
  await r.open();
  const erased: string[] = [];
  r.eraseLegacyHook = async (connector) => {
    erased.push(connector);
  };
  await r.writer.deleteConnection(CONNECTOR);
  expect(erased).toEqual([CONNECTOR]);
});
