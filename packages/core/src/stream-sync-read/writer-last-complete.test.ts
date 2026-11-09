/**
 * The real writer, publishing a complete head and then an incomplete one,
 * names the complete head it replaced, so a device that never imported it
 * still reads it.
 */

import { describe, expect, it } from "vitest";
import { ask, body } from "./service-fixture.js";
import { Rig } from "./writer-rig.js";

describe("writer-emitted lastComplete", () => {
  it("lets a fresh store read the complete head behind an incomplete publication", async () => {
    const rig = new Rig();
    await rig.open();
    await rig.collect({
      runId: "base",
      key: "id",
      version: "1.0.0",
      rows: [{ id: "a", v: 1 }],
      full: true,
    });
    await rig.publish();
    const complete = await rig.registeredHead();
    // A checkpointed run whose connector changed the key: published incomplete.
    await rig.collect({
      runId: "r2",
      key: "uid",
      version: "2.0.0",
      rows: [{ uid: "z", v: 1 }],
      full: false,
    });
    await rig.publish();
    const incomplete = await rig.registeredHead();
    expect(incomplete?.complete).toBe(false);
    expect(incomplete?.lastComplete?.version).toBe(1);
    expect(complete?.complete).toBe(true);

    await rig.open(true);
    await rig.sync();
    const decision = await rig.service.resolve(
      ask("pdpp.acme.items", { streamOnly: true, isOwnerView: false }),
    );
    expect(decision.kind).toBe("view");
    const records = (await body(decision)).data.records;
    expect(records.map((r: any) => r.id)).toEqual(["a"]);
  });
});
