import { afterEach, expect, it } from "vitest";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import {
  CONNECTION_ID,
  CONTROL,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

for (const listed of [false, true]) {
  it(`fetches the newest segment while control is held (${listed ? "cycle listing" : "standalone"})`, async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("first", [{ stream: sName(0), id: "x" }]);
    await a.cycle();
    const b = await w.device("b");
    await b.cycle();
    await a.run("second", [{ stream: sName(0), id: "y" }], { full: false });
    await a.cycle();
    const rows = listed ? await b.deps.registry.listOwnerRows() : undefined;
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let fetched = false;
    let reads = 0;
    let gets = 0;
    const applying = applyConnection(
      {
        ...b.deps,
        registry: {
          ...b.deps.registry,
          async read(scope) {
            reads++;
            if (scope === CONTROL) await held;
            return b.deps.registry.read(scope);
          },
        },
        blobs: {
          ...b.deps.blobs,
          async get(key) {
            fetched = true;
            gets++;
            return b.deps.blobs.get(key);
          },
        },
      },
      CONNECTION_ID,
      rows,
    );
    try {
      await expect.poll(() => fetched, { timeout: 1000 }).toBe(true);
      // Prefetch must never apply rows before control admits the lifetime.
      expect(await b.rows()).not.toEqual(await a.rows());
    } finally {
      release();
      await applying;
    }
    expect(await b.rows()).toEqual(await a.rows());
    expect(reads).toBe(listed ? 1 : 2);
    expect(gets).toBe(1);
  });
}

it("an absent control discards a failed speculative fetch without applying it", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  await a.run("first", [{ stream: sName(0), id: "x" }]);
  await a.cycle();
  const b = await w.device("b");
  await b.cycle();
  await a.run("second", [{ stream: sName(0), id: "y" }], { full: false });
  await a.cycle();
  const before = await b.rows();
  let gets = 0;
  await applyConnection(
    {
      ...b.deps,
      registry: {
        ...b.deps.registry,
        read: (scope) =>
          scope === CONTROL
            ? Promise.resolve({ found: false as const })
            : b.deps.registry.read(scope),
      },
      blobs: {
        ...b.deps.blobs,
        async get() {
          gets++;
          throw new Error("storage unavailable");
        },
      },
    },
    CONNECTION_ID,
  );
  expect(gets).toBe(1);
  expect(await b.rows()).toEqual(before);
});
