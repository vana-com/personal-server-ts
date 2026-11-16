import { runInNewContext } from "node:vm";
import { setFlagsFromString } from "node:v8";
import { expect, it } from "vitest";
import type { HeadPart } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  createStorageAccess,
  DEFAULT_STORAGE_ACCESS_POLICY,
} from "../stream-sync/storage-retry.js";
import { readPartsAhead } from "./part-readahead.js";

const part = (bytes: number, count: number): HeadPart => ({
  prefix: "",
  hash: `h${Math.random()}`,
  bytes,
  count,
});
const governorOf = (maxBytesInFlight: number) =>
  createStorageAccess({ ...DEFAULT_STORAGE_ACCESS_POLICY, maxBytesInFlight });
const within = <T>(work: Promise<T>, ms = 5000) =>
  Promise.race([
    work,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("deadline")), ms),
    ),
  ]);
/** The apply's use of a reader: read each unit's parts, commit it, repeat. */
async function drain(
  reader: ReturnType<typeof readPartsAhead>,
  parts: HeadPart[],
) {
  for (let i = 0; i < parts.length; i++) {
    await reader.load(parts[i]!, i);
    if (parts[i + 1] === undefined || parts[i + 1]!.count !== 0)
      reader.committed(i);
  }
  reader.close();
}
const bytesOf = (part: HeadPart) => new Uint8Array(part.bytes);

it("admits a record that spans more parts than the budget holds, alone", async () => {
  // A budget of three parts and a record of 30: a reservation per part would
  // hold three and wait for the fourth, which only a commit can free.
  const governor = governorOf(2 * 3 * 100);
  const parts = [
    part(100, 1),
    ...Array.from({ length: 29 }, () => part(100, 0)),
  ];
  const reader = readPartsAhead({ governor }, parts, async (p) => bytesOf(p));
  await within(drain(reader, parts));
  const whole = await within(governor.reserve(2 * 3 * 100));
  whole();
});

it("settles two readers that share one budget, each with a record larger than it", async () => {
  const governor = governorOf(2 * 3 * 100);
  const run = () => {
    const parts = [
      part(100, 1),
      ...Array.from({ length: 19 }, () => part(100, 0)),
      part(100, 1),
      part(100, 1),
    ];
    return drain(
      readPartsAhead({ governor }, parts, async (p) => {
        await new Promise((r) => setImmediate(r));
        return bytesOf(p);
      }),
      parts,
    );
  };
  await within(Promise.all([run(), run(), run()]));
  const whole = await within(governor.reserve(2 * 3 * 100));
  whole();
});

it("gives every reservation back when a part of a record fails to fetch", async () => {
  const governor = governorOf(2 * 3 * 100);
  const parts = [part(100, 1), part(100, 0), part(100, 0), part(100, 1)];
  const reader = readPartsAhead({ governor }, parts, async (p) => {
    if (p === parts[2]) throw new Error("part blob transfer failed");
    return bytesOf(p);
  });
  await expect(within(drain(reader, parts))).rejects.toThrow(
    "part blob transfer failed",
  );
  reader.close();
  const whole = await within(governor.reserve(2 * 3 * 100));
  whole();
});

it("does not keep the bytes of a part the apply has read", async () => {
  setFlagsFromString("--expose-gc");
  const gc = runInNewContext("gc") as () => void;
  // Forty parts through a budget of four.
  const governor = governorOf(2 * 4 * 1000);
  const parts = Array.from({ length: 40 }, () => part(1000, 1));
  const seen: WeakRef<Uint8Array>[] = [];
  const reader = readPartsAhead({ governor }, parts, async (p) => {
    const bytes = bytesOf(p);
    seen.push(new WeakRef(bytes));
    return bytes;
  });
  for (let i = 0; i < parts.length; i++) {
    await reader.load(parts[i]!, i);
    reader.committed(i);
    await new Promise((r) => setImmediate(r));
  }
  gc();
  await new Promise((r) => setImmediate(r));
  gc();
  const alive = seen.filter((ref) => ref.deref() !== undefined).length;
  reader.close();
  // What the reader may still hold is a budget's worth, not the head.
  expect(seen).toHaveLength(40);
  expect(alive).toBeLessThanOrEqual(4);
});

it("raises a read of a part twice", async () => {
  const governor = governorOf(2 * 3 * 100);
  const parts = [part(100, 1)];
  const reader = readPartsAhead({ governor }, parts, async (p) => bytesOf(p));
  await reader.load(parts[0]!, 0);
  await expect(reader.load(parts[0]!, 0)).rejects.toThrow("read twice");
  reader.close();
});
