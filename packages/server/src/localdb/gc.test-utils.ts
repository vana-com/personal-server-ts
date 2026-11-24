// Forced collections for tests that ask what memory still holds.
import vm from "node:vm";
import v8 from "node:v8";

v8.setFlagsFromString("--expose-gc");
const collect = vm.runInNewContext("gc") as () => void;

/** True once every object behind `refs` is collected: a macrotask, then a collection, until it is or 10 rounds pass. */
export async function collected(
  refs: readonly WeakRef<object>[],
): Promise<boolean> {
  for (let round = 0; round < 10; round++) {
    // A WeakRef target stays alive to the end of the job that made it.
    await new Promise((resolve) => setTimeout(resolve, 0));
    collect();
    if (refs.every((ref) => ref.deref() === undefined)) return true;
  }
  return false;
}

/** The bytes this process holds now, in its heap and in array buffers, after a collection. */
export function liveBytes(): number {
  collect();
  const { heapUsed, arrayBuffers } = process.memoryUsage();
  return heapUsed + arrayBuffers;
}
