import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { run } from "../../../core/src/test-support/memory-oracle.js";

it("releases consumed source pages before yielding the host to fetch another", async () => {
  const measured = await run<boolean>({
    module: fileURLToPath(
      new URL("./canonical-import-source.memory.workload.ts", import.meta.url),
    ),
    exportName: "releasedSourcePage",
  });
  expect(measured.result).toBe(true);
}, 60_000);
