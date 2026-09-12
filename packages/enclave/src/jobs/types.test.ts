import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BLOCK_START = "// JOB_EXECUTE_WIRE_START";
const BLOCK_END = "// JOB_EXECUTE_WIRE_END";
const CURRENT_DIR = dirname(fileURLToPath(import.meta.url));
const ENCLAVE_TYPES = resolve(CURRENT_DIR, "types.ts");
const SERVER_TYPES = resolve(CURRENT_DIR, "../../../server/src/jobs/types.ts");

function wireBlock(source: string): string {
  const start = source.indexOf(BLOCK_START);
  const end = source.indexOf(BLOCK_END);
  if (start < 0 || end <= start) {
    throw new Error("Job execute wire block markers are missing");
  }

  return source.slice(start, end + BLOCK_END.length);
}

describe("sandbox job wire types", () => {
  it("stay byte-identical to the server route wire types", async () => {
    const [enclave, server] = await Promise.all([
      readFile(ENCLAVE_TYPES, "utf8"),
      readFile(SERVER_TYPES, "utf8"),
    ]);

    expect(wireBlock(enclave)).toBe(wireBlock(server));
  });
});
