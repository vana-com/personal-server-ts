// The Keccak-256 of a log's segments, heads and control rows comes from the
// host's `streamCrypto` port (`keccakOf`), so the Node host's native one reaches
// every caller. A module of `localdb/` that imports noble's keccak itself would
// hash on the main thread at a thirtieth of that speed and give no sign: this
// holds the import out.
import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const here = new URL(".", import.meta.url);

describe("the Keccak-256 of a log", () => {
  it("is not imported from noble by any module of localdb", () => {
    const offenders = readdirSync(here)
      .filter((name) => name.endsWith(".ts") && !name.endsWith(".test.ts"))
      .filter((name) =>
        /@noble\/hashes\/sha3/.test(readFileSync(new URL(name, here), "utf8")),
      );
    expect(offenders).toEqual([]);
  });
});
