import { expect, it } from "vitest";
import { importFingerprint } from "../../../core/src/localdb/import-fingerprint.js";

it("lets pending host work run while fingerprinting a synchronous row stream", async () => {
  let consumed = 0;
  let observed: number | undefined;
  const timer = setTimeout(() => {
    observed = consumed;
  }, 0);
  try {
    const result = await importFingerprint(
      (async function* () {
        for (let i = 0; i < 384; i++) {
          consumed++;
          yield {
            pk_hash: i.toString(16).padStart(64, "0"),
            body_sha256: "a".repeat(64),
          };
        }
      })(),
    );
    expect(result.rows).toBe(384);
    expect(observed).toBeGreaterThan(0);
    expect(observed).toBeLessThan(result.rows);
  } finally {
    clearTimeout(timer);
  }
});
