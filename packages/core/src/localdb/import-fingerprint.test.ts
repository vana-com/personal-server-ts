import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { importFingerprint } from "./import-fingerprint.js";

const a = { pk_hash: "1".repeat(64), body_sha256: "a".repeat(64) };
const b = { pk_hash: "2".repeat(64), body_sha256: "b".repeat(64) };
async function* rows(values: (typeof a)[]) {
  yield* values;
}
it("hashes empty input with the SHA-256 empty vector", async () => {
  expect(await importFingerprint(rows([]))).toEqual({
    rows: 0,
    fingerprint:
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  });
});
it("hashes big-endian length-prefixed hexadecimal ASCII", async () => {
  const expected = createHash("sha256");
  for (const text of [a.pk_hash, a.body_sha256, b.pk_hash, b.body_sha256]) {
    expected.update(Buffer.from([0, 0, 0, 64])).update(text, "ascii");
  }
  const result = await importFingerprint(rows([a, b]));
  expect(result).toEqual({ rows: 2, fingerprint: expected.digest("hex") });
  expect(
    await importFingerprint(rows([a, { ...b, body_sha256: a.body_sha256 }])),
  ).not.toEqual(result);
});
it("refuses unsorted, duplicate and malformed digest rows", async () => {
  for (const invalid of [[b, a], [a, a], [{ ...a, pk_hash: "A".repeat(64) }]]) {
    await expect(importFingerprint(rows(invalid))).rejects.toThrow(
      "invalid_import_fingerprint_rows",
    );
  }
});
