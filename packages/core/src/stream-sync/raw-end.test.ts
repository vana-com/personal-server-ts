import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { validateRawEnd } from "./raw-end.js";

const vectors = JSON.parse(
  readFileSync(
    new URL("../../contracts/raw-end.json", import.meta.url),
    "utf8",
  ),
);
describe("raw end wire vectors", () => {
  for (const vector of vectors.validation)
    it(vector.name, () => {
      if (vector.valid) expect(validateRawEnd(vector.raw)).toEqual(vector.raw);
      else expect(() => validateRawEnd(vector.raw)).toThrow();
    });
});
