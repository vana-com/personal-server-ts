import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { LEGACY_SCOPE_BINDINGS } from "../../../core/src/legacy-projection/index.js";
import { legacyConnectorKey } from "../../../core/src/storage/canonical-legacy-projection.js";

it("localdb fixtures contain no connector or legacy data-set names", () => {
  const forbidden = new Set(
    [...LEGACY_SCOPE_BINDINGS].flatMap(([scope, binding]) => [
      scope,
      legacyConnectorKey(binding.pdppSource),
    ]),
  );
  for (const name of [
    "legacy-access.test.ts",
    "import-readback.test.ts",
    "import-upload.test.ts",
  ]) {
    const text = readFileSync(new URL(name, import.meta.url), "utf8");
    const found = [...forbidden].filter((value) =>
      new RegExp(
        `\\b${value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`,
        "i",
      ).test(text),
    );
    expect(found, name).toEqual([]);
  }
});
