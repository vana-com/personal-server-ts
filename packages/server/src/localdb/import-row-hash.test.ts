import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { canonicalImportRow } from "../../../core/src/localdb/import-snapshot.js";

it("hashes canonical UTF-8 across scratch boundaries without splitting a scalar", async () => {
  const prefix = JSON.stringify({ id: "fixture", text: "" }).length;
  const record = {
    id: "fixture",
    text: "x".repeat(65536 - prefix + 1) + "😀é",
  };
  const row = await canonicalImportRow(record, ["id"]);
  expect(row.body_sha256).toBe(
    createHash("sha256").update(row.body).digest("hex"),
  );
  const other = await canonicalImportRow({ id: "other", text: "new body" }, [
    "id",
  ]);
  expect(other.body_sha256).toBe(
    createHash("sha256").update(other.body).digest("hex"),
  );
});
