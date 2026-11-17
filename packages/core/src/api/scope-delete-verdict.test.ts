import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  decideScopeDeletion,
  type ScopeDeletionVerdict,
} from "./scope-delete-verdict.js";

// The file Rust and Dart hosts run. This test is the TypeScript side of it.
const file = JSON.parse(
  readFileSync(
    new URL("../../contracts/scope-delete-receipt.json", import.meta.url),
    "utf8",
  ),
) as {
  cases: {
    id: string;
    scope: string;
    status: number;
    receipt: unknown;
    verdict: ScopeDeletionVerdict;
  }[];
};

describe("decideScopeDeletion", () => {
  it("has a case for every refusal the rule names", () => {
    const ids = file.cases.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(
      expect.arrayContaining([
        "happy-path",
        "gateway-not-registered",
        "storage-failed-requeued",
        "not-durable",
        "pending-blob-deletion",
        "blobs-pending-3",
        "non-ok-http-with-receipt",
        "receipt-for-another-scope",
      ]),
    );
    for (const kind of [
      "durably-deleted",
      "deleted-cleanup-pending",
      "incomplete",
      "unconfirmed",
    ]) {
      expect(
        file.cases.some((c) => c.verdict.kind === kind),
        kind,
      ).toBe(true);
    }
  });

  it.each(file.cases)("$id", ({ scope, status, receipt, verdict }) => {
    expect(decideScopeDeletion({ status, receipt, scope })).toEqual(verdict);
  });
});
