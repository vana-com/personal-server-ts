import { expect, it } from "vitest";
import { gatewayBatchRefusal } from "../../../core/src/localdb/batch-contract.js";
import type { SignedRegistryBatch } from "../../../core/src/stream-sync/ports.js";

const row = (scope: string) => ({
  scope,
  dataHash: "0x01",
  metadataHash: "0x02",
  expectedVersion: "2",
  signature: "0x00",
});
const need = (scope: string) => ({
  scope,
  expectedVersion: "1",
  notDeleted: true,
});
const request = (
  rows: string[],
  requires: string[] = [],
): SignedRegistryBatch => ({
  ownerAddress: "0x" + "11".repeat(20),
  rows: rows.map(row),
  requires: requires.map(need),
});

it("accepts a condition on a row the request does not write", () => {
  expect(gatewayBatchRefusal(request(["a", "b"], ["control"]))).toBeNull();
});

it("refuses a condition on a row the same request writes", () => {
  expect(gatewayBatchRefusal(request(["control", "a"], ["control"]))).toBe(
    "requires[0].scope: must be a different data point than the one written",
  );
});

it("refuses a repeated condition scope and an oversize request", () => {
  expect(gatewayBatchRefusal(request(["a"], ["c", "c"]))).toBe(
    "requires[1].scope: repeated",
  );
  expect(
    gatewayBatchRefusal(request(Array.from({ length: 17 }, (_, i) => `r${i}`))),
  ).toBe("rows: at most 16 rows (got 17)");
});
