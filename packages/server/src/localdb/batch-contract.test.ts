import { expect, it } from "vitest";
import { gatewayBatchRefusal } from "../../../core/src/localdb/batch-contract.js";
import type {
  RegistryBatchPolicy,
  SignedRegistryBatch,
} from "../../../core/src/stream-sync/ports.js";

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

const POLICY: RegistryBatchPolicy = {
  rows: 16,
  requires: 16,
  bytes: 65_536,
};

it("accepts a condition on a row the request does not write", () => {
  expect(
    gatewayBatchRefusal(request(["a", "b"], ["control"]), POLICY),
  ).toBeNull();
});

// Conditions are judged on the state the request commits, so a condition may
// name a row the same request writes (a first save: control v1 and the log
// row that needs it).
it("accepts a condition on a row the same request writes", () => {
  expect(
    gatewayBatchRefusal(request(["control", "a"], ["control"]), POLICY),
  ).toBeNull();
});

it("refuses a repeated condition scope and an oversize request", () => {
  expect(gatewayBatchRefusal(request(["a"], ["c", "c"]), POLICY)).toBe(
    "requires[1].scope: repeated",
  );
  expect(
    gatewayBatchRefusal(request(Array.from({ length: 5 }, (_, i) => `r${i}`)), {
      ...POLICY,
      rows: 4,
    }),
  ).toBe("rows: at most 4 rows (got 5)");
});
