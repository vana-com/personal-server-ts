import { expect, it, vi } from "vitest";
import { streamReadScope } from "../stream-sync-read/routing.js";
import {
  isMemoryScope,
  isReservedSystemConnector,
  isReservedSystemScope,
  isSystemScope,
} from "./reserved-scopes.js";

vi.mock("../replication/namespace.js", () => ({
  isReplicaScope: () => false,
}));

it("#574 keeps physical scopes private and normalizes read aliases before policy", () => {
  const logical = "pdpp.connector.records";
  const identityless = "pdpp.connector~.records";
  const physical = [
    "pdpp.connector~namespace.records",
    "pdpp.connector~namespace",
    "pdpp.connector~",
    identityless,
    "invalid~scope",
  ];

  for (const scope of physical) {
    expect(isSystemScope(scope), scope).toBe(true);
  }

  // The read route must normalize the identity-less alias before policy:
  // its raw physical spelling is private, but its logical name is not.
  const normalized = streamReadScope(identityless);
  expect(normalized).toBe(logical);
  expect(isSystemScope(normalized!)).toBe(false);
  expect(isSystemScope(logical)).toBe(false);
});

it("recognizes a private memory snapshot only when its stream name is present", () => {
  expect(isMemoryScope("memory")).toBe(false);
  expect(isMemoryScope("memory.synthetic")).toBe(true);
  expect(isMemoryScope("memory.")).toBe(false);
  expect(isMemoryScope("synthetic.memory")).toBe(false);
});

it("recognizes platform-owned scopes in both namespace spellings", () => {
  expect(isReservedSystemScope("vana.system.synthetic")).toBe(true);
  expect(isReservedSystemScope("pdpp.vana-system-synthetic.records")).toBe(
    true,
  );
});

it("distinguishes ordinary catalog labels from the platform namespace", () => {
  expect(isReservedSystemConnector("vana-system-catalog")).toBe(true);
  expect(isReservedSystemConnector("catalog")).toBe(false);
  expect(isReservedSystemScope("pdpp.catalog.records")).toBe(false);
});

it("recognizes connector-level platform scope names before a stream is named", () => {
  expect(isReservedSystemScope("pdpp.vana-system-synthetic")).toBe(true);
  expect(isReservedSystemScope("pdpp.vana-system-example")).toBe(true);
});

it("recognizes nested names in the ordinary memory catalog", () => {
  expect(isMemoryScope("memory.project.notes")).toBe(true);
  expect(isMemoryScope("memory.project.decisions")).toBe(true);
});
