import { expect, it, vi } from "vitest";
import { streamReadScope } from "../stream-sync-read/routing.js";
import { isSystemScope } from "./reserved-scopes.js";

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
