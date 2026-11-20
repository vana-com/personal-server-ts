import { describe, expect, it } from "vitest";
import { scopeToPathSegments } from "@opendatalabs/vana-sdk/browser";
import { parseDataScopeContract } from "../contracts/data.js";
import {
  buildDataFilePath,
  buildScopeDir,
} from "../storage/hierarchy/paths.js";
import { PhysicalScopeError, isPhysicalScope } from "./scope-routing.js";

// Ruling Q7: physical stream-sync names never reach the vana-sdk ScopeSchema
// or scopeToPathSegments.
const PHYSICAL = [
  "pdpp.chatgpt~0123456789abcdef.conversations",
  "pdpp.chatgpt~0123456789abcdef",
  "pdpp.chatgpt~.conversations",
  "pdpp.chatgpt~",
];

describe("stream-sync scope routing (ruling Q7)", () => {
  it("recognises every physical name and no SDK scope", () => {
    for (const name of PHYSICAL) expect(isPhysicalScope(name)).toBe(true);
    for (const name of [
      "chatgpt.conversations",
      "pdpp.chatgpt.conversations",
    ]) {
      expect(isPhysicalScope(name)).toBe(false);
    }
  });

  it("the SDK helper itself throws on a physical name", () => {
    // Why the routing exists: without it this throw reaches callers.
    expect(() => scopeToPathSegments(PHYSICAL[0]!)).toThrow();
  });

  it.each(PHYSICAL)(
    "parseDataScopeContract answers 400 for %s without throwing",
    (name) => {
      expect(parseDataScopeContract(name)).toMatchObject({
        ok: false,
        status: 400,
        body: { error: "INVALID_SCOPE" },
      });
    },
  );

  it.each(PHYSICAL)(
    "path builders refuse %s with PhysicalScopeError before the SDK",
    (name) => {
      expect(() =>
        buildDataFilePath("/data", name, "2026-01-01T00:00:00Z"),
      ).toThrow(PhysicalScopeError);
      expect(() => buildScopeDir("/data", name)).toThrow(PhysicalScopeError);
    },
  );
});
