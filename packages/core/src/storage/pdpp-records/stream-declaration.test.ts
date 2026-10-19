import { describe, it, expect } from "vitest";
import {
  createStreamDeclarationRegistry,
  withRequiredFields,
} from "./stream-declaration.js";

describe("createStreamDeclarationRegistry", () => {
  it("looks up a declared stream by name", () => {
    const registry = createStreamDeclarationRegistry([
      {
        name: "messages",
        semantics: "append_only",
        primaryKey: ["id"],
        cursorField: "source_created_at",
        requiredFields: ["id"],
      },
    ]);
    expect(registry.get("messages")?.semantics).toBe("append_only");
    expect(registry.get("unknown")).toBeUndefined();
  });
});

describe("withRequiredFields", () => {
  it("returns undefined (no restriction) when no fields were requested", () => {
    expect(withRequiredFields(undefined, ["id"])).toBeUndefined();
  });

  it("merges required fields into a requested projection", () => {
    expect(withRequiredFields(["name"], ["id"])).toEqual(["name", "id"]);
  });

  it("does not duplicate a required field already requested", () => {
    expect(withRequiredFields(["id", "name"], ["id"])).toEqual(["id", "name"]);
  });
});
