import { describe, it, expect } from "vitest";
import { createStreamDeclarationRegistry } from "./stream-declaration.js";

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
