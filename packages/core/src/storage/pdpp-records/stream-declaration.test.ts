import { describe, it, expect } from "vitest";
import {
  createSourceStreamDeclarationRegistry,
  createStreamDeclarationRegistry,
  type StreamDeclaration,
} from "./stream-declaration.js";

const messages: StreamDeclaration = {
  name: "messages",
  semantics: "append_only",
  primaryKey: ["id"],
  cursorField: "source_created_at",
  requiredFields: ["id"],
};

describe("a name or instance no declaration covers", () => {
  // The stored legacy read looks up every bound stream's schema; a binding
  // name with no declaration must come back empty, never throw, or one such
  // scope would fail a whole listing.
  it("resolves to undefined in the single-source registry", () => {
    const registry = createStreamDeclarationRegistry([messages]);
    expect(registry.get("profile")).toBeUndefined();
    expect(
      registry.get("profile", "https://registry.pdpp.dev/sources/x"),
    ).toBeUndefined();
    expect(registry.forInstance("any", "profile")).toBeUndefined();
    expect(registry.declares("profile")).toBe(false);
  });

  it("resolves to undefined in the source-aware registry", () => {
    const registry = createSourceStreamDeclarationRegistry([
      {
        sourceId: "https://registry.pdpp.dev/sources/x",
        instance: "x",
        streams: [messages],
      },
    ]);
    expect(registry.get("profile")).toBeUndefined();
    expect(
      registry.get("profile", "https://registry.pdpp.dev/sources/x"),
    ).toBeUndefined();
    expect(
      registry.get("messages", "https://registry.pdpp.dev/sources/other"),
    ).toBeUndefined();
    expect(registry.forInstance("x", "profile")).toBeUndefined();
    expect(
      registry.forInstance("unknown-instance", "messages"),
    ).toBeUndefined();
    expect(registry.declares("profile")).toBe(false);
  });
});

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
