import { describe, expect, it } from "vitest";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import { retainedConnectorKey } from "./retained-connector.js";

const snapshot = (source_id: string) =>
  ({ source_id }) as unknown as DeclarationSnapshot;

describe("retainedConnectorKey", () => {
  it("names the one configured method of a source", () => {
    const key = retainedConnectorKey({
      configuredMethods: [{ sourceId: "github", methodId: "github-browser" }],
      connectionMethods: new Map(),
    });
    expect(key(snapshot("github"))).toBe("github-browser");
  });

  it("uses a connection method the same way", () => {
    const key = retainedConnectorKey({
      configuredMethods: [],
      connectionMethods: new Map([["oura", ["oura-browser"]]]),
    });
    expect(key(snapshot("oura"))).toBe("oura-browser");
  });

  it("falls back to the source id when no method names the source", () => {
    expect(retainedConnectorKey(undefined)(snapshot("github"))).toBe("github");
  });

  it("leaves a source with two different methods unresolvable", () => {
    const key = retainedConnectorKey({
      configuredMethods: [
        { sourceId: "github", methodId: "github-browser" },
        { sourceId: "github", methodId: "github-api" },
      ],
      connectionMethods: new Map(),
    });
    expect(key(snapshot("github"))).toBeNull();
  });

  it("counts a method named twice once", () => {
    const key = retainedConnectorKey({
      configuredMethods: [{ sourceId: "github", methodId: "github-browser" }],
      connectionMethods: new Map([["github", ["github-browser"]]]),
    });
    expect(key(snapshot("github"))).toBe("github-browser");
  });
});
