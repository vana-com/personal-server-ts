import { describe, expect, it } from "vitest";
import { assertSandboxEnv } from "./runtime.js";

describe("sandbox environment", () => {
  it("accepts the storage API URL", () => {
    expect(() =>
      assertSandboxEnv({
        GATEWAY_URL: "https://gateway.example",
        STORAGE_API_URL: "https://storage-dev.vana.org",
      }),
    ).not.toThrow();
  });

  it("rejects an unknown key", () => {
    expect(() => assertSandboxEnv({ DATABASE_URL: "secret" })).toThrow(
      "Unknown sandbox environment key: DATABASE_URL",
    );
  });
});
