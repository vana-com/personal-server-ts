import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  PS_GRANTEE_REF_HEADER,
  PS_LITE_RELAY_READ_HEADER,
  type PersonalServerDataApiDeps,
  type PersonalServerReadAuthResult,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

const BUILDER = "0x000000000000000000000000000000000000bEEF";

async function fixture(readResult: PersonalServerReadAuthResult | void) {
  const storage = createMemoryDataStorage();
  const deps: PersonalServerDataApiDeps = {
    storage,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () => readResult),
    },
    accessLogWriter: { write: vi.fn(async () => undefined) },
  };
  const write = await handlePersonalServerDataRequest(
    new Request("https://ps.example/example.items", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ items: [1] }),
    }),
    deps,
  );
  expect(write.status).toBe(201);
  return deps;
}

function read(headers: Record<string, string> = {}) {
  return new Request("https://ps.example/example.items?grantId=grant-1", {
    headers,
  });
}

describe("relay grantee ref header", () => {
  it("labels a relay-forwarded builder read with a truncated sha256 of the lowercased builder", async () => {
    const deps = await fixture({ builder: BUILDER, grantId: "grant-1" });
    const response = await handlePersonalServerDataRequest(
      read({ [PS_LITE_RELAY_READ_HEADER]: "1" }),
      deps,
    );
    expect(response.status).toBe(200);
    const expected = createHash("sha256")
      .update(BUILDER.toLowerCase())
      .digest("hex")
      .slice(0, 12);
    expect(response.headers.get(PS_GRANTEE_REF_HEADER)).toBe(expected);
  });

  it("does not add the header when the request is not relay-forwarded", async () => {
    const deps = await fixture({ builder: BUILDER, grantId: "grant-1" });
    const response = await handlePersonalServerDataRequest(read(), deps);
    expect(response.status).toBe(200);
    expect(response.headers.get(PS_GRANTEE_REF_HEADER)).toBeNull();
  });

  it("labels owner reads as owner, never hashing an address", async () => {
    const deps = await fixture({ builder: BUILDER, grantId: "owner" });
    const response = await handlePersonalServerDataRequest(
      read({ [PS_LITE_RELAY_READ_HEADER]: "1" }),
      deps,
    );
    expect(response.headers.get(PS_GRANTEE_REF_HEADER)).toBe("owner");
  });

  it("omits the header when auth resolves no builder address", async () => {
    const deps = await fixture({ grantId: "grant-1" });
    const response = await handlePersonalServerDataRequest(
      read({ [PS_LITE_RELAY_READ_HEADER]: "1" }),
      deps,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get(PS_GRANTEE_REF_HEADER)).toBeNull();
  });
});
