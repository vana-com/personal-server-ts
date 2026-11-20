import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  attachPersonalServerReadGranteeObserver,
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
  type PersonalServerReadAuthResult,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { fixedOwnedAccountStorageMode } from "../test-utils/account-mode.js";

const BUILDER = "0x000000000000000000000000000000000000bEEF";

async function fixture(readResult: PersonalServerReadAuthResult | void) {
  const storage = createMemoryDataStorage();
  const deps: PersonalServerDataApiDeps = {
    storage,
    accountStorageMode: fixedOwnedAccountStorageMode("unswitched"),
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

async function observedRead(
  readResult: PersonalServerReadAuthResult | void,
  observer?: (ref: Promise<string | undefined>) => void,
) {
  const deps = await fixture(readResult);
  const request = read();
  const refs: Array<Promise<string | undefined>> = [];
  attachPersonalServerReadGranteeObserver(
    request,
    observer ?? ((ref) => refs.push(ref)),
  );
  const response = await handlePersonalServerDataRequest(request, deps);
  return { response, refs };
}

describe("read grantee observer", () => {
  it("reports a truncated sha256 of the lowercased builder for an attached observer", async () => {
    const { response, refs } = await observedRead({
      builder: BUILDER,
      grantId: "grant-1",
    });
    expect(response.status).toBe(200);
    const expected = createHash("sha256")
      .update(BUILDER.toLowerCase())
      .digest("hex")
      .slice(0, 12);
    expect(refs).toHaveLength(1);
    await expect(refs[0]).resolves.toBe(expected);
  });

  it("never exposes the label as a response header, even when a requester asks via the old wire header", async () => {
    const deps = await fixture({ builder: BUILDER, grantId: "grant-1" });
    const response = await handlePersonalServerDataRequest(
      read({ "x-ps-lite-relay-read": "1" }),
      deps,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("x-ps-grantee-ref")).toBeNull();
    expect([...response.headers.keys()].join(",")).not.toContain("grantee");
  });

  it("labels owner reads as owner", async () => {
    const { refs } = await observedRead({ builder: BUILDER, grantId: "owner" });
    await expect(refs[0]).resolves.toBe("owner");
  });

  it("reports undefined when auth resolves no builder address", async () => {
    const { response, refs } = await observedRead({ grantId: "grant-1" });
    expect(response.status).toBe(200);
    await expect(refs[0]).resolves.toBeUndefined();
  });

  it("never fails the read when the observer throws or hashing fails", async () => {
    const { response } = await observedRead(
      { builder: BUILDER, grantId: "grant-1" },
      () => {
        throw new Error("observer fault");
      },
    );
    expect(response.status).toBe(200);

    const digest = vi
      .spyOn(crypto.subtle, "digest")
      .mockRejectedValue(new Error("no subtle"));
    try {
      const { response: hashed, refs } = await observedRead({
        builder: BUILDER,
        grantId: "grant-1",
      });
      expect(hashed.status).toBe(200);
      await expect(refs[0]).resolves.toBeUndefined();
    } finally {
      digest.mockRestore();
    }
  });
  it("labels a switched-account read once, although the read authorizes twice (check, then settle)", async () => {
    const authorizeBuilderRead = vi.fn(async () => ({
      builder: BUILDER,
      grantId: "grant-1",
    }));
    const deps: PersonalServerDataApiDeps = {
      storage: createMemoryDataStorage(),
      accountStorageMode: fixedOwnedAccountStorageMode("switched"),
      streamSyncRead: {
        resolve: vi.fn(async () => ({
          kind: "view" as const,
          connector: "fixture",
          ns: "",
          cursor: "head",
          served: { scope: "example.items", version: 1 },
          body: new Response(JSON.stringify({ data: { records: [] } })).body!,
        })),
      },
      auth: {
        authorizeOwner: vi.fn(async () => undefined),
        authorizeBuilderList: vi.fn(async () => undefined),
        authorizeBuilderRead,
      },
      accessLogWriter: { write: vi.fn(async () => undefined) },
    } as never;
    const request = read();
    const refs: Array<Promise<string | undefined>> = [];
    attachPersonalServerReadGranteeObserver(request, (ref) => refs.push(ref));
    const response = await handlePersonalServerDataRequest(request, deps);
    await response.text();
    expect(response.status).toBe(200);
    expect(authorizeBuilderRead).toHaveBeenCalledTimes(2);
    const expected = createHash("sha256")
      .update(BUILDER.toLowerCase())
      .digest("hex")
      .slice(0, 12);
    expect(refs).toHaveLength(1);
    await expect(refs[0]).resolves.toBe(expected);
  });
});
