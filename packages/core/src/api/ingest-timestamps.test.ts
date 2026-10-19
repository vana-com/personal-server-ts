import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

const WALL = "2026-10-18T00:00:00.123Z";

function fixture() {
  const storage = createMemoryDataStorage();
  const deps: PersonalServerDataApiDeps = {
    storage,
    now: () => new Date(WALL),
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () => undefined),
    },
    accessLogWriter: { write: vi.fn(async () => undefined) },
  };
  const post = (scope = "example.items", body = "{}") =>
    new Request("https://ps.example/" + scope, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
  return { storage, deps, post };
}

describe("bounded per-scope ingest timestamps", () => {
  it("malformed-write flood cannot advance this or another scope", async () => {
    const { storage, deps, post } = fixture();
    for (let i = 0; i < 60001; i += 1) {
      const response = await handlePersonalServerDataRequest(
        post("bad.items", "{"),
        deps,
      );
      expect(response.status).toBe(400);
    }
    expect(storage.entries).toHaveLength(0);
    expect(
      (await handlePersonalServerDataRequest(post("other.items"), deps)).status,
    ).toBe(201);
    expect(
      (await handlePersonalServerDataRequest(post("bad.items"), deps)).status,
    ).toBe(201);
    expect(storage.entries.map((entry) => entry.collectedAt)).toEqual([
      WALL,
      WALL,
    ]);
  }, 60000);

  it("rejects the 61st pending reservation and reuses a failed slot", async () => {
    const { storage, deps, post } = fixture();
    const release: Array<() => void> = [];
    let allStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      allStarted = resolve;
    });
    const pending = Array.from({ length: 60 }, () => {
      const request = post();
      vi.spyOn(request, "json").mockImplementation(
        () =>
          new Promise((_, reject) => {
            release.push(() => reject(new SyntaxError("bad JSON")));
            if (release.length === 60) allStarted();
          }),
      );
      return handlePersonalServerDataRequest(request, deps);
    });
    await started;
    const full = await handlePersonalServerDataRequest(post(), deps);
    expect(full.status).toBe(429);
    expect(await full.json()).toMatchObject({
      error: { errorCode: "INGEST_CAPACITY" },
    });
    // A full scope never consumes another scope's window.
    expect(
      (await handlePersonalServerDataRequest(post("other.items"), deps)).status,
    ).toBe(201);
    release[0]!();
    expect((await pending[0]!).status).toBe(400);
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      201,
    );
    expect(storage.findEntry({ scope: "example.items" })?.collectedAt).toBe(
      WALL,
    );
    release.slice(1).forEach((resolve) => resolve());
    expect(
      (await Promise.all(pending)).every((response) => response.status === 400),
    ).toBe(true);
  });

  it("preserves actual milliseconds, same-ms uniqueness, and durable monotonicity", async () => {
    const { storage, deps, post } = fixture();
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      201,
    );
    // A new storage-port identity simulates loss of all process-local reservations.
    deps.storage = { ...storage };
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      201,
    );
    expect(storage.entries.map((entry) => entry.collectedAt)).toEqual([
      WALL,
      "2026-10-18T00:00:00.124Z",
    ]);
    deps.now = () => new Date("2026-10-17T23:59:59Z");
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      429,
    );
    expect(storage.entries).toHaveLength(2);
    deps.now = () => new Date("2026-10-18T00:00:00.125Z");
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      201,
    );
    expect(storage.entries[2]?.collectedAt).toBe("2026-10-18T00:00:00.125Z");
  });

  it("returns capacity after 60 committed slots and recovers as wall time advances", async () => {
    const { storage, deps, post } = fixture();
    for (let i = 0; i < 60; i += 1) {
      expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
        201,
      );
    }
    expect(
      new Set(storage.entries.map((entry) => entry.collectedAt)).size,
    ).toBe(60);
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      429,
    );
    deps.now = () => new Date("2026-10-18T00:00:00.124Z");
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      201,
    );
    expect(storage.entries[60]?.collectedAt).toBe("2026-10-18T00:00:00.183Z");
  });

  it("releases on body validation, storage exceptions, and binary-body exceptions", async () => {
    const { storage, deps, post } = fixture();
    expect(
      (
        await handlePersonalServerDataRequest(
          post("example.items", '{"$writtenBy":{}}'),
          deps,
        )
      ).status,
    ).toBe(400);
    const write = vi
      .spyOn(storage, "writeEnvelope")
      .mockRejectedValueOnce(new Error("storage unavailable"));
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      500,
    );
    write.mockRestore();
    const binary = new Request("https://ps.example/example.items", {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: "data",
    });
    vi.spyOn(binary, "arrayBuffer").mockRejectedValue(
      new Error("body unavailable"),
    );
    expect((await handlePersonalServerDataRequest(binary, deps)).status).toBe(
      500,
    );
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      201,
    );
    expect(storage.entries[0]?.collectedAt).toBe(WALL);
  });

  it("auth failures do not reserve a stamp", async () => {
    const { storage, deps, post } = fixture();
    vi.mocked(deps.auth.authorizeOwner).mockRejectedValueOnce(
      new Error("unauthorized"),
    );
    expect(
      (await handlePersonalServerDataRequest(post(), deps)).status,
    ).not.toBe(201);
    expect((await handlePersonalServerDataRequest(post(), deps)).status).toBe(
      201,
    );
    expect(storage.entries[0]?.collectedAt).toBe(WALL);
  });
});
