import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

const OWNER = "0x000000000000000000000000000000000000dEaD" as const;
const BUILDER = "0x000000000000000000000000000000000000bEEF" as const;
const SCOPE = "oura.daily_summary";
const COLLECTED_AT = "2026-06-06T00:00:00.000Z";

async function fixture() {
  const storage = createMemoryDataStorage();
  const envelope = {
    version: "1.0",
    scope: SCOPE,
    collectedAt: COLLECTED_AT,
    data: { restingHeartRate: 52 },
  };
  const written = await storage.writeEnvelope(envelope);
  const entry = storage.insertEntry({
    scope: SCOPE,
    fileId: "file-1",
    collectedAt: COLLECTED_AT,
    path: written.path,
    relativePath: written.relativePath,
    sizeBytes: written.sizeBytes,
    version: 1,
    dataPointId: null,
  });
  let owner = false;
  const readLatest = vi.fn(async () => ({
    kind: "canonical" as const,
    envelope: {
      ...envelope,
      data: { restingHeartRate: 49 },
    },
    revision: "canonical-revision",
  }));
  const deps: PersonalServerDataApiDeps = {
    storage,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () =>
        owner ? undefined : { builder: BUILDER, grantId: "chain-grant" },
      ),
    },
    accessLogWriter: { write: vi.fn(async () => undefined) },
    serverOwner: OWNER,
    legacyScopeView: {
      readLatest,
      ownsScope: vi.fn(() => true),
    } as never,
  };
  const get = (suffix = "") =>
    handlePersonalServerDataRequest(
      new Request(`https://ps.example/v1/data/${SCOPE}${suffix}`),
      deps,
      { basePath: "/v1/data" },
    );
  return {
    deps,
    entry,
    get,
    readLatest,
    setOwner: (value: boolean) => (owner = value),
  };
}

describe("canonical data reads under a chain grant", () => {
  it("serves a builder the legacy-format canonical view of a scope its grant covers", async () => {
    const { deps, get, readLatest } = await fixture();
    const response = await get();

    expect(response.status).toBe(200);
    expect(response.headers.get("X-Vana-Data-Source")).toBe("canonical");
    expect(await response.json()).toMatchObject({
      data: { restingHeartRate: 49 },
    });
    expect(readLatest).toHaveBeenCalledWith(SCOPE);
    expect(deps.accessLogWriter.write).toHaveBeenCalledOnce();
  });

  it("serves the canonical view that becomes selectable while authorization is awaiting settlement, as a canonical read", async () => {
    const { deps, get, readLatest } = await fixture();
    let settle!: () => void;
    let started!: () => void;
    const authorizing = new Promise<void>((resolve) => {
      started = resolve;
    });
    const settlement = new Promise<void>((resolve) => {
      settle = resolve;
    });
    readLatest.mockResolvedValue({ kind: "file" } as never);
    deps.auth.authorizeBuilderRead = async () => {
      started();
      await settlement;
      return { builder: BUILDER, grantId: "chain-grant" };
    };
    const pending = get();
    await authorizing;
    readLatest.mockResolvedValue({
      kind: "canonical",
      envelope: {
        version: "1.0",
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        data: { secret: "late-canonical" },
      },
      revision: "after-settlement",
    } as never);
    settle();
    const response = await pending;
    expect(response.status).toBe(200);
    expect(response.headers.get("X-Vana-Data-Source")).toBe("canonical");
    expect(await response.text()).toContain("late-canonical");
  });

  it("serves the selected canonical body to the owner", async () => {
    const { get, setOwner } = await fixture();
    setOwner(true);
    const response = await get();

    expect(response.status).toBe(200);
    expect(response.headers.get("X-Vana-Data-Source")).toBe("canonical");
    expect(await response.json()).toMatchObject({
      data: { restingHeartRate: 49 },
    });
  });

  it("keeps an explicit historical file read available to a builder", async () => {
    const { deps, entry, get } = await fixture();
    const response = await get(`?at=${encodeURIComponent(entry.collectedAt)}`);

    expect(response.status).toBe(200);
    expect(response.headers.get("X-Vana-Data-Source")).toBe("legacy");
    expect(await response.json()).toMatchObject({
      data: { restingHeartRate: 52 },
    });
    expect(deps.accessLogWriter.write).toHaveBeenCalledOnce();
  });
});
