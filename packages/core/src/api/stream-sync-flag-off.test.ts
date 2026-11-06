import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { createMemoryStreamSyncReadFiles } from "../stream-sync-read/memory-files.js";
import { createStreamSyncReadKeys } from "../stream-sync-read/keys.js";
import { StreamSyncReadService } from "../stream-sync-read/service.js";

/**
 * With `streamSync.read` off, every read answers exactly as before stream
 * sync. The snapshot was recorded on the commit before the read side existed
 * (the same test, run there) and must not change.
 */

const PARITY = join(
  dirname(fileURLToPath(import.meta.url)),
  "../legacy-projection/__fixtures__/parity",
);
const COLLECTED_AT = "2026-10-01T00:00:00.000Z";
const BUILDER = "0x000000000000000000000000000000000000bEEF";

/** Parity fixtures that carry a legacy body; the first file per scope. */
function parityBodies(): { scope: string; data: unknown }[] {
  const byScope = new Map<string, unknown>();
  for (const name of readdirSync(PARITY).sort()) {
    if (!name.endsWith(".json")) continue;
    const fixture = JSON.parse(readFileSync(join(PARITY, name), "utf8"));
    if (fixture.legacyBody === undefined || byScope.has(fixture.scope))
      continue;
    byScope.set(fixture.scope, fixture.legacyBody);
  }
  return [...byScope].map(([scope, data]) => ({ scope, data }));
}

async function seededDeps(): Promise<PersonalServerDataApiDeps> {
  const storage = createMemoryDataStorage();
  const envelopes = parityBodies();
  envelopes.push({
    scope: "pdpp.acme.items",
    data: {
      records: [
        { id: "a", n: 1 },
        { id: "b", n: 2 },
      ],
    },
  });
  for (const { scope, data } of envelopes) {
    const envelope = {
      version: "1.0" as const,
      scope,
      collectedAt: COLLECTED_AT,
      data,
    };
    const written = await storage.writeEnvelope(envelope);
    storage.insertEntry({
      fileId: null,
      path: written.relativePath,
      scope,
      collectedAt: COLLECTED_AT,
      sizeBytes: written.sizeBytes,
    } as never);
  }
  return {
    storage,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async ({ request }: { request: Request }) =>
        request.headers.get("x-test-builder")
          ? { builder: BUILDER, grantId: "grant-1" }
          : { builder: BUILDER, grantId: "owner" },
      ),
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
  };
}

const REQUESTS: { name: string; path: string; builder?: boolean }[] = [];
for (const { scope } of parityBodies()) {
  REQUESTS.push({ name: `owner ${scope}`, path: `/${scope}` });
  REQUESTS.push({ name: `builder ${scope}`, path: `/${scope}`, builder: true });
}
REQUESTS.push(
  { name: "raw pdpp stream", path: "/pdpp.acme.items" },
  {
    name: "connection and cursor ignored",
    path: "/pdpp.acme.items?connection=0123456789abcdef&cursor=abc",
  },
  {
    name: "bad connection ignored",
    path: "/chatgpt.conversations?connection=zz",
  },
  { name: "stored view", path: "/pdpp.acme.items?view=stored" },
  { name: "unknown scope", path: "/acme.nothing" },
  { name: "physical stream name", path: "/pdpp.acme~0123456789abcdef.items" },
  { name: "physical control name", path: "/pdpp.acme~0123456789abcdef" },
  { name: "identity-less physical name", path: "/pdpp.acme~.items" },
);

async function observe(
  deps: PersonalServerDataApiDeps,
  requests: typeof REQUESTS,
): Promise<Record<string, unknown>> {
  const observed: Record<string, unknown> = {};
  for (const request of requests) {
    const response = await handlePersonalServerDataRequest(
      new Request(`https://ps.example.com${request.path}`, {
        headers: request.builder ? { "x-test-builder": "1" } : {},
      }),
      deps,
    );
    const body = await response.text();
    observed[request.name] = {
      status: response.status,
      contentType: response.headers.get("content-type"),
      source: response.headers.get("x-vana-data-source"),
      bytes: body.length,
      sha256: createHash("sha256").update(body).digest("hex"),
    };
  }
  return observed;
}

describe("data reads with streamSync.read off", () => {
  it("answer every fixture read as before", async () => {
    const observed = await observe(await seededDeps(), REQUESTS);
    await expect(JSON.stringify(observed, null, 2) + "\n").toMatchFileSnapshot(
      "./__snapshots__/stream-sync-flag-off.json",
    );
  });

  it("answer the same with the flag on and nothing published", async () => {
    // `connection` and `cursor` mean something once the flag is on.
    const plain = REQUESTS.filter(
      (r) => !/[?&](connection|cursor)=/.test(r.path),
    );
    const off = await observe(await seededDeps(), plain);
    const service = await StreamSyncReadService.open({
      files: createMemoryStreamSyncReadFiles(),
      blobs: { get: async () => null },
      keys: await createStreamSyncReadKeys(new Uint8Array(65).fill(7)),
      logger: { info() {}, warn() {}, error() {} },
    });
    const on = await observe(
      { ...(await seededDeps()), streamSyncRead: service },
      plain,
    );
    expect(Object.keys(on)).toHaveLength(plain.length);
    expect(on).toEqual(off);
  });
});
