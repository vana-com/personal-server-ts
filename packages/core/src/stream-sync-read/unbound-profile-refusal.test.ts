import { afterEach, describe, expect, it, vi } from "vitest";
import { LEGACY_SCOPE_BINDINGS } from "../legacy-projection/index.js";
import { ask, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";
import { planProjection } from "./projection.js";

// Derive a windowed binding from the registry; no connector-specific fixture.
const selected = [...LEGACY_SCOPE_BINDINGS].find(
  ([, binding]) => binding.window,
);
if (!selected)
  throw new Error("The regression needs one registered windowed binding");
const [scope, binding] = selected;
const connector = binding.pdppSource.slice(
  binding.pdppSource.lastIndexOf("/") + 1,
);
const unbound = `${connector}:unbound-profile-for-test`;
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("unsupported profile refusal before response creation", () => {
  it("plans an unsupported profile without reading rows or writing a spool", async () => {
    const lines = vi.fn(async function* () {
      throw new Error("must not read unsupported rows");
    });
    const write = vi.fn();
    const plan = await planProjection({
      scope,
      binding,
      profileKey: unbound,
      lines,
      streamBytes: () => 0,
      sha256: async () => new Uint8Array(32),
      spool: {
        write,
        read: async () => null,
        async *readChunks() {},
        list: async () => [],
        remove: async () => {},
      },
      spoolId: "unsupported",
      budgetBytes: 1024,
      now: new Date(0).toISOString(),
    });
    expect(plan).toEqual({ kind: "unsupported_profile" });
    expect(lines).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
  });

  it.each([true, false])(
    "rejects owner=%s before a body and releases every lease (mutant: check-after-toStream)",
    async (owner) => {
      const f = new Fixture(await testOwnerKey(masterKey(owner ? 891 : 892)));
      f.overlay.connector = connector;
      const ns = await f.key.ns(connector, "test-account");
      await f.activate(connector, ns);
      for (const stream of binding.pdppStreams) {
        await f.publish({
          connector,
          ns,
          stream,
          generation: 1,
          records: [],
          primaryKey: [...binding.primaryKey[stream]!],
          profileKey: unbound,
          complete: true,
        });
      }
      const service = await f.service();
      await f.sync(service);
      const releases: ReturnType<typeof vi.fn>[] = [];
      const views = (
        service as unknown as {
          views: { lease: (...args: unknown[]) => { release(): void } | null };
        }
      ).views;
      const lease = views.lease.bind(views);
      vi.spyOn(views, "lease").mockImplementation((...args) => {
        const held = lease(...args);
        if (held) {
          const original = held.release.bind(held);
          const release = vi.fn(original);
          held.release = release;
          releases.push(release);
        }
        return held;
      });
      const OriginalStream = globalThis.ReadableStream;
      const created = vi.fn();
      vi.stubGlobal(
        "ReadableStream",
        class<T> extends OriginalStream<T> {
          constructor(
            source?: UnderlyingSource<T>,
            strategy?: QueuingStrategy<T>,
          ) {
            super(source, strategy);
            created();
          }
        },
      );
      await expect(
        service.resolve(ask(scope, { isOwnerView: owner })),
      ).rejects.toThrow("unsupported_profile");
      expect(created).not.toHaveBeenCalled();
      expect(releases).toHaveLength(binding.pdppStreams.length);
      expect(releases.every((release) => release.mock.calls.length === 1)).toBe(
        true,
      );
      expect(f.overlay.open).toBe(0);
    },
  );
});
