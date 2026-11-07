import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import type { Head } from "@opendatalabs/personal-server-ts-stream-sync";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import type { StreamSyncReadFiles } from "./ports.js";
import { ViewStore, type ViewKey } from "./view-store.js";

const KEY: ViewKey = { connector: "c", ns: "n", stream: "s" };
const enc = new TextEncoder();
const dec = new TextDecoder();

/** A part is stored under the SHA-256 of its clear bytes. */
function partBytes(label: string): Uint8Array {
  return enc.encode(`part ${label}\n`);
}
function partHash(label: string): string {
  return Array.from(sha256(partBytes(label)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

function headOf(...hashes: string[]): Head {
  return { parts: hashes.map((hash) => ({ hash })) } as unknown as Head;
}

/** Holds `list(<suffix>)` calls (the first `count`) until `open()` is called. */
function gated(files: StreamSyncReadFiles, suffix: string, count = 1) {
  let waiting = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  let reached!: () => void;
  const hit = new Promise<void>((resolve) => (reached = resolve));
  const wrapped: StreamSyncReadFiles = {
    ...files,
    async list(prefix) {
      if (prefix.endsWith(suffix) && waiting > 0) {
        waiting--;
        reached();
        await gate;
      }
      return files.list(prefix);
    },
  };
  return {
    files: wrapped,
    hit,
    open: release,
    arm: () => void (waiting = count),
  };
}

/** Import one version the way the importer does: parts first, then commit. */
async function importVersion(
  store: ViewStore,
  version: number,
  label: string,
): Promise<void> {
  const part = partHash(label);
  const head = headOf(part);
  await store.withImport(KEY, async (tx) => {
    await tx.putPart(part, partBytes(label));
    await tx.commit(
      version,
      `h${version}`,
      enc.encode(`head ${version}`),
      head,
    );
  });
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 25));

async function expectViewIntact(
  base: ReturnType<typeof createMemoryStreamSyncReadFiles>,
  store: ViewStore,
  version: number,
  label: string,
) {
  const lease = store.lease(KEY)!;
  expect(lease.version.version).toBe(version);
  const paths = await base.list("views");
  expect(paths.some((p) => p.endsWith(`/heads/${version}.json`))).toBe(true);
  expect(dec.decode(await store.readPart(KEY, partHash(label)))).toBe(
    `part ${label}\n`,
  );
  lease.release();
}

describe("ViewStore collection vs import", () => {
  async function seeded(suffix: string, count = 1) {
    const base = createMemoryStreamSyncReadFiles();
    const g = gated(base, suffix, count);
    const store = await ViewStore.open(g.files);
    await importVersion(store, 1, "a");
    g.arm();
    return { base, g, store };
  }

  it("a collector held at the heads listing does not delete a version imported meanwhile", async () => {
    const { base, g, store } = await seeded("/heads");
    store.lease(KEY)!.release(); // collector starts, holds at the heads listing
    await g.hit;
    const importing = importVersion(store, 2, "b");
    await settle();
    const leased = store.lease(KEY);
    g.open();
    await importing;
    await settle();
    await expectViewIntact(base, store, 2, "b");
    leased?.release();
  });

  it("a collector held at the parts listing does not delete a part imported meanwhile", async () => {
    const { base, g, store } = await seeded("/parts");
    store.lease(KEY)!.release();
    await g.hit;
    const importing = importVersion(store, 2, "b");
    await settle();
    g.open();
    await importing;
    await settle();
    await expectViewIntact(base, store, 2, "b");
  });

  it("two collectors cannot delete the version a later import committed", async () => {
    const { base, g, store } = await seeded("/heads", 2);
    store.lease(KEY)!.release();
    store.lease(KEY)!.release();
    await g.hit;
    const importing = importVersion(store, 2, "b");
    await settle();
    g.open();
    await importing;
    await settle();
    await expectViewIntact(base, store, 2, "b");
  });
});
