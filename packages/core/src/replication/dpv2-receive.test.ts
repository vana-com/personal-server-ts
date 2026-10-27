import { describe, expect, it } from "vitest";
import * as openpgp from "openpgp";
import { bytesToHex } from "viem";
import { deriveScopeKey } from "@opendatalabs/vana-sdk/browser";
import { readBoundedResponse, type ByteBudget } from "../additions/budget.js";
import type { StorageAdapter } from "../storage/adapters/interface.js";
import { createDpv2ReplicaTransport, ReplicaObjectRefused } from "./dpv2.js";
import {
  fragmentReplicaPayload,
  REPLICA_FRAGMENT_OVERHEAD_BYTES,
  replicaFragmentKey,
  replicaFramedBytesBound,
  replicaManifestKey,
  replicaScope,
} from "./transport.js";

const owner = `0x${"1".repeat(40)}` as const;
const writer = "a".repeat(32);
const scope = replicaScope(writer);

/** A DPv2 transport over in-memory storage, with or without bounded reads. */
function transport(objects: Map<string, Uint8Array>, bounded: boolean) {
  const reads: number[] = [];
  const storage: StorageAdapter = {
    upload: async (key, data) => {
      objects.set(key, data);
      return key;
    },
    urlForKey: (key) => key,
    download: async (key) => {
      const bytes = objects.get(key);
      if (!bytes) throw new Error("404");
      reads.push(bytes.length);
      return bytes;
    },
    delete: async () => false,
    exists: async (key) => objects.has(key),
    ...(bounded && {
      async downloadBounded(key: string, budget: ByteBudget) {
        const bytes = objects.get(key)!;
        // Serve in 1 KiB chunks, so a refusal stops part-way.
        let offset = 0;
        const body = new ReadableStream<Uint8Array>({
          pull(controller) {
            if (offset >= bytes.length) return controller.close();
            controller.enqueue(bytes.slice(offset, offset + 1024));
            offset += 1024;
          },
        });
        try {
          return await readBoundedResponse(new Response(body), budget);
        } finally {
          reads.push(Math.min(offset, bytes.length));
        }
      },
    }),
  };
  const port = createDpv2ReplicaTransport({
    owner,
    masterKey: new Uint8Array(32).fill(5),
    storage,
    gateway: { registerDataPoint: async () => ({}) as never },
    feed: {
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    } as never,
    signer: { signAddData: async () => "0x12" },
    evidence: async () => ({ head: null, chain: null, pending: false }),
  });
  return { port, reads };
}

describe("bounded reads", () => {
  for (const bounded of [true, false])
    it(`returns an object of exactly maxBytes and refuses one byte more (${bounded ? "bounded storage" : "plain storage"})`, async () => {
      const objects = new Map<string, Uint8Array>();
      const { port } = transport(objects, bounded);
      const digest = `sha256:${"0".repeat(64)}`;
      objects.set(replicaManifestKey(scope, 1), new Uint8Array(4096));
      await expect(
        port.get(scope, 1, { maxBytes: 4096 }),
      ).resolves.toHaveLength(4096);
      await expect(port.get(scope, 1, { maxBytes: 4095 })).rejects.toEqual(
        new ReplicaObjectRefused("oversize"),
      );
      objects.set(replicaFragmentKey(scope, digest), new Uint8Array(10));
      await expect(
        port.getFragment(scope, digest, { maxBytes: 9 }),
      ).rejects.toEqual(new ReplicaObjectRefused("oversize"));
    });

  it("stops reading an oversize object at the bound", async () => {
    const objects = new Map<string, Uint8Array>();
    const { port, reads } = transport(objects, true);
    objects.set(replicaManifestKey(scope, 1), new Uint8Array(1024 * 1024));
    await expect(port.get(scope, 1, { maxBytes: 4096 })).rejects.toEqual(
      new ReplicaObjectRefused("oversize"),
    );
    // The reader charges chunks and their copy against twice the bound, and
    // the stream may have pulled one chunk ahead.
    expect(reads).toHaveLength(1);
    expect(reads[0]).toBeLessThanOrEqual(2 * 4096 + 2 * 1024);
  });
});

describe("decryption", () => {
  it("decrypts the SDK's own encryption", async () => {
    const { port } = transport(new Map(), true);
    const plaintext = new TextEncoder().encode("manifest".repeat(1000));
    const encrypted = await port.encrypt(scope, plaintext);
    await expect(port.decrypt(scope, encrypted)).resolves.toEqual(plaintext);
  });

  it("refuses a compressed message before it inflates", async () => {
    const { port } = transport(new Map(), true);
    // 4 MiB of zeros with zlib, under the scope password the port derives.
    const password = bytesToHex(
      deriveScopeKey(new Uint8Array(32).fill(5), scope),
    ).slice(2);
    const compressed = await openpgp.encrypt({
      message: await openpgp.createMessage({
        binary: new Uint8Array(4 * 1024 * 1024),
      }),
      passwords: [password],
      format: "binary",
      config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
    });
    expect(compressed.length).toBeLessThan(64 * 1024);
    await expect(port.decrypt(scope, compressed)).rejects.toEqual(
      new ReplicaObjectRefused("compressed"),
    );
  });
});

describe("framed bytes bound", () => {
  for (const [label, payload, chunk] of [
    ["one-byte chunks", 64, 1],
    ["1 MiB chunks", 3 * 1024 * 1024 + 5, 1024 * 1024],
    ["4 MiB chunks", 9 * 1024 * 1024, 4 * 1024 * 1024],
  ] as const)
    it(`holds for real encrypted fragments: ${label}`, async () => {
      const { port } = transport(new Map(), true);
      const fragments = await fragmentReplicaPayload({
        owner,
        writer,
        batch: "b".repeat(32),
        sequence: 2,
        previous: { batch: "c".repeat(32), digest: `sha256:${"d".repeat(64)}` },
        bytes: new Uint8Array(payload).fill(9),
        collectedAt: "2026-10-27T00:00:00.000Z",
        encrypt: port.encrypt,
        maxBlobBytes: 100 * 1024 * 1024,
        targetChunkBytes: chunk,
      });
      const encrypted = fragments.map((f) => f.encrypted.length);
      const total = encrypted.reduce((a, b) => a + b, 0);
      expect(total).toBeLessThanOrEqual(
        replicaFramedBytesBound(payload, fragments.length),
      );
      // Each fragment's overhead beyond its base64 chunk stays well inside
      // the constant.
      for (const [index, bytes] of encrypted.entries()) {
        const size = Math.min(chunk, payload - index * chunk);
        expect(bytes - 4 * Math.ceil(size / 3)).toBeLessThan(
          REPLICA_FRAGMENT_OVERHEAD_BYTES / 2,
        );
      }
    }, 60000);
});
