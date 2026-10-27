import { afterEach, describe, expect, it, vi } from "vitest";
import * as openpgp from "openpgp";
import { bytesToHex } from "viem";
import { deriveScopeKey } from "@opendatalabs/vana-sdk/browser";
import { readBoundedResponse, type ByteBudget } from "../additions/budget.js";
import type { StorageAdapter } from "../storage/adapters/interface.js";
import { createVanaSyncStorageAdapter } from "../storage/adapters/vana.js";
import { ServerConfigSchema } from "../schemas/server-config.js";
import { createDpv2ReplicaTransport, ReplicaObjectRefused } from "./dpv2.js";
import {
  fragmentReplicaPayload,
  fromBase64,
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

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("bounded reads", () => {
  it("refuses a storage adapter without bounded reads", () => {
    expect(() => transport(new Map(), false)).toThrow(
      "replication needs a storage adapter with bounded reads",
    );
  });

  it("returns an object of exactly maxBytes and refuses one byte more", async () => {
    const objects = new Map<string, Uint8Array>();
    const { port } = transport(objects, true);
    const digest = `sha256:${"0".repeat(64)}`;
    objects.set(replicaManifestKey(scope, 1), new Uint8Array(4096));
    await expect(port.get(scope, 1, { maxBytes: 4096 })).resolves.toHaveLength(
      4096,
    );
    await expect(port.get(scope, 1, { maxBytes: 4095 })).rejects.toEqual(
      new ReplicaObjectRefused("oversize"),
    );
    objects.set(replicaFragmentKey(scope, digest), new Uint8Array(10));
    await expect(
      port.getFragment(scope, digest, { maxBytes: 9 }),
    ).rejects.toEqual(new ReplicaObjectRefused("oversize"));
  });

  for (const length of [false, true])
    it(`stops a public-read Vana response at the bound (${length ? "with" : "without"} Content-Length)`, async () => {
      // An 8 MiB body served in 64 KiB pulls; count what is pulled.
      let pulled = 0;
      vi.stubGlobal(
        "fetch",
        async () =>
          new Response(
            new ReadableStream<Uint8Array>({
              pull(controller) {
                if (pulled === 128) return controller.close();
                pulled++;
                controller.enqueue(new Uint8Array(65536));
              },
            }),
            length ? { headers: { "Content-Length": String(8 << 20) } } : {},
          ),
      );
      const storage = createVanaSyncStorageAdapter({
        config: ServerConfigSchema.parse({
          storage: {
            config: { vana: { apiUrl: "https://storage.test.invalid" } },
          },
          gateway: { chainId: 14800 },
        }),
        serverOwner: owner,
        serverAccount: {
          address: owner,
          signMessage: async () => "0x12" as const,
        },
        reads: "public",
      });
      const port = createDpv2ReplicaTransport({
        owner,
        masterKey: new Uint8Array(32).fill(5),
        storage,
        gateway: { registerDataPoint: async () => ({}) as never },
        feed: {
          listDataPointsByOwner: async () => ({
            dataPoints: [],
            cursor: null,
          }),
        } as never,
        signer: { signAddData: async () => "0x12" },
        evidence: async () => ({ head: null, chain: null, pending: false }),
      });
      await expect(port.get(scope, 1, { maxBytes: 4096 })).rejects.toEqual(
        new ReplicaObjectRefused("oversize"),
      );
      await expect(
        port.getFragment(scope, `sha256:${"0".repeat(64)}`, { maxBytes: 4096 }),
      ).rejects.toEqual(new ReplicaObjectRefused("oversize"));
      // Twice the bound plus the chunk in flight, for two reads; a declared
      // length refuses before the body is read at all.
      expect(pulled * 65536).toBeLessThanOrEqual(
        length ? 2 * 65536 : 2 * (2 * 4096 + 2 * 65536),
      );
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

/** A password message under `config`, with its S2K's prototype for spying on the KDF. */
async function passwordMessage(
  config: Parameters<typeof openpgp.encrypt>[0]["config"],
  passwords = ["not-the-scope-key"],
) {
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ binary: new Uint8Array([1]) }),
    passwords,
    format: "binary",
    config,
  });
  const message = await openpgp.readMessage({ binaryMessage: encrypted });
  const s2k = (message.packets[0] as unknown as { s2k: object }).s2k;
  return {
    encrypted,
    s2k: Object.getPrototypeOf(s2k) as { produceKey(): unknown },
  };
}

describe("OpenPGP profile", () => {
  it("refuses an Argon2 message before its KDF runs, whatever memory it asks for", async () => {
    const { port } = transport(new Map(), true);
    const { encrypted, s2k } = await passwordMessage({
      aeadProtect: true,
      s2kType: openpgp.enums.s2k.argon2,
      s2kArgon2Params: { passes: 1, parallelism: 1, memoryExponent: 10 },
    });
    // Ask for 2^20 KiB, 1 GiB, as the review did: the memory exponent is the
    // last byte of the S2K specifier.
    const message = await openpgp.readMessage({ binaryMessage: encrypted });
    const specifier = (
      message.packets[0] as unknown as { s2k: { write(): Uint8Array } }
    ).s2k.write();
    const at =
      Buffer.from(encrypted).indexOf(Buffer.from(specifier)) +
      specifier.length -
      1;
    const hostile = new Uint8Array(encrypted);
    hostile[at] = 20;
    const parsed = await openpgp.readMessage({ binaryMessage: hostile });
    expect(
      (parsed.packets[0] as unknown as { s2k: { encodedM: number } }).s2k
        .encodedM,
    ).toBe(20);
    const kdf = vi.spyOn(s2k, "produceKey").mockImplementation(() => {
      throw new Error("the KDF ran");
    });
    await expect(port.decrypt(scope, hostile)).rejects.toEqual(
      new ReplicaObjectRefused("profile"),
    );
    expect(kdf).not.toHaveBeenCalled();
  });

  for (const [label, config, passwords] of [
    [
      "an Argon2 S2K in a v4 packet",
      {
        s2kType: openpgp.enums.s2k.argon2,
        s2kArgon2Params: { passes: 1, parallelism: 1, memoryExponent: 10 },
      },
    ],
    ["more iterations than the writers use", { s2kIterationCountByte: 255 }],
    ["two password packets", {}, ["a", "b"]],
    ["AEAD (v6 packets)", { aeadProtect: true }],
  ] as const)
    it(`refuses ${label} before its KDF runs`, async () => {
      const { port } = transport(new Map(), true);
      const { encrypted, s2k } = await passwordMessage(
        config,
        passwords ? [...passwords] : undefined,
      );
      const kdf = vi.spyOn(s2k, "produceKey");
      await expect(port.decrypt(scope, encrypted)).rejects.toEqual(
        new ReplicaObjectRefused("profile"),
      );
      expect(kdf).not.toHaveBeenCalled();
    });

  it("decrypts what PS and Lite (SDK 3.23) and Desktop (SDK 4.1.0, OpenPGP 6.3.1) encrypt", async () => {
    const { port } = transport(new Map(), true);
    const plaintext = new TextEncoder().encode("manifest".repeat(1000));
    await expect(
      port.decrypt(scope, await port.encrypt(scope, plaintext)),
    ).resolves.toEqual(plaintext);
    // Encrypted for this scope by SDK 4.1.0's encryptWithPassword on
    // OpenPGP.js 6.3.1, the versions Desktop locks.
    await expect(
      port.decrypt(scope, fromBase64(desktopSdkCiphertext)),
    ).resolves.toEqual(new TextEncoder().encode("Desktop SDK 4.1.0 manifest"));
  });
});

const desktopSdkCiphertext =
  "wy4ECQMI9pqungnGY/jg8VjzvHeTHQvTIuZ6pOHLnCL1hjCS3MNkLcaPkKVHCxrh0ksB4VGupm7JC742cUPpgJqpA6lFyaYKk++qFqC7CplJ689l74J7Muiiwm/9nYXNEfx8xov2GV0v3N3GtvAkA4/VIBoi8My3ld8bhdc=";

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
