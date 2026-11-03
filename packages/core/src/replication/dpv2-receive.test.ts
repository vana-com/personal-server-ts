import { afterEach, describe, expect, it, vi } from "vitest";
import * as openpgp from "openpgp";
import { bytesToHex } from "viem";
import { deriveScopeKey } from "@opendatalabs/vana-sdk/browser";
import { readBoundedResponse, type ByteBudget } from "../additions/budget.js";
import type { StorageAdapter } from "../storage/adapters/interface.js";
import { createSdkStorageAdapter } from "../storage/adapters/sdk.js";
import { createVanaSyncStorageAdapter } from "../storage/adapters/vana.js";
import { ServerConfigSchema } from "../schemas/server-config.js";
import { createDpv2ReplicaTransport, ReplicaObjectRefused } from "./dpv2.js";
import {
  fragmentReplicaPayload,
  fromBase64,
  REPLICA_FRAGMENT_OVERHEAD_BYTES,
  replicaFragmentKey,
  replicaLegacyFragmentKey,
  replicaDigest,
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
  for (const fragment of [false, true])
    it(`cancels a stalled ${fragment ? "fragment" : "manifest"} read at its default deadline`, async () => {
      const controller = new AbortController();
      const timeout = vi
        .spyOn(AbortSignal, "timeout")
        .mockReturnValue(controller.signal);
      let cancelled = false;
      vi.stubGlobal(
        "fetch",
        async () =>
          new Response(
            new ReadableStream({
              start(stream) {
                stream.enqueue(new Uint8Array([1]));
              },
              cancel() {
                cancelled = true;
              },
            }),
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
          listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
        } as never,
        signer: { signAddData: async () => "0x12" },
        evidence: async () => ({ head: null, chain: null, pending: false }),
      });
      const request = fragment
        ? port.getFragment(scope, `sha256:${"0".repeat(64)}`, {
            maxBytes: 4096,
          })
        : port.get(scope, 1, { maxBytes: 4096 });
      // Let the reader acquire the stream and block on the next chunk.
      await new Promise((resolve) => setTimeout(resolve, 10));
      const result = request.then(
        () => "completed",
        () => "aborted",
      );
      controller.abort();
      expect(
        await Promise.race([
          result,
          new Promise((resolve) =>
            setTimeout(() => resolve("still pending"), 30),
          ),
        ]),
      ).toBe("aborted");
      expect(timeout).toHaveBeenCalledWith(30_000);
      expect(cancelled).toBe(true);
    });

  it("bounds existence probes instead of calling the adapter's unbounded exists", async () => {
    const objects = new Map<string, Uint8Array>();
    const { port, reads } = transport(objects, true);
    const digest = `sha256:${"0".repeat(64)}`;
    objects.set(
      replicaFragmentKey(scope, digest),
      new Uint8Array(8 * 1024 * 1024),
    );
    await expect(port.hasFragment(scope, digest)).resolves.toBe(true);
    expect(reads.length).toBe(1);
    expect(reads[0]).toBeLessThanOrEqual(2048);
  });
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

describe("SDK-compatible fragment addresses", () => {
  function fixture() {
    const objects = new Map<string, Uint8Array>();
    const reads: string[] = [],
      writes: string[] = [];
    const failures = new Map<string, number | Error>();
    const vana = createVanaSyncStorageAdapter({
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
    // Exercise the real SDK adapter's unchanged filename forwarding.
    // This provider enforces the supplied SDK filename contract, not a
    // claim that the installed SDK or a live service was exercised.
    const sdk = createSdkStorageAdapter(
      {
        async upload(blob, filename) {
          const parts = filename?.split("/") ?? [];
          if (
            parts.length !== 2 ||
            parts.some((p) => !p || p === "." || p === "..")
          )
            throw new Error("INVALID_FILENAME");
          writes.push(filename!);
          const url = vana.urlForKey(filename!);
          objects.set(url, new Uint8Array(await blob.arrayBuffer()));
          return { url };
        },
        async download() {
          throw new Error("unbounded SDK download forbidden");
        },
        async delete() {
          return false;
        },
      },
      { urlForKey: (key) => vana.urlForKey(key) },
    );
    vi.stubGlobal("fetch", async (input: string | URL | Request) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      reads.push(url);
      const failure = failures.get(url);
      if (failure instanceof Error) throw failure;
      if (failure) return new Response(null, { status: failure });
      const bytes = objects.get(url);
      return bytes
        ? new Response(new Blob([Uint8Array.from(bytes).buffer]))
        : new Response(null, { status: 404 });
    });
    const port = createDpv2ReplicaTransport({
      owner,
      masterKey: new Uint8Array(32).fill(5),
      storage: { ...sdk, downloadBounded: vana.downloadBounded.bind(vana) },
      gateway: { registerDataPoint: async () => ({}) as never },
      feed: {
        listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      } as never,
      signer: { signAddData: async () => "0x12" },
      evidence: async () => ({ head: null, chain: null, pending: false }),
    });
    return {
      port,
      objects,
      reads,
      writes,
      failures,
      url: (key: string) => vana.urlForKey(key),
    };
  }

  it("uploads, gets and probes the same two-segment SDK address", async () => {
    const f = fixture(),
      bytes = new Uint8Array([1, 2, 3]);
    const digest = replicaDigest(bytes),
      key = replicaFragmentKey(scope, digest);
    await f.port.putFragment({ scope, digest, encrypted: bytes });
    expect(f.writes).toEqual([key]);
    expect(key.split("/")).toEqual([scope, "fragments-" + digest.slice(7)]);
    expect(key).not.toBe(replicaManifestKey(scope, 1));
    await expect(
      f.port.getFragment(scope, digest, { maxBytes: 3 }),
    ).resolves.toEqual(bytes);
    await expect(f.port.hasFragment(scope, digest)).resolves.toBe(true);
    expect(f.reads).toEqual([f.url(key), f.url(key)]);
  });

  it("passes the fragment address through the installed Vana SDK upload validator", async () => {
    let signCalls = 0;
    const requests: {
      method: string;
      pathname: string;
      authorization: boolean;
    }[] = [];
    vi.stubGlobal(
      "fetch",
      async (input: string | URL | Request, init?: RequestInit) => {
        const url =
          input instanceof Request
            ? input.url
            : input instanceof URL
              ? input.href
              : input;
        requests.push({
          method: init?.method ?? "GET",
          pathname: new URL(url).pathname,
          authorization: new Headers(init?.headers).has("authorization"),
        });
        return new Response(
          JSON.stringify({ url: "https://storage.test.invalid/uploaded" }),
          { status: 201, headers: { "content-type": "application/json" } },
        );
      },
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
        signMessage: async () => {
          signCalls++;
          return `0x${"ab".repeat(65)}` as const;
        },
      },
    });
    const digest = `sha256:${"b".repeat(64)}`;
    const key = replicaFragmentKey(scope, digest);

    await expect(storage.upload(key, new Uint8Array([1, 2, 3]))).resolves.toBe(
      "https://storage.test.invalid/uploaded",
    );
    expect(signCalls).toBe(1);
    expect(requests).toEqual([
      {
        method: "PUT",
        pathname: `/v1/chains/14800/blobs/${owner}/${key}`,
        authorization: true,
      },
    ]);
  });

  for (const status of [404, 410])
    it(`reads and probes historical bytes only after new-address ${status}`, async () => {
      const f = fixture(),
        plain = new Uint8Array([7, 8, 9]);
      const bytes = await f.port.encrypt(scope, plain),
        digest = replicaDigest(bytes);
      const current = f.url(replicaFragmentKey(scope, digest));
      const legacy = f.url(replicaLegacyFragmentKey(scope, digest));
      f.failures.set(current, status);
      f.objects.set(legacy, bytes);
      const got = await f.port.getFragment(scope, digest, {
        maxBytes: bytes.length,
      });
      expect(replicaDigest(got)).toBe(digest);
      await expect(f.port.decrypt(scope, got)).resolves.toEqual(plain);
      await expect(f.port.hasFragment(scope, digest)).resolves.toBe(true);
      expect(f.reads).toEqual([current, legacy, current, legacy]);
      expect(f.writes).toEqual([]);
    });

  it("returns absent only after both addresses are definitively absent", async () => {
    const f = fixture(),
      digest = "sha256:" + "0".repeat(64);
    await expect(f.port.hasFragment(scope, digest)).resolves.toBe(false);
    expect(f.reads).toEqual([
      f.url(replicaFragmentKey(scope, digest)),
      f.url(replicaLegacyFragmentKey(scope, digest)),
    ]);
  });

  for (const failure of [401, 403, 500, new Error("connection reset")])
    it(`does not fall back on current-address ${String(failure)}`, async () => {
      const f = fixture(),
        bytes = new Uint8Array([1]),
        digest = replicaDigest(bytes);
      const current = f.url(replicaFragmentKey(scope, digest));
      f.objects.set(f.url(replicaLegacyFragmentKey(scope, digest)), bytes);
      f.failures.set(current, failure);
      await expect(
        f.port.getFragment(scope, digest, { maxBytes: 1 }),
      ).rejects.toBeDefined();
      await expect(f.port.hasFragment(scope, digest)).rejects.toBeDefined();
      expect(f.reads).toEqual([current, current]);
    });

  it("never replaces corrupt or oversized current bytes with valid legacy bytes", async () => {
    const f = fixture(),
      plain = new Uint8Array([4, 5]);
    const good = await f.port.encrypt(scope, plain),
      digest = replicaDigest(good);
    const current = f.url(replicaFragmentKey(scope, digest));
    f.objects.set(current, new Uint8Array([0, 1, 2]));
    f.objects.set(f.url(replicaLegacyFragmentKey(scope, digest)), good);
    const got = await f.port.getFragment(scope, digest, {
      maxBytes: good.length,
    });
    // Digest verification remains the receiver's responsibility; the carrier
    // must not try a different address after bad bytes have been returned.
    expect(replicaDigest(got)).not.toBe(digest);
    await expect(f.port.decrypt(scope, got)).rejects.toBeDefined();
    await expect(
      f.port.getFragment(scope, digest, { maxBytes: 2 }),
    ).rejects.toEqual(new ReplicaObjectRefused("oversize"));
    await expect(f.port.hasFragment(scope, digest)).resolves.toBe(true);
    expect(f.reads).toEqual([current, current, current]);
  });

  it("honors cancellation between new-address absence and legacy fallback", async () => {
    const f = fixture(),
      digest = "sha256:" + "0".repeat(64);
    const current = f.url(replicaFragmentKey(scope, digest));
    const controller = new AbortController(),
      reads: string[] = [];
    vi.stubGlobal("fetch", async (input: string | URL | Request) => {
      reads.push(
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url,
      );
      controller.abort(new Error("cancelled before legacy"));
      return new Response(null, { status: 404 });
    });
    await expect(
      f.port.getFragment(scope, digest, {
        maxBytes: 1,
        signal: controller.signal,
      }),
    ).rejects.toBeDefined();
    expect(reads).toEqual([current]);
  });

  it("does not retry legacy reads or hide a legacy authentication failure", async () => {
    const f = fixture(),
      digest = "sha256:" + "0".repeat(64);
    const current = f.url(replicaFragmentKey(scope, digest));
    const legacy = f.url(replicaLegacyFragmentKey(scope, digest));
    f.failures.set(legacy, 403);
    await expect(
      f.port.getFragment(scope, digest, { maxBytes: 1 }),
    ).rejects.toBeDefined();
    await expect(f.port.hasFragment(scope, digest)).rejects.toBeDefined();
    expect(f.reads).toEqual([current, legacy, current, legacy]);
  });
});
