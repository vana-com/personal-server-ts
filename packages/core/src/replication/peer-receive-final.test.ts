import { describe, expect, it } from "vitest";
import {
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import { bytesToHex } from "viem";
import { createDpv2ReplicaTransport } from "./dpv2.js";
import desktopFixture from "./__fixtures__/sdk41-replica.json";
import {
  decodeReplicaManifest,
  decodeReplicaFragment,
  fragmentMatchesManifest,
  fragmentReplicaPayload,
  prepareReplicaManifest,
  REPLICA_MAX_FRAGMENTS,
  ReplicaManifestRefused,
  replicaScope,
} from "./transport.js";
import { unsignedReplicaBatch } from "./writer-identity.test-utils.js";

const owner = `0x${"1".repeat(40)}`;
const writer = "a".repeat(32);
const scope = replicaScope(writer);
const masterKey = new Uint8Array(32).fill(5);
const password = bytesToHex(deriveScopeKey(masterKey, scope)).slice(2);
const collectedAt = "2026-10-27T00:00:00.000Z";

async function validManifest() {
  const result = await prepareReplicaManifest({
    owner,
    writer,
    version: 2,
    batch: "b".repeat(32),
    sequence: 2,
    previous: { batch: "c".repeat(32), digest: `sha256:${"1".repeat(64)}` },
    collectedAt,
    digest: `sha256:${"2".repeat(64)}`,
    totalBytes: 2,
    fragments: [
      { digest: `sha256:${"3".repeat(64)}`, bytes: 1 },
      { digest: `sha256:${"4".repeat(64)}`, bytes: 1 },
    ],
    sign: unsignedReplicaBatch,
    encrypt: async (_scope, bytes) => bytes,
  });
  return new TextDecoder().decode(result.plaintext);
}

function withRawNumber(text: string, path: (string | number)[], raw: string) {
  const tree = JSON.parse(text) as Record<string, unknown>;
  let parent: unknown = tree;
  for (const key of path.slice(0, -1))
    parent = (parent as Record<string | number, unknown>)[key]!;
  const last = path.at(-1)!;
  (parent as Record<string | number, unknown>)[last] = "__RAW_NUMBER__";
  return JSON.stringify(tree).replace('"__RAW_NUMBER__"', raw);
}

describe("peer manifest numeric fields", () => {
  it.each([
    ["version", ["data", "manifest", "version"]],
    ["sequence", ["data", "manifest", "sequence"]],
    ["totalBytes", ["data", "manifest", "totalBytes"]],
    ["fragment length", ["data", "manifest", "fragments", 0, "bytes"]],
  ] as const)(
    "rejects negative, fractional, unsafe and overflow values for %s",
    async (_label, path) => {
      const valid = await validManifest();
      expect(() =>
        decodeReplicaManifest(new TextEncoder().encode(valid), scope, owner),
      ).not.toThrow();
      for (const raw of [
        "-1",
        "1.5",
        "9007199254740992",
        "1e400",
        "NaN",
        '"NaN"',
      ]) {
        const malformed = withRawNumber(valid, [...path], raw);
        // The original decoder accepts this exact key order, so each refusal is
        // caused by numeric validation rather than canonicalization.
        const plaintext = new TextEncoder().encode(malformed);
        expect(() => decodeReplicaManifest(plaintext, scope, owner)).toThrow(
          new ReplicaManifestRefused("manifest_invalid"),
        );
      }
    },
  );

  it("rejects duplicate fragment hashes", async () => {
    const valid = await validManifest();
    const tree = JSON.parse(valid) as {
      data: { manifest: { fragments: { digest: string }[] } };
    };
    tree.data.manifest.fragments[1]!.digest =
      tree.data.manifest.fragments[0]!.digest;
    expect(() =>
      decodeReplicaManifest(
        new TextEncoder().encode(JSON.stringify(tree)),
        scope,
        owner,
      ),
    ).toThrow();
  });

  it("rejects a fragment count above the protocol limit", async () => {
    const valid = await validManifest();
    const tree = JSON.parse(valid) as {
      data: { manifest: { fragments: { digest: string; bytes: number }[] } };
    };
    const entry = tree.data.manifest.fragments[0]!;
    tree.data.manifest.fragments = Array.from(
      { length: REPLICA_MAX_FRAGMENTS + 1 },
      () => ({ ...entry }),
    );
    expect(() =>
      decodeReplicaManifest(
        new TextEncoder().encode(JSON.stringify(tree)),
        scope,
        owner,
      ),
    ).toThrow();
  });
});

function transport() {
  return createDpv2ReplicaTransport({
    owner,
    masterKey,
    storage: {
      upload: async () => "unused",
      urlForKey: (key: string) => key,
      download: async () => new Uint8Array(),
      delete: async () => false,
      exists: async () => false,
      downloadBounded: async () => new Uint8Array(),
    },
    gateway: { registerDataPoint: async () => ({}) as never },
    feed: {
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    } as never,
    signer: { signAddData: async () => "0x12" },
    evidence: async () => ({ head: null, chain: null, pending: false }),
  });
}

describe("honest SDK writer crypto", () => {
  it("decrypts SDK 3.23 / OpenPGP 6.3.0 manifests and fragments", async () => {
    const port = transport();
    const manifest = await prepareReplicaManifest({
      owner,
      writer,
      version: 2,
      batch: "b".repeat(32),
      sequence: 2,
      previous: { batch: "c".repeat(32), digest: `sha256:${"1".repeat(64)}` },
      collectedAt,
      digest: `sha256:${"2".repeat(64)}`,
      totalBytes: 1,
      fragments: [{ digest: `sha256:${"3".repeat(64)}`, bytes: 1 }],
      sign: unsignedReplicaBatch,
      encrypt: async (_scope, bytes) => encryptWithPassword(bytes, password),
    });
    await expect(port.decrypt(scope, manifest.encrypted)).resolves.toEqual(
      manifest.plaintext,
    );

    const fragmentPlaintext = new TextEncoder().encode("SDK 3.23 fragment");
    const framed = await fragmentReplicaPayload({
      owner,
      writer,
      batch: "b".repeat(32),
      sequence: 2,
      previous: { batch: "c".repeat(32), digest: `sha256:${"1".repeat(64)}` },
      bytes: fragmentPlaintext,
      collectedAt,
      encrypt: async (_scope, bytes) => encryptWithPassword(bytes, password),
      maxBlobBytes: 1024 * 1024,
      targetChunkBytes: 1024,
    });
    await expect(port.decrypt(scope, framed[0]!.encrypted)).resolves.toEqual(
      framed[0]!.plaintext,
    );
  });

  it("decrypts SDK 4.1 / OpenPGP 6.3.1 manifest and fragment ciphertext", async () => {
    const port = transport();
    expect(desktopFixture.versions).toEqual({ sdk: "4.1.0", openpgp: "6.3.1" });
    const manifestPlaintext = await port.decrypt(
      scope,
      fromBase64(desktopFixture.manifest.encrypted),
    );
    expect(manifestPlaintext).toEqual(
      fromBase64(desktopFixture.manifest.plaintext),
    );
    const manifest = decodeReplicaManifest(manifestPlaintext, scope, owner);
    const fragmentPlaintext = await port.decrypt(
      scope,
      fromBase64(desktopFixture.fragment.encrypted),
    );
    expect(fragmentPlaintext).toEqual(
      fromBase64(desktopFixture.fragment.plaintext),
    );
    const fragment = decodeReplicaFragment(fragmentPlaintext, scope, owner);
    expect(fragmentMatchesManifest(fragment, manifest, 0)).toBe(true);
  });
});

function fromBase64(encoded: string) {
  return Uint8Array.from(Buffer.from(encoded, "base64"));
}
