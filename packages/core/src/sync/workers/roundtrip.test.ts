import { describe, expect, it, vi } from "vitest";

import type {
  DataFileEnvelope,
  DataPointRecord,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";

import type { ServerSigner } from "../../signing/signer.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import type { Logger } from "../../logger/index.js";
import { downloadOne } from "./download.js";
import { uploadOne } from "./upload.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const SCOPE = "instagram.profile";
const COLLECTED_AT = "2026-01-21T10:00:00Z";
const DATA_POINT_ID =
  "0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed";

class MemoryBlobAdapter implements StorageAdapter {
  readonly blobs = new Map<string, Uint8Array>();

  async upload(key: string, data: Uint8Array): Promise<string> {
    this.blobs.set(key, new Uint8Array(data));
    return this.urlForKey(key);
  }

  urlForKey(key: string): string {
    return `memory://blob/${key}`;
  }

  async download(url: string): Promise<Uint8Array> {
    const key = this.keyFromUrl(url);
    const blob = this.blobs.get(key);
    if (!blob) throw new Error(`missing blob ${key}`);
    return new Uint8Array(blob);
  }

  async delete(url: string): Promise<boolean> {
    return this.blobs.delete(this.keyFromUrl(url));
  }

  async exists(url: string): Promise<boolean> {
    return this.blobs.has(this.keyFromUrl(url));
  }

  private keyFromUrl(url: string): string {
    const prefix = "memory://blob/";
    if (!url.startsWith(prefix)) throw new Error(`unexpected blob URL ${url}`);
    return url.slice(prefix.length);
  }
}

function makeLogger(): Logger {
  return {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger;
}

describe("sync worker real crypto round trip", () => {
  it("preserves producer provenance while serving the original data bytes", async () => {
    const masterKey = new Uint8Array(65).fill(0xaa);
    const storageAdapter = new MemoryBlobAdapter();
    const producerStorage = createMemoryDataStorage();
    const granteeStorage = createMemoryDataStorage();
    const producerProvenance = {
      projector_version: "1",
      declaration_digest: "sha256:declaration",
      inputs: [{ stream: "profile", changes_since_token: "opaque" }],
      payload_sha256: "a".repeat(64),
    };
    const unattributedEnvelope: DataFileEnvelope = {
      version: "1.0",
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
      data: { username: "testuser", followers: 12 },
    };
    const attributedEnvelope = {
      ...unattributedEnvelope,
      producer: "pdpp-projector",
      producer_provenance: producerProvenance,
    } as DataFileEnvelope & {
      producer: "pdpp-projector";
      producer_provenance: typeof producerProvenance;
    };

    const write = await producerStorage.writeEnvelope(attributedEnvelope);
    const unsynced = producerStorage.insertEntry({
      fileId: null,
      schemaId: null,
      path: write.relativePath,
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
      sizeBytes: write.sizeBytes,
      version: 1,
      dataPointId: null,
      producer: "pdpp-projector",
      producerProvenance: JSON.stringify(producerProvenance),
    });

    let registered: DataPointRecord | null = null;
    const gateway = {
      registerDataPoint: vi.fn(async (request) => {
        registered = {
          id: DATA_POINT_ID,
          ownerAddress: request.ownerAddress,
          scope: request.scope,
          dataHash: request.dataHash,
          metadataHash: request.metadataHash,
          expectedVersion: request.expectedVersion,
          addedAt: "2026-01-21T10:00:00Z",
        };
        return { dataPointId: DATA_POINT_ID };
      }),
      getDataPoint: vi.fn(async () => registered),
      listDataPointsByOwner: vi.fn(),
    } as unknown as GatewayClient;
    const signer = {
      signAddData: vi.fn(async () => `0x${"11".repeat(65)}` as `0x${string}`),
      signLineageAttestation: vi.fn(
        async () => `0x${"22".repeat(65)}` as `0x${string}`,
      ),
    } as Pick<ServerSigner, "signAddData" | "signLineageAttestation">;

    await uploadOne(
      {
        storage: producerStorage,
        storageAdapter,
        gateway,
        signer,
        masterKey,
        serverOwner: OWNER,
        logger: makeLogger(),
      },
      unsynced,
    );

    expect(registered).not.toBeNull();
    expect(storageAdapter.blobs.get(`${SCOPE}/1`)).toBeInstanceOf(Uint8Array);

    await downloadOne(
      {
        storage: granteeStorage,
        storageAdapter,
        gateway,
        cursor: {
          read: vi.fn(),
          write: vi.fn(),
        },
        masterKey,
        serverOwner: OWNER,
        logger: makeLogger(),
      },
      registered!,
    );

    const downloaded = (await granteeStorage.readEnvelope(
      SCOPE,
      COLLECTED_AT,
    )) as DataFileEnvelope & {
      producer?: unknown;
      producer_provenance?: unknown;
    };
    expect(downloaded.producer).toBe("pdpp-projector");
    expect(downloaded.producer_provenance).toEqual(producerProvenance);
    expect(granteeStorage.entries[0]).toEqual(
      expect.objectContaining({
        producer: "pdpp-projector",
        producerProvenance: JSON.stringify(producerProvenance),
      }),
    );
    expect(new TextEncoder().encode(JSON.stringify(downloaded.data))).toEqual(
      new TextEncoder().encode(JSON.stringify(unattributedEnvelope.data)),
    );
  });
});
