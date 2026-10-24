import { describe, expect, it, vi } from "vitest";
import {
  createDataFileEnvelope,
  deriveScopeKey,
  encryptWithPassword,
  type DataFileEnvelope,
} from "@opendatalabs/vana-sdk/browser";
import { publishVersion } from "@opendatalabs/personal-server-ts-core/publication";
import type {
  FencedPublicationPort,
  PublicationFence,
} from "@opendatalabs/personal-server-ts-core/publication";
import type { StorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { StoredBlobConflictError } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { createIndexManager } from "./index-manager.js";
import { initializeDatabase } from "./index-schema.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";

describe("fenced publication candidate authority", () => {
  it("refuses a recovered legacy candidate after real canonical takeover", async () => {
    const scope = "oura.activity";
    const collectedAt = "2026-10-24T00:00:00Z";
    const masterKey = new Uint8Array(65).fill(0x2a);
    const db = initializeDatabase(":memory:");
    const index = createIndexManager(db);
    const authority = createLegacyScopeAuthority(db);
    const legacyPath = `${scope.replace(".", "/")}/${collectedAt}.json`;
    index.insert({
      fileId: null,
      path: legacyPath,
      scope,
      collectedAt,
      sizeBytes: 40,
      producer: null,
    });
    const legacyHead = authority.eligibleLegacyHead(scope);
    expect(legacyHead).not.toBeNull();
    expect(
      await authority.confirmRead(scope, legacyHead, () => true, "oura"),
    ).toBe(true);
    expect(authority.hasCanonicalAuthority(scope)).toBe(true);
    expect(authority.hasTakeover(scope)).toBe(true);

    const legacyEnvelope = createDataFileEnvelope(scope, collectedAt, {
      value: "foreign legacy bytes",
    });
    const legacyPlaintext = new TextEncoder().encode(
      JSON.stringify(legacyEnvelope),
    );
    const scopeKey = Array.from(deriveScopeKey(masterKey, scope), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    const legacyCiphertext = await encryptWithPassword(
      legacyPlaintext,
      scopeKey,
    );
    const storageAdapter: StorageAdapter = {
      upload: vi.fn(async (key) => {
        throw new StoredBlobConflictError(key);
      }),
      urlForKey: (key) => `https://storage.example/${key}`,
      download: vi.fn(async () => {
        return legacyCiphertext;
      }),
      async delete() {
        return false;
      },
      async exists() {
        return false;
      },
    };
    const initialFence: PublicationFence = {
      generation: "generation-1",
      head: null,
    };
    const fencedPublication: FencedPublicationPort = {
      read: vi.fn().mockResolvedValue(initialFence),
      commit: vi.fn().mockRejectedValue(new Error("must not register")),
    };
    const registerDataPoint = vi.fn();
    const canonicalEnvelope = {
      ...createDataFileEnvelope(scope, collectedAt, {
        value: "canonical upload",
      }),
      producer: "pdpp-projector",
    } as DataFileEnvelope;
    const publishOptions = {
      ownerAddress: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
      envelope: canonicalEnvelope,
      preferredVersion: 1n,
      masterKey,
      storageAdapter,
      signer: {
        signAddData: vi.fn().mockResolvedValue("0xsignature"),
      },
      gateway: { registerDataPoint },
      fencedPublication,
      registrationAuthority: authority,
      publicationClass: "canonical" as const,
      readHead: async () => null,
    };

    await expect(publishVersion(publishOptions)).rejects.toMatchObject({
      code: "HISTORY_ONLY_VERSION",
    });

    expect(storageAdapter.download).toHaveBeenCalledOnce();
    expect(fencedPublication.commit).not.toHaveBeenCalled();
    expect(registerDataPoint).not.toHaveBeenCalled();

    const unknownProducerEnvelope = {
      ...createDataFileEnvelope(scope, collectedAt, { value: "unknown" }),
      producer: "unrecognized-producer",
    };
    const unknownProducerCiphertext = await encryptWithPassword(
      new TextEncoder().encode(JSON.stringify(unknownProducerEnvelope)),
      scopeKey,
    );
    (storageAdapter.download as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
      unknownProducerCiphertext,
    );
    await expect(publishVersion(publishOptions)).rejects.toThrow(
      "Cannot determine publication class from candidate producer",
    );
    expect(fencedPublication.commit).not.toHaveBeenCalled();
    expect(registerDataPoint).not.toHaveBeenCalled();

    index.close();
  });
});
