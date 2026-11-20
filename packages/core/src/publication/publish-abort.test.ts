import { describe, expect, it, vi } from "vitest";

import {
  publishPreparedVersion,
  type PublicationCandidate,
  type PreparedPublishOptions,
} from "./publish.js";
import type { StorageAdapter } from "../storage/adapters/interface.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const HASH = `0x${"11".repeat(32)}` as const;
const META = `0x${"22".repeat(32)}` as const;
const candidate: PublicationCandidate = {
  dataHash: HASH,
  metadataHash: META,
  sizeBytes: 3,
  lineage: undefined as never,
};

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => (open = resolve));
  return { opened, open };
}

function options(
  over: Partial<PreparedPublishOptions>,
  storage: Partial<StorageAdapter> = {},
): PreparedPublishOptions {
  return {
    ownerAddress: OWNER,
    scope: "scope.a",
    preferredVersion: 1n,
    storageAdapter: {
      urlForKey: (key: string) => `https://storage.test/${key}`,
      upload: vi.fn().mockResolvedValue("https://storage.test/blob"),
      download: vi.fn(),
      exists: vi.fn().mockResolvedValue(true),
      ...storage,
    } as unknown as StorageAdapter,
    signer: { signAddData: vi.fn().mockResolvedValue("0xsig") },
    gateway: {
      registerDataPoint: vi.fn().mockResolvedValue({ dataPointId: "0xid" }),
    },
    readHead: async () => null,
    async prepare() {
      return {
        encrypted: new Uint8Array([1, 2, 3]),
        wanted: candidate,
        verifyStored: async () => candidate,
      };
    },
    ...over,
  } as PreparedPublishOptions;
}

describe("no remote effect starts after the attempt is aborted", () => {
  it("does not register after an abort that lands while signing", async () => {
    const signing = gate();
    const controller = new AbortController();
    const opts = options({
      signal: controller.signal,
      signer: {
        signAddData: vi.fn(async () => {
          await signing.opened;
          return "0xsig";
        }),
      },
    });
    const run = publishPreparedVersion(opts);
    const settled = run.catch((error: unknown) => error);
    await new Promise((r) => setTimeout(r, 0));
    controller.abort(new Error("deadline"));
    signing.open();
    expect(await settled).toMatchObject({ message: "deadline" });
    expect(opts.gateway.registerDataPoint).not.toHaveBeenCalled();
  });

  it("does not start the healing upload after an abort that lands during the existence probe", async () => {
    const probing = gate();
    const controller = new AbortController();
    const upload = vi.fn().mockResolvedValue("https://storage.test/blob");
    const opts = options(
      {
        signal: controller.signal,
        head: {
          id: "0xid",
          expectedVersion: "1",
          dataHash: HASH,
          metadataHash: META,
        },
        fencedPublication: {
          read: async () => ({
            generation: "g",
            head: {
              id: "0xid",
              expectedVersion: "1",
              dataHash: HASH,
              metadataHash: META,
            },
          }),
          commit: vi.fn(),
        },
      },
      {
        exists: vi.fn(async () => {
          await probing.opened;
          return false;
        }),
        upload,
      },
    );
    const settled = publishPreparedVersion(opts).catch((e: unknown) => e);
    await new Promise((r) => setTimeout(r, 0));
    controller.abort(new Error("deadline"));
    probing.open();
    expect(await settled).toMatchObject({ message: "deadline" });
    expect(upload).not.toHaveBeenCalled();
  });
});
