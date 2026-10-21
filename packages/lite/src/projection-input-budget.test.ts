import { describe, expect, it, vi } from "vitest";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { granteeReadPort } from "@opendatalabs/personal-server-ts-core/storage/disclosure-policy";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import {
  createPersistentPsLiteStorage,
  createOpfsPsLiteDataFileStore,
} from "./storage.js";
import {
  createMemoryPsLitePersistence,
  createMemoryPsLiteDataFileStore,
} from "./test-support/memory.js";

const AT = "2026-10-01T00:00:00.000Z";
const SCOPE = "chatgpt.conversations";
const size = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value)).byteLength;

async function fixture(unused: string) {
  const storage = await createPersistentPsLiteStorage(
    { kind: "custom" },
    createMemoryPsLitePersistence(),
  );
  const envelopes: DataFileEnvelope[] = [
    {
      version: "1.0",
      scope: SCOPE,
      collectedAt: AT,
      data: {
        records: [
          {
            id: "c",
            title: "small",
            create_time: AT,
            update_time: AT,
            current_node: "m",
            message_count_on_current_branch: 1,
            unused,
          },
        ],
      },
    },
    {
      version: "1.0",
      scope: "chatgpt.messages",
      collectedAt: AT,
      data: {
        records: [
          {
            id: "m",
            conversation_id: "c",
            parent_id: null,
            role: "user",
            content: "small",
            content_type: "text",
            create_time: AT,
            on_current_branch: true,
            unused,
          },
        ],
      },
    },
  ];
  for (const e of envelopes) {
    const w = await storage.writeEnvelope(e);
    await storage.insertEntry({
      fileId: null,
      path: w.relativePath,
      scope: e.scope,
      collectedAt: AT,
      sizeBytes: w.sizeBytes,
    });
  }
  return { storage, sizes: envelopes.map(size) };
}

describe("Lite projection input allowance", () => {
  it("refuses an oversized stored input even when projection omits its large field", async () => {
    const { storage, sizes } = await fixture("x".repeat(3000));
    expect(sizes[0]).toBeGreaterThan(1024);
    const port = granteeReadPort(withLegacyProjection(storage), {
      maxProjectionBytes: 1024,
    });
    await expect(port.readEnvelope(SCOPE, AT)).rejects.toMatchObject({
      code: "too_large",
    });
  });

  it("shares the allowance across individually small sibling inputs", async () => {
    const { storage, sizes } = await fixture("x".repeat(500));
    const cap = Math.max(...sizes) + 10;
    expect(sizes.every((n) => n < cap)).toBe(true);
    expect(sizes.reduce((a, b) => a + b)).toBeGreaterThan(cap);
    const port = granteeReadPort(withLegacyProjection(storage), {
      maxProjectionBytes: cap,
    });
    await expect(port.readEnvelope(SCOPE, AT)).rejects.toMatchObject({
      code: "too_large",
    });
  });

  it("preserves a small projected read within the aggregate allowance", async () => {
    const { storage, sizes } = await fixture("small");
    const port = granteeReadPort(withLegacyProjection(storage), {
      maxProjectionBytes: sizes.reduce((a, b) => a + b) + 100,
    });
    expect(JSON.stringify(await port.readEnvelope(SCOPE, AT))).toContain(
      "small",
    );
  });

  it("bounds an OPFS file before text decoding or JSON parsing", async () => {
    const envelope = {
      version: "1.0",
      scope: SCOPE,
      collectedAt: AT,
      data: { records: [], unused: "x".repeat(3000) },
    };
    const file = new Blob([JSON.stringify(envelope)]);
    const text = vi.spyOn(file, "text");
    const root = {
      getDirectoryHandle: async () => root,
      getFileHandle: async () => ({ getFile: async () => file }),
    };
    vi.stubGlobal("navigator", { storage: { getDirectory: async () => root } });
    try {
      const store = await createOpfsPsLiteDataFileStore();
      await expect(
        store.readEnvelopeBounded!("data/a/b.json", { maxBytes: 1024 }),
      ).rejects.toMatchObject({ code: "too_large" });
      expect(text).not.toHaveBeenCalled();
      await expect(
        store.readEnvelopeBounded!("data/a/b.json", { maxBytes: file.size }),
      ).resolves.toEqual({ envelope, byteLength: file.size });
      expect(text).toHaveBeenCalledTimes(1);
    } finally {
      text.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  it("reports an unsupported custom bounded read without invoking its unbounded reader", async () => {
    const { readEnvelopeBounded: _bounded, ...files } =
      createMemoryPsLiteDataFileStore();
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      createMemoryPsLitePersistence(),
      files,
    );
    const e = {
      version: "1.0",
      scope: SCOPE,
      collectedAt: AT,
      data: { records: [] },
    };
    const w = await storage.writeEnvelope(e);
    await storage.insertEntry({
      fileId: null,
      path: w.relativePath,
      scope: SCOPE,
      collectedAt: AT,
      sizeBytes: w.sizeBytes,
    });
    const read = vi.spyOn(files, "readEnvelope");
    try {
      const port = granteeReadPort(withLegacyProjection(storage), {
        maxProjectionBytes: 1024,
      });
      await expect(port.readEnvelope(SCOPE, AT)).rejects.toMatchObject({
        code: "bounded_read_unavailable",
      });
      expect(read).not.toHaveBeenCalled();
      await expect(storage.readEnvelope(SCOPE, AT)).resolves.toEqual(e);
    } finally {
      read.mockRestore();
    }
  });
});
