import { describe, expect, it } from "vitest";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { granteeReadPort } from "./disclosure-policy.js";
import { withLegacyProjection } from "./legacy-projection.js";

const AT = "2026-10-01T00:00:00.000Z";
const SCOPE = "chatgpt.conversations";
const conversation = {
  id: "c",
  title: "a",
  create_time: AT,
  update_time: AT,
  current_node: "m",
  message_count_on_current_branch: 1,
};

async function fixture(unused = "") {
  const raw = createMemoryDataStorage();
  const values: DataFileEnvelope[] = [
    {
      version: "1.0",
      scope: SCOPE,
      collectedAt: AT,
      data: {
        records: Array.from({ length: unused ? 1 : 16 }, () => ({
          ...conversation,
          unused,
        })),
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
            content: unused ? "small" : "x".repeat(1024),
            content_type: "text",
            create_time: AT,
            on_current_branch: true,
          },
        ],
      },
    },
  ];
  for (const envelope of values) {
    const written = await raw.writeEnvelope(envelope);
    await raw.insertEntry({
      fileId: null,
      path: written.path,
      scope: envelope.scope,
      collectedAt: AT,
      sizeBytes: written.sizeBytes,
    });
  }
  raw.readEnvelopeStream = async (scope, at) =>
    new Blob([JSON.stringify(await raw.readEnvelope(scope, at))]).stream();
  raw.readScopeBlocks = async () => {
    throw new Error("projection must provide blocks");
  };
  raw.readBlockManifest = async () => null;
  const port = granteeReadPort(withLegacyProjection(raw), {
    maxProjectionBytes: 8192,
  });
  const row = raw.findEntry({ scope: SCOPE })!;
  await new Response(
    await port.readEnvelopeStream!(port.pinVersion(row), { maxBytes: 65536 }),
  ).text();
  return { port, row };
}

describe("a projection cache never reuses a read allowance", () => {
  it.each(["envelope", "blocks", "manifest"] as const)(
    "rechecks a smaller %s output cap on a warm value",
    async (kind) => {
      const { port, row } = await fixture();
      const read =
        kind === "envelope"
          ? port.readEnvelope(SCOPE, AT)
          : kind === "blocks"
            ? port.readScopeBlocks!(SCOPE, AT, {
                maxBytes: 512,
                generation: row.generation,
              })
            : port.readBlockManifest!(SCOPE, AT, {
                generation: row.generation,
              });
      await expect(read).rejects.toMatchObject({ code: "too_large" });
    },
  );

  it("keeps the smaller stream rejection", async () => {
    const { port, row } = await fixture();
    await expect(
      port.readEnvelopeStream!(port.pinVersion(row), { maxBytes: 8192 }),
    ).rejects.toMatchObject({ code: "too_large" });
  });

  it("rechecks the cached input cost even when its output fits", async () => {
    const { port } = await fixture("z".repeat(10000));
    await expect(port.readEnvelope(SCOPE, AT)).rejects.toMatchObject({
      code: "too_large",
    });
  });

  it("serves a warm small value within the current allowances", async () => {
    const { port } = await fixture("small");
    expect(JSON.stringify(await port.readEnvelope(SCOPE, AT))).toContain(
      "small",
    );
  });
});
