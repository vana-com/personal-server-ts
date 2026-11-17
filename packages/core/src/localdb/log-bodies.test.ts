import { expect, it } from "vitest";
import type {
  JsonObject,
  LogUpsert,
  LogUpsertByRef,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createMemoryStreamSyncBlobs } from "../stream-sync/memory-registry.js";
import { PARTS_IN_FLIGHT } from "../stream-sync/storage-retry.js";
import type { LocalSyncDeps } from "./deps.js";
import { putBodiesOutOfLine, resolveBodies } from "./log-bodies.js";

const SCOPE = "log-scope";
const keys = {
  encryptPart: async (_scope: string, bytes: Uint8Array) => bytes,
  decrypt: async (_scope: string, bytes: Uint8Array) => bytes,
} as unknown as LocalSyncDeps["keys"];

it("fetches a body's pieces at most the store gate's width at once", async () => {
  const value: JsonObject = { id: "x", text: "y".repeat(4096) };
  const upsert: LogUpsert = {
    kind: "upsert",
    stream: "s",
    pkHash: "0x01",
    key: ["x"],
    stamp: { o: 1, r: "r" },
    value,
  } as unknown as LogUpsert;
  // 64-byte pieces: about 65 of them, several times the gate's width.
  const { ops, pieces } = await putBodiesOutOfLine(
    { keys },
    SCOPE,
    [upsert],
    64,
  );
  expect(pieces.length).toBeGreaterThan(PARTS_IN_FLIGHT * 2);
  const store = createMemoryStreamSyncBlobs();
  for (const piece of pieces)
    await store.put(`${SCOPE}/${piece.name}`, piece.cipher);

  let open = 0;
  let most = 0;
  const blobs = {
    ...store,
    get: async (key: string) => {
      open += 1;
      most = Math.max(most, open);
      await new Promise((resolve) => setTimeout(resolve, 1));
      open -= 1;
      return store.get(key);
    },
  };
  // A body this device resolved is remembered by object: read a copy.
  const [byRef] = ops as LogUpsertByRef[];
  const [resolved] = await resolveBodies({ blobs, keys }, SCOPE, [
    { ...byRef!, body: { ...byRef!.body } },
  ]);

  expect(resolved).toMatchObject({ kind: "upsert", value });
  expect(most).toBe(PARTS_IN_FLIGHT);
});
