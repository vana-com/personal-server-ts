import { keccak_256 } from "@noble/hashes/sha3";
import {
  encodeSegment,
  encodeSnapshotPart,
  digestSegment,
  digestSnapshotPart,
  type SnapshotPart,
  type Segment,
  type LogEntry,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  world,
  CONNECTION_ID,
  CONNECTOR,
  LOG,
  idHash,
} from "./log-world.test-utils.js";
export async function progressiveScenario(
  partsCount = 4,
  distinct = false,
  entries?: readonly (readonly LogEntry[])[],
) {
  const w = await world({ streams: 1 });
  const a = await w.device("sender");
  await a.run("first", [{ stream: "s0", id: "k" }]);
  await a.cycle();
  const template = [...(await w.segments()).values()][0]!;
  const pk = await idHash("k");
  const hashes = await Promise.all(
    Array.from({ length: partsCount }, (_, i) =>
      idHash(`k${String(i).padStart(3, "0")}`),
    ),
  );
  const upsert = (o: number) => ({
    kind: "upsert" as const,
    stream: "s0",
    pkHash: pk,
    stamp: { o, r: "r" },
    firstSeen: o,
    value: { id: "k", v: o },
  });
  const extra = (index: number) =>
    distinct
      ? {
          ...upsert(30 + index),
          pkHash: hashes[index]!,
          value: { id: `k${String(index).padStart(3, "0")}`, v: 30 + index },
        }
      : upsert(30 + index);
  const parts: SnapshotPart[] = Array.from(
    { length: partsCount },
    (_, index) => ({
      format: template.format,
      connector: CONNECTOR,
      ns: "",
      generation: 1,
      keyCheck: template.keyCheck,
      position: 4,
      index,
      streams: template.streams,
      entries:
        entries?.[index] ??
        (index === 0
          ? [upsert(10)]
          : index === 1
            ? [
                {
                  kind: "delete",
                  stream: "s0",
                  pkHash: pk,
                  key: ["k"],
                  stamp: { o: 20, r: "r" },
                },
              ]
            : index === 2
              ? [upsert(30)]
              : [extra(index)]),
    }),
  );
  const refs = [];
  for (const part of parts) {
    const bytes = encodeSnapshotPart(part);
    const digest = await digestSnapshotPart(async (b) => keccak_256(b), bytes);
    await w.innerBlobs.put(`${LOG}/${digest.blobName}`, bytes);
    refs.push({ dataHash: digest.dataHash, bytes: bytes.length });
  }
  const head: Segment = {
    ...template,
    position: 5,
    base: 4,
    refs: [],
    snapshot: { position: 4, parts: refs },
    operations: [],
  };
  const encoded = encodeSegment(head);
  const digest = await digestSegment(async (b) => keccak_256(b), encoded);
  await w.innerBlobs.put(`${LOG}/${digest.blobName}`, encoded);
  const b = await w.device("receiver", {
    progressiveFirstLoad: true,
    keyedFirstLoad: false,
    maxBytesInFlight: 1,
  });
  await b.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES(?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
  const existing = await b.deps.registry.read(LOG);
  if (!existing.found) throw new Error("missing template");
  const read = { ...existing, version: 5, dataHash: digest.dataHash };
  const context = {
    connector: CONNECTOR,
    ns: "",
    generation: 1,
    keyCheck: template.keyCheck,
    hashes: await import("@opendatalabs/personal-server-ts-stream-sync").then(
      (m) =>
        m.controlHashes(async (bytes) => keccak_256(bytes), template.keyCheck),
    ),
    read,
  };
  return { w, b, parts, head, context };
}
