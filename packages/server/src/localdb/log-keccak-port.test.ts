// A reader hashes every byte of every log segment it applies: the registry's
// `dataHash` is a Keccak-256 of the segment's bytes, and that one hash is what
// binds the rows in it. These tests hold three things about that hash: the
// reader takes it from the host's port (the Node host's native Keccak-256 is
// thirty times faster than the pure-JS default), it computes it once per
// segment, and a segment the hash does not match exposes no row.
import { afterEach, describe, expect, it } from "vitest";
import { nobleStreamCrypto } from "../../../core/src/stream-sync/crypto-port.js";
import type { StreamCryptoPort } from "../../../core/src/stream-sync/crypto-port.js";
import { applyConnection } from "../../../core/src/localdb/index.js";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

type World = Awaited<ReturnType<typeof world>>;

const S0 = sName(0);
const SEGMENTS = 6;
const PAD = 3_000;

/** A port that runs noble and writes down the length of every input. */
function recordingPort(digest?: (data: Uint8Array) => Uint8Array) {
  const sizes: number[] = [];
  const port: StreamCryptoPort = {
    ...nobleStreamCrypto,
    keccak256(data) {
      sizes.push(data.length);
      return digest ? digest(data) : nobleStreamCrypto.keccak256(data);
    },
  };
  return { port, sizes };
}

async function publishedLog(w: World) {
  const a = await w.device("a");
  for (let n = 1; n <= SEGMENTS; n++) {
    await a.run(
      `run-${n}`,
      [
        { stream: S0, id: `row-${n}`, pad: PAD },
        { stream: S0, id: "shared", v: n },
      ],
      { full: false, covered: [S0], observedAt: 1000 + n },
    );
    await a.cycle();
  }
}

async function reader(
  w: World,
  id: string,
  hooks: Parameters<World["device"]>[2],
) {
  const d = await w.device(id, true, hooks);
  await d.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, "fixture"],
    },
  ]);
  return d;
}

const segmentLengths = async (w: World) =>
  Promise.all(
    [...(await w.segmentKeys()).values()].map(
      async (key) => (await w.innerBlobs.get(key))!.length,
    ),
  );

describe("the Keccak-256 of a log segment", () => {
  it.each([
    ["segment by segment", false],
    ["key by key", true],
  ])(
    "is taken from the host's port, once per segment, %s",
    async (_name, keyed) => {
      const w = await world({ streams: 1, logProtocol: true });
      await publishedLog(w);
      const lengths = await segmentLengths(w);
      const { port, sizes } = recordingPort();
      const d = await reader(w, "b", {
        streamCrypto: port,
        ...(keyed
          ? { maxBytesInFlight: 2 * Math.max(...lengths) }
          : { keyedFirstLoad: false }),
      });
      const stages: string[] = [];
      const db = d.db as unknown as { batch: typeof d.db.batch };
      const batch = db.batch.bind(db);
      db.batch = async (statements) => {
        for (const s of statements)
          if (/^CREATE (TEMP )?TABLE log_stage_/.test(s.sql))
            stages.push(s.sql);
        return batch(statements);
      };
      await applyConnection(d.deps, CONNECTION_ID);

      expect(stages.length > 0).toBe(keyed);
      expect(await d.position()).toBe(SEGMENTS);
      // Control hashes are a few dozen bytes; every segment is longer than PAD.
      const hashedSegments = sizes
        .filter((n) => n >= PAD)
        .sort((x, y) => x - y);
      expect(hashedSegments).toEqual([...lengths].sort((x, y) => x - y));
    },
  );

  it("refuses a segment whose bytes the port's digest does not match, and exposes no row", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    await publishedLog(w);
    // A port that disagrees with the registry about every segment.
    const { port } = recordingPort((data) =>
      data.length >= PAD
        ? new Uint8Array(32).fill(7)
        : nobleStreamCrypto.keccak256(data),
    );
    const d = await reader(w, "b", { streamCrypto: port });
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow(
      /invalid log segment \d+ \(hash_mismatch\)/,
    );
    expect(await d.records()).toEqual([]);
    expect(await d.position()).toBe(0);
  });

  it("refuses a segment with one flipped byte through the native port's digest too", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    await publishedLog(w);
    const keys = [...(await w.segmentKeys()).values()];
    const victim = keys[2]!;
    const bytes = (await w.innerBlobs.get(victim))!.slice();
    bytes[Math.floor(bytes.length / 2)] ^= 1;
    await w.innerBlobs.put(victim, bytes);
    const { port } = recordingPort();
    const d = await reader(w, "b", { streamCrypto: port });
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow(
      /hash_mismatch/,
    );
    expect(await d.position()).toBeLessThan(SEGMENTS);
  });
});
