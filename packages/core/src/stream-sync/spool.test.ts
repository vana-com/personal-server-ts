import { describe, expect, it } from "vitest";
import { shardOf } from "@opendatalabs/personal-server-ts-stream-sync";
import { createMemoryStreamSyncFiles } from "./memory-files.js";
import {
  inlineSpoolLine,
  SpoolWriter,
  deriveShards,
  readSpool,
  shardPath,
  spoolLogPath,
} from "./spool.js";

const hashOf = (n: number) => n.toString(16).padStart(64, "0");

/** One spool line for key `n` with body `body`. */
function lineOf(n: number, body: string): string {
  return inlineSpoolLine(
    {
      h: "0".repeat(64),
      k: hashOf(n),
      n: new TextEncoder().encode(body).length,
      o: 0,
      r: "r",
    },
    body,
  );
}

async function lines(
  files: ReturnType<typeof createMemoryStreamSyncFiles>,
  path: string,
) {
  const out: { pkHash: string; text: string }[] = [];
  for await (const entry of readSpool(files, path)) {
    if (entry.body.kind !== "inline") throw new Error("expected inline body");
    out.push({ pkHash: entry.envelope.k, text: entry.body.text });
  }
  return out;
}

describe("deriveShards", () => {
  it("splits the intake log into shards and keeps log order inside each", async () => {
    const files = createMemoryStreamSyncFiles();
    const dir = "runs/r/spool/s0";
    const writer = new SpoolWriter(files);
    const log = spoolLogPath(dir);
    // Two keys, each written three times; log order must survive.
    for (let i = 0; i < 3; i++) {
      await writer.add(log, lineOf(1, `a${i}`));
      await writer.add(log, lineOf(2, `b${i}`));
    }
    await writer.flush();

    await deriveShards(files, dir);

    for (const key of [1, 2]) {
      const shard = await lines(files, shardPath(dir, shardOf(hashOf(key))));
      const own = shard.filter((l) => l.pkHash === hashOf(key));
      expect(own.map((l) => l.text)).toEqual(
        [0, 1, 2].map((i) => `${key === 1 ? "a" : "b"}${i}`),
      );
    }
  });

  it("replaces stale or short shards, so a restart can derive again", async () => {
    const files = createMemoryStreamSyncFiles();
    const dir = "runs/r/spool/s0";
    const writer = new SpoolWriter(files);
    const log = spoolLogPath(dir);
    for (let i = 0; i < 50; i++) await writer.add(log, lineOf(i, `v${i}`));
    await writer.flush();
    await deriveShards(files, dir);
    const first = new Map<string, string>();
    for (const path of await files.list(dir)) {
      first.set(path, new TextDecoder().decode((await files.read(path))!));
    }

    // A crash left one shard short and one extra shard behind.
    const [victim] = [...first.keys()];
    await files.write(victim!, new TextEncoder().encode("garbage\n"));
    await files.write(`${dir}/zz`, new TextEncoder().encode("extra\n"));

    await deriveShards(files, dir);
    const second = new Map<string, string>();
    for (const path of await files.list(dir)) {
      second.set(path, new TextDecoder().decode((await files.read(path))!));
    }
    expect(second).toEqual(first);
  });

  it("writes nothing for an empty log", async () => {
    const files = createMemoryStreamSyncFiles();
    await deriveShards(files, "runs/r/spool/s0");
    expect(await files.list("runs/r/spool/s0")).toEqual([]);
  });
});

describe("SpoolWriter.flush", () => {
  it("fails every later flush once an append has failed", async () => {
    const files = createMemoryStreamSyncFiles();
    let fail = true;
    const failing = {
      ...files,
      async appendMany(entries: Parameters<typeof files.appendMany>[0]) {
        if (fail) throw new Error("disk full");
        return files.appendMany(entries);
      },
    };
    const log = spoolLogPath("runs/r/spool/s0");
    const writer = new SpoolWriter(failing);
    await writer.add(log, lineOf(1, "early"));
    // The second add crosses the flush threshold, so its flush fails and
    // takes the earlier line down with it.
    await expect(
      writer.add(log, lineOf(2, "x".repeat(9 * 1024 * 1024))),
    ).rejects.toThrow("disk full");
    fail = false;
    // The run must not be able to end as if every line were durable.
    await expect(writer.flush()).rejects.toThrow();
  });
});

describe("a log with base-version lines", () => {
  it("reads a base line and a current line from one file, in order, with the base size measure", async () => {
    const files = createMemoryStreamSyncFiles();
    const dir = "runs/r/spool/s0";
    const log = spoolLogPath(dir);
    const base = `{"o":5,"r":"r","v":{"id":"é"}}`;
    await files.appendMany([
      {
        path: log,
        bytes: new TextEncoder().encode(
          `${hashOf(1)} ${base}\n${lineOf(2, `{"id":"b"}`)}\n`,
        ),
      },
    ]);
    const out = [];
    for await (const entry of readSpool(files, log)) out.push(entry);
    expect(out.map((e) => e.envelope.k)).toEqual([hashOf(1), hashOf(2)]);
    expect(out[0]!.body).toEqual({ kind: "inline", text: `{"id":"é"}` });
    expect(out[0]!.envelope).toMatchObject({ o: 5, r: "r", n: 11 });
    expect(out[0]!.size).toBe(new TextEncoder().encode(base).length + 1);
    // Shards derived from the mixed log keep both lines readable.
    await deriveShards(files, dir);
    const shard = await lines(files, shardPath(dir, shardOf(hashOf(1))));
    expect(shard.map((l) => l.text)).toContain(`{"id":"é"}`);
  });
});
