/**
 * Node filesystem sink/source for the query-layer eval corpus.
 *
 * This is the only piece of the eval harness that needs a Node built-in, which
 * is why it lives outside `packages/core` — that package is imported by
 * `packages/lite` and must stay browser-safe.
 */

import { createWriteStream } from "node:fs";
import { mkdir, readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { once } from "node:events";
import type {
  FixtureFile,
  FixtureSink,
  FixtureSource,
} from "@opendatalabs/personal-server-ts-core/query/evals";

export class FsFixtureSink implements FixtureSink, FixtureSource {
  constructor(private readonly dir: string) {}

  async init(): Promise<void> {
    await mkdir(this.dir, { recursive: true });
  }

  async open(fileName: string): Promise<FixtureFile> {
    const stream = createWriteStream(join(this.dir, fileName), {
      encoding: "utf8",
    });
    return {
      write: async (chunk: string) => {
        // Respect backpressure — the full profile is ~222MB.
        if (!stream.write(chunk)) await once(stream, "drain");
      },
      close: async () => {
        stream.end();
        await once(stream, "finish");
      },
    };
  }

  async list(): Promise<string[]> {
    return (await readdir(this.dir)).filter((f) => f.endsWith(".json")).sort();
  }

  async read(fileName: string): Promise<string> {
    return readFile(join(this.dir, fileName), "utf8");
  }

  async size(fileName: string): Promise<number> {
    return (await stat(join(this.dir, fileName))).size;
  }
}
