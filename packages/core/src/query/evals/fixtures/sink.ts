/**
 * The IO boundary for fixture generation and reading.
 *
 * `packages/core` is imported by `packages/lite` and must stay browser-safe, so
 * nothing here may touch a Node built-in. The generator writes through a
 * `FixtureSink`; the reference implementation reads through a `FixtureSource`.
 * A Node filesystem implementation of both lives outside this package (see the
 * `scripts/` runner) — it is the only piece that needs `node:fs`.
 */

export interface FixtureFile {
  write(chunk: string): Promise<void>;
  close(): Promise<void>;
}

/** Write side: where a generated corpus goes. */
export interface FixtureSink {
  open(fileName: string): Promise<FixtureFile>;
}

/**
 * Read side: where the reference implementation reads a corpus back from.
 *
 * Deliberately byte-oriented. The reference path must re-parse the serialized
 * corpus rather than share the generator's in-memory objects — otherwise the
 * eval only proves that the generator's arithmetic agrees with itself.
 */
export interface FixtureSource {
  list(): Promise<string[]>;
  read(fileName: string): Promise<string>;
  /** Byte length without materializing the file, where the backend can do it cheaply. */
  size(fileName: string): Promise<number>;
}

/**
 * In-memory sink. Used for the `small` profile, which is a few MB and needs no
 * filesystem — that is what keeps `npm run eval` runnable in a browser, in
 * vitest, and in CI without generating 222MB first.
 */
export class MemoryFixtureSink implements FixtureSink, FixtureSource {
  private readonly files = new Map<string, string[]>();

  async open(fileName: string): Promise<FixtureFile> {
    if (this.files.has(fileName)) {
      throw new Error(`fixture file already written: ${fileName}`);
    }
    const chunks: string[] = [];
    this.files.set(fileName, chunks);
    return {
      write: async (chunk: string) => {
        chunks.push(chunk);
      },
      close: async () => {},
    };
  }

  async list(): Promise<string[]> {
    return [...this.files.keys()].sort();
  }

  async read(fileName: string): Promise<string> {
    const chunks = this.files.get(fileName);
    if (!chunks) throw new Error(`no such fixture file: ${fileName}`);
    // Collapse on first read so repeated reads are cheap.
    if (chunks.length > 1) {
      const joined = chunks.join("");
      chunks.length = 0;
      chunks.push(joined);
    }
    return chunks[0] ?? "";
  }

  async size(fileName: string): Promise<number> {
    return (await this.read(fileName)).length;
  }
}

/** Writes an array of records as one JSON array, streamed, without holding them all. */
export async function writeJsonArray<T>(
  sink: FixtureSink,
  fileName: string,
  records: Iterable<T>,
): Promise<number> {
  const file = await sink.open(fileName);
  await file.write("[");
  let n = 0;
  for (const record of records) {
    await file.write((n === 0 ? "" : ",") + JSON.stringify(record));
    n++;
  }
  await file.write("]");
  await file.close();
  return n;
}
