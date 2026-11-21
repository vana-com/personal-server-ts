import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openAliasSpool } from "./alias-spool.js";

/**
 * A windowed alias body is written to disk for the length of a response. It is
 * the owner's data in plain text: only the server's own user may read it.
 */
describe("the server's alias spool", () => {
  let storageRoot: string;
  let previousMask: number;
  beforeEach(async () => {
    storageRoot = await mkdtemp(join(tmpdir(), "alias-spool-open-"));
    previousMask = process.umask(0o022);
  });
  afterEach(async () => {
    process.umask(previousMask);
    await rm(storageRoot, { recursive: true, force: true });
  });
  const modeOf = async (path: string) => (await stat(path)).mode & 0o777;

  it("writes a directory only its owner can enter and files only its owner can read", async () => {
    const spool = await openAliasSpool(storageRoot);
    await spool.appendMany([
      { path: "alias-one", bytes: new TextEncoder().encode("body") },
    ]);
    await spool.sync("");
    expect(await modeOf(join(storageRoot, "alias-spool"))).toBe(0o700);
    expect(await modeOf(join(storageRoot, "alias-spool", "alias-one"))).toBe(
      0o600,
    );
  });

  it("tightens a directory an earlier start made with wider modes, and sweeps it", async () => {
    const dir = join(storageRoot, "alias-spool");
    await mkdir(dir, { mode: 0o755 });
    await writeFile(join(dir, "alias-left"), "half a body");
    const spool = await openAliasSpool(storageRoot);
    expect(await spool.list("")).toEqual([]);
    await spool.appendMany([
      { path: "alias-two", bytes: new TextEncoder().encode("body") },
    ]);
    expect(await modeOf(dir)).toBe(0o700);
  });

  it("keeps a file readable by its owner under a umask that would leave it 0000", async () => {
    const spool = await openAliasSpool(storageRoot);
    const file = join(storageRoot, "alias-spool", "alias-masked");
    // `open` applies the umask to the creating mode: with 0777 it is 0000.
    process.umask(0o777);
    try {
      await spool.appendMany([
        { path: "alias-masked", bytes: new TextEncoder().encode("body") },
      ]);
      await spool.sync("");
      expect(await modeOf(file)).toBe(0o600);
      // The server can open it again: a file at 0000 refuses its owner.
      expect(
        new TextDecoder().decode((await spool.read("alias-masked"))!),
      ).toBe("body");
      await spool.write("alias-written", new TextEncoder().encode("body"));
      expect(
        await modeOf(join(storageRoot, "alias-spool", "alias-written")),
      ).toBe(0o600);
    } finally {
      process.umask(0o022);
    }
  });

  it("refuses a root that is a symbolic link, and leaves the files of its target alone", async () => {
    const target = join(storageRoot, "somewhere-else");
    await mkdir(target, { mode: 0o755 });
    await writeFile(join(target, "precious"), "not the spool's");
    await symlink(target, join(storageRoot, "alias-spool"));
    await expect(openAliasSpool(storageRoot)).rejects.toThrow(
      /not a directory/,
    );
    // Neither the sweep nor the tighten followed the link.
    expect(await readFile(join(target, "precious"), "utf8")).toBe(
      "not the spool's",
    );
    expect(await modeOf(target)).toBe(0o755);
  });
});
