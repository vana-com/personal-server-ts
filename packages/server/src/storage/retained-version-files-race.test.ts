import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createNodeDataStorage } from "./node-data-storage.js";
import { retainLegacyVersions } from "./legacy-publication-fence.js";
import * as hierarchy from "./hierarchy.js";

/**
 * Another process's step, run at an exact point inside one file effect of
 * the owner. Each hook fires once.
 */
type Hook = {
  call: "renameSync" | "linkSync" | "fsyncSync" | "openSync";
  when: "before" | "after";
  /** `from` is the first argument as text: a path, or a file descriptor. */
  match: (from: string, to: string) => boolean;
  run: () => void;
};
const hooks: Hook[] = [];
/** Paths whose `lstatSync` fails with EACCES, as an unreadable path would. */
const unreadable = new Set<string>();
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof fs>();
  const wrap =
    (call: Hook["call"]) =>
    (...args: unknown[]) => {
      const [from, to] = args;
      const fire = (when: Hook["when"]) => {
        const i = hooks.findIndex(
          (hook) =>
            hook.call === call &&
            hook.when === when &&
            hook.match(String(from), String(to)),
        );
        if (i >= 0) hooks.splice(i, 1)[0].run();
      };
      fire("before");
      const result = (actual[call] as (...args: unknown[]) => unknown)(...args);
      fire("after");
      return result;
    };
  const mocked = {
    ...actual,
    renameSync: wrap("renameSync"),
    linkSync: wrap("linkSync"),
    fsyncSync: wrap("fsyncSync"),
    openSync: wrap("openSync"),
    lstatSync: ((path: string, options?: never) => {
      if (unreadable.has(String(path)))
        throw Object.assign(new Error(`EACCES: ${path}`), { code: "EACCES" });
      return actual.lstatSync(path, options);
    }) as typeof actual.lstatSync,
  };
  return { ...mocked, default: mocked };
});

const scope = "spotify.profile";
const cleanups: (() => void)[] = [];
afterEach(() => {
  hooks.splice(0);
  unreadable.clear();
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

async function fixture(withBlocks: boolean) {
  const root = mkdtempSync(join(tmpdir(), "retained-race-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  const db = initializeDatabase(join(root, "index.db"));
  cleanups.push(() => db.open && db.close());
  const index = createIndexManager(db);
  const dataDir = join(root, "data");
  mkdirSync(dataDir);
  const hierarchyOptions = { dataDir };
  const storage = createNodeDataStorage({
    indexManager: index,
    hierarchyOptions,
  });
  await storage.commitVersion!({
    kind: "append",
    envelope: createDataFileEnvelope(scope, "2026-10-24T00:00:00Z", {
      name: "original",
    }),
    metadata: {},
  });
  const entry = index.findLatestByScope(scope)!;
  const stored = await storage.readEnvelope(scope, entry.collectedAt);
  const built = await buildDataBlocksAsync({
    scope,
    collectedAt: entry.collectedAt,
    content: stored,
  });
  if (withBlocks)
    await storage.writeBlockManifest!(
      scope,
      entry.collectedAt,
      built.manifest,
      built.blocks,
    );
  const file = join(dataDir, entry.path);
  const blockDir = join(
    dataDir,
    "blocks",
    "spotify",
    "profile",
    entry.collectedAt,
  );
  const retained = () =>
    db
      .prepare("SELECT version_id FROM legacy_publication_retained_versions")
      .all();
  /** The stop barrier's seal; its failure is returned, not thrown. */
  const seal = (): unknown => {
    try {
      db.transaction(() =>
        retainLegacyVersions(db, hierarchyOptions, { scope }),
      ).immediate();
      return undefined;
    } catch (error) {
      return error;
    }
  };
  const outside = join(root, "outside");
  mkdirSync(outside);
  return {
    dataDir,
    storage,
    entry,
    file,
    bytes: readFileSync(file),
    blockDir,
    built,
    retained,
    seal,
    outside,
  };
}

it("a seal landing between a removal's move-aside and its recheck fails; the removal wins and nothing sealed is lost", async () => {
  const f = await fixture(true);
  let sealError: unknown;
  hooks.push({
    call: "renameSync",
    when: "after",
    match: (from) => from === f.file,
    run: () => (sealError = f.seal()),
  });
  hierarchy.deleteDataFileSync(
    { dataDir: f.dataDir },
    scope,
    f.entry.collectedAt,
  );
  expect(String(sealError)).toContain("file is missing");
  expect(f.retained()).toEqual([]);
  expect(existsSync(f.file)).toBe(false);
});

it("a raw move before the seal starts fails the seal; once back, the seal holds and refuses the removal", async () => {
  const f = await fixture(true);
  const aside = join(f.outside, "aside");
  fs.renameSync(f.file, aside);
  expect(String(f.seal())).toContain("file is missing");
  expect(f.retained()).toEqual([]);
  fs.renameSync(aside, f.file);
  expect(f.seal()).toBeUndefined();
  expect(() =>
    hierarchy.deleteDataFileSync(
      { dataDir: f.dataDir },
      scope,
      f.entry.collectedAt,
    ),
  ).toThrow(expect.objectContaining({ errorCode: "legacy_history_retained" }));
  expect(readFileSync(f.file)).toEqual(f.bytes);
});

it("a mutation landing between a seal's records and its re-read fails the seal before commit", async () => {
  const f = await fixture(true);
  const aside = join(f.outside, "aside");
  hooks.push({
    call: "linkSync",
    when: "after",
    match: (_from, to) => to.endsWith(`${f.entry.path}.retained`),
    // Another process that checked before the record existed moves the file.
    run: () => fs.renameSync(f.file, aside),
  });
  expect(String(f.seal())).toContain("changed while sealing");
  expect(f.retained()).toEqual([]);
  // That process's recheck now finds the record and puts the file back.
  fs.renameSync(aside, f.file);
  expect(readFileSync(f.file)).toEqual(f.bytes);
  // The record stays: the files remain protected, failing closed.
  expect(() =>
    hierarchy.deleteDataFileSync(
      { dataDir: f.dataDir },
      scope,
      f.entry.collectedAt,
    ),
  ).toThrow(expect.objectContaining({ errorCode: "legacy_history_retained" }));
});

it("a seal landing between a sidecar's admission and its publication undoes the publication", async () => {
  const f = await fixture(false);
  let sealError: unknown = "not run";
  hooks.push({
    call: "renameSync",
    when: "before",
    match: (from, to) => to === f.blockDir && from.includes(".tmp."),
    run: () => (sealError = f.seal()),
  });
  await expect(
    hierarchy.writeBlockManifest(
      { dataDir: f.dataDir },
      scope,
      f.entry.collectedAt,
      f.built.manifest,
      f.built.blocks,
    ),
  ).rejects.toMatchObject({ errorCode: "legacy_history_retained" });
  // The seal recorded no sidecar; none appears after it.
  expect(sealError).toBeUndefined();
  expect(f.retained()).toHaveLength(1);
  expect(existsSync(f.blockDir)).toBe(false);
  await expect(
    f.storage.readBlockManifest!(scope, f.entry.collectedAt),
  ).resolves.toBeNull();
});

it("a path-only publisher never consumes a source sealed after its check", async () => {
  const f = await fixture(true);
  const dest = join(f.outside, "dest.json");
  let sealError: unknown = "not run";
  hooks.push({
    call: "linkSync",
    when: "after",
    match: (from, to) => from === f.file && to === dest,
    run: () => (sealError = f.seal()),
  });
  expect(() => hierarchy.publishStagedDataFileSync(f.file, dest)).toThrow(
    expect.objectContaining({ errorCode: "legacy_history_retained" }),
  );
  expect(sealError).toBeUndefined();
  expect(f.retained()).toHaveLength(1);
  expect(readFileSync(f.file)).toEqual(f.bytes);
});

it("an unreadable retention record never reads as unretained", async () => {
  const f = await fixture(true);
  expect(f.seal()).toBeUndefined();
  const records = join(fs.realpathSync(f.dataDir), ".legacy-retained");
  for (const path of [records, join(records, `${f.entry.path}.retained`)]) {
    unreadable.add(path);
    expect(() =>
      hierarchy.deleteDataFileSync(
        { dataDir: f.dataDir },
        scope,
        f.entry.collectedAt,
      ),
    ).toThrow(expect.objectContaining({ code: "EACCES" }));
    unreadable.clear();
    expect(readFileSync(f.file)).toEqual(f.bytes);
  }
});

/** The file a descriptor names, as text; empty if it names nothing. */
function descriptorPath(fd: string): string {
  try {
    return fs.readlinkSync(`/proc/self/fd/${fd}`);
  } catch {
    return "";
  }
}

it("a temp file a seal recorded survives the refusal of its creation, unchanged", async () => {
  const f = await fixture(true);
  // A data directory whose first-seen dir is the sealed sidecar itself.
  const alias = join(f.outside, "alias");
  mkdirSync(alias);
  fs.symlinkSync(f.blockDir, join(alias, "first-seen"));
  const realBlockDir = fs.realpathSync(f.blockDir);
  let staged = "";
  let sealError: unknown = "not run";
  hooks.push({
    call: "fsyncSync",
    when: "after",
    match: (fd) => {
      const path = descriptorPath(fd);
      if (!path.startsWith(`${realBlockDir}/`) || !path.includes(".tmp."))
        return false;
      staged = path;
      return true;
    },
    // Another process seals after the whole temp file is written.
    run: () => (sealError = f.seal()),
  });
  await expect(
    hierarchy.writeFirstSeenLedger({ dataDir: alias }, scope, { seen: 42 }),
  ).rejects.toMatchObject({ errorCode: "legacy_history_retained" });
  expect(sealError).toBeUndefined();
  expect(f.retained()).toHaveLength(1);
  // The seal recorded the temp file by name and bytes; it is still that file.
  const record = JSON.parse(
    readFileSync(
      join(
        fs.realpathSync(f.dataDir),
        ".legacy-retained",
        "blocks",
        "spotify",
        "profile",
        `${f.entry.collectedAt}.retained`,
      ),
      "utf8",
    ),
  ) as { files: Record<string, string> };
  const name = staged.split("/").pop()!;
  expect(record.files[name]).toBeDefined();
  expect(existsSync(staged)).toBe(true);
  expect(createHash("sha256").update(readFileSync(staged)).digest("hex")).toBe(
    record.files[name],
  );
  // The ledger itself was never published, and the version file is unchanged.
  expect(existsSync(join(f.blockDir, `${scope}.json`))).toBe(false);
  expect(readFileSync(f.file)).toEqual(f.bytes);
});

it("a temp file the seal did not record is still removed when its creation is refused", async () => {
  const f = await fixture(true);
  const alias = join(f.outside, "alias");
  mkdirSync(alias);
  fs.symlinkSync(f.blockDir, join(alias, "first-seen"));
  let sealError: unknown = "not run";
  hooks.push({
    call: "openSync",
    when: "before",
    match: (path) =>
      path.startsWith(`${join(alias, "first-seen")}/`) &&
      path.includes(".tmp."),
    // The seal lists the sidecar before the temp file exists.
    run: () => (sealError = f.seal()),
  });
  await expect(
    hierarchy.writeFirstSeenLedger({ dataDir: alias }, scope, { seen: 42 }),
  ).rejects.toMatchObject({ errorCode: "legacy_history_retained" });
  expect(sealError).toBeUndefined();
  expect(readdirSync(f.blockDir).filter((n) => n.includes(".tmp."))).toEqual(
    [],
  );
  expect(readFileSync(f.file)).toEqual(f.bytes);
});

/** A data directory that is a link to the retained sidecar itself. */
function rootAlias(f: Awaited<ReturnType<typeof fixture>>): string {
  const alias = join(f.outside, "root-alias");
  fs.symlinkSync(f.blockDir, alias);
  return alias;
}

it("a streamed stage whose data directory is a sidecar keeps that sidecar unsealed while it is written", async () => {
  const f = await fixture(true);
  const alias = rootAlias(f);
  const stagePath = join(alias, ".scope-imports", "import", "envelope.stage");
  const stage = await hierarchy.createStreamedStage(
    { dataDir: alias },
    stagePath,
  );
  await stage.write(Buffer.from("first"));
  // The sidecar now holds the import directory: it is not flat files.
  expect(String(f.seal())).toContain("more than flat files");
  expect(f.retained()).toEqual([]);
  expect(existsSync(join(fs.realpathSync(f.dataDir), ".legacy-retained"))).toBe(
    false,
  );
  await stage.write(Buffer.from(" second"));
  await stage.sync();
  await stage.close();
  expect(readFileSync(stagePath, "utf8")).toBe("first second");
  expect(readFileSync(f.file)).toEqual(f.bytes);
});

it("a streamed stage is refused inside a sidecar sealed before its directory existed", async () => {
  const f = await fixture(true);
  expect(f.seal()).toBeUndefined();
  const before = readdirSync(f.blockDir).sort();
  const alias = rootAlias(f);
  await expect(
    hierarchy.createStreamedStage(
      { dataDir: alias },
      join(alias, ".scope-imports", "import", "envelope.stage"),
    ),
  ).rejects.toMatchObject({ errorCode: "legacy_history_retained" });
  expect(readdirSync(f.blockDir).sort()).toEqual(before);
});

it("a streamed stage is refused outside a dot directory or behind a link below the data directory", async () => {
  const f = await fixture(true);
  // A scope directory that is a link into the sidecar is not a private place.
  const scopeAlias = join(f.outside, "scope-alias");
  mkdirSync(scopeAlias);
  fs.symlinkSync(f.blockDir, join(scopeAlias, "spotify"));
  await expect(
    hierarchy.createStreamedStage(
      { dataDir: scopeAlias },
      join(scopeAlias, "spotify", "envelope.stage"),
    ),
  ).rejects.toThrow("private file in a dot directory");
  // A dot directory that is itself a link is refused before anything is made.
  const elsewhere = join(f.outside, "elsewhere");
  mkdirSync(elsewhere);
  fs.symlinkSync(elsewhere, join(f.dataDir, ".scope-imports"));
  await expect(
    hierarchy.createStreamedStage(
      { dataDir: f.dataDir },
      join(f.dataDir, ".scope-imports", "import", "envelope.stage"),
    ),
  ).rejects.toThrow("through a link or file");
  expect(readdirSync(elsewhere)).toEqual([]);
  expect(readdirSync(f.blockDir).filter((n) => n.endsWith(".stage"))).toEqual(
    [],
  );
});
