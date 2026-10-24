// Identity and build freshness of one supplied tree. The harness imports each
// tree's compiled dist; nothing else proves that the dist matches the source
// at the tree's commit. This reports what can be checked cheaply:
//
//   commit        git HEAD of the tree
//   dirtyPaths    tracked source files that differ from HEAD (not untracked)
//   buildDigest   sha256 over every compiled .js file the harness can import
//   staleSources  source files newer than their emitted .js (mtime heuristic)
//
// `fresh` is true only when no source file is newer than its output. A clean
// `git status` plus a fresh dist is strong evidence, not proof: the digest lets
// a reader confirm that two runs used the same build.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const PACKAGES = ["core", "server"];

function walk(dir, accept, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir).sort()) {
    if (name === "node_modules") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, accept, out);
    else if (accept(path)) out.push(path);
  }
  return out;
}

const git = (tree, ...args) => {
  try {
    return execFileSync("git", ["-C", tree, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trimEnd();
  } catch {
    return null;
  }
};

export function treeIdentity(tree) {
  const digest = createHash("sha256");
  let distFiles = 0;
  const staleSources = [];
  for (const pkg of PACKAGES) {
    const src = join(tree, "packages", pkg, "src");
    const dist = join(tree, "packages", pkg, "dist");
    for (const file of walk(dist, (path) => path.endsWith(".js"))) {
      distFiles++;
      digest.update(`${relative(tree, file)}\0`);
      digest.update(readFileSync(file));
    }
    for (const file of walk(
      src,
      (path) => path.endsWith(".ts") && !path.endsWith(".test.ts"),
    )) {
      const rel = relative(src, file).replace(/\.ts$/, ".js");
      const out = join(dist, rel);
      // A declaration-only or type-only module emits an empty file or none.
      if (!existsSync(out)) continue;
      if (statSync(file).mtimeMs > statSync(out).mtimeMs + 1000)
        staleSources.push(relative(tree, file));
    }
  }
  const status = git(tree, "status", "--porcelain", "--", "packages");
  return {
    tree,
    commit: git(tree, "rev-parse", "HEAD"),
    dirtyPaths: status
      ? status
          .split("\n")
          .filter((line) => !line.startsWith("??"))
          .map((line) => line.slice(3))
      : [],
    distFiles,
    buildDigest: distFiles ? digest.digest("hex") : null,
    staleSources,
    fresh: distFiles > 0 && staleSources.length === 0,
  };
}
