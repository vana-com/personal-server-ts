#!/usr/bin/env node
/**
 * Writes vectors/v1.json. Byte outputs (HMAC, SHA-256, Keccak-256, canonical
 * text) are computed here with node:crypto and @noble/hashes, independently of
 * the package code. Logic expectations (decide, checkpoint, needsFull,
 * eligible, ...) are written by hand from the design tables, not computed
 * from the package. Run with `--check` to fail when the checked-in file is
 * stale.
 *
 *   node packages/stream-sync/scripts/generate-vectors.mjs [--check]
 */

import { createHash, createHmac, hkdfSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak_256 } from "@noble/hashes/sha3";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "vectors", "v1.json");

// ---------- independent primitives ----------

function cj(v) {
  if (Array.isArray(v)) return `[${v.map(cj).join(",")}]`;
  if (v !== null && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${cj(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}
const sha = (text) => createHash("sha256").update(text, "utf8").digest("hex");
const keccak = (text) =>
  "0x" + Buffer.from(keccak_256(Buffer.from(text, "utf8"))).toString("hex");
const K_NS_HEX =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const hmac8 = (text) =>
  createHmac("sha256", Buffer.from(K_NS_HEX, "hex"))
    .update(text, "utf8")
    .digest("hex")
    .slice(0, 16);
const bits = (hex, n) =>
  [...hex]
    .map((c) => parseInt(c, 16).toString(2).padStart(4, "0"))
    .join("")
    .slice(0, n);
const lineText = (l) => cj({ o: l.o, r: l.r, v: l.v });

// ---------- namespace ----------

const keyCheck = hmac8("key-check");
const hashes = {
  activeData: keccak("pdpp.stream-sync.connection.active.v1:" + keyCheck),
  activeMetadata: keccak("pdpp.stream-sync.connection.active.metadata.v1"),
  tombstoneData: keccak("vana.data-point.tombstone.v1"),
  tombstoneMetadata: keccak("vana.data-point.tombstone.metadata.v1"),
};
const nsCases = [
  ["chatgpt", "user-123"],
  ["chatgpt", "user-124"],
  ["spotify", "user-123"],
  ["github", 'Ünïcödé ✓ "quoted" \\ slash'],
  ["linkedin", "42"],
].map(([connector, accountId]) => {
  const message = cj([connector, accountId]);
  return { connector, accountId, message, ns: hmac8(message) };
});
const NS = nsCases[0].ns;
const NS2 = nsCases[1].ns;

const namespace = {
  description:
    "K_ns is the HMAC key. ns = first 8 bytes of HMAC-SHA256(K_ns, utf8(message)); keyCheck = first 8 bytes of HMAC-SHA256(K_ns, utf8('key-check')). Registry hashes are keccak256 of the UTF-8 labels, 0x + lowercase hex.",
  kNsHex: K_NS_HEX,
  keyCheck,
  controlHashes: hashes,
  cases: nsCases,
};

// ---------- stream master key (ruling R4, U1-Q1) ----------

// Anvil account #0 signs "vana-master-key-v1" (personal_sign). viem gives
// this low-s, v = 27 encoding; the other two are the same signature.
const OWNER_SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d51b";
const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const sigR = OWNER_SIGNATURE.slice(2, 66);
const sigS = BigInt("0x" + OWNER_SIGNATURE.slice(66, 130));
const sigV = parseInt(OWNER_SIGNATURE.slice(130), 16);
const hex32 = (n) => n.toString(16).padStart(64, "0");
const hex1 = (n) => n.toString(16).padStart(2, "0");
const masterKeyHex = OWNER_SIGNATURE.slice(2);
const streamKNs = Buffer.from(
  hkdfSync(
    "sha256",
    Buffer.from(masterKeyHex, "hex"),
    Buffer.from("vana", "utf8"),
    Buffer.from("scope:pdpp-stream-sync/namespace/v1", "utf8"),
    32,
  ),
);
const streamHmac8 = (text) =>
  createHmac("sha256", streamKNs)
    .update(text, "utf8")
    .digest("hex")
    .slice(0, 16);
const streamMasterKey = {
  description:
    "The stream-sync master key is the 65-byte owner signature as r, low s and v = 27/28. Every encoding gives the same key, so the same K_ns = HKDF-SHA256(masterKey, salt 'vana', info 'scope:' + NAMESPACE_KEY_LABEL, 32), ns and keyCheck. Legacy scope keys keep the raw signature.",
  encodings: [
    { name: "v 27/28, low s", signature: OWNER_SIGNATURE },
    {
      name: "v 0/1, low s",
      signature: "0x" + sigR + hex32(sigS) + hex1(sigV - 27),
    },
    {
      name: "v 27/28, high s",
      signature:
        "0x" + sigR + hex32(SECP256K1_N - sigS) + hex1(sigV === 27 ? 28 : 27),
    },
    {
      name: "v 0/1, high s",
      signature:
        "0x" + sigR + hex32(SECP256K1_N - sigS) + hex1(sigV === 27 ? 1 : 0),
    },
  ],
  masterKeyHex,
  kNsHex: streamKNs.toString("hex"),
  keyCheck: streamHmac8("key-check"),
  ns: {
    connector: "chatgpt",
    accountId: "user-123",
    ns: streamHmac8(cj(["chatgpt", "user-123"])),
  },
  invalid: [
    { name: "64 bytes", signature: "0x" + masterKeyHex.slice(0, 128) },
    { name: "66 bytes", signature: "0x" + masterKeyHex + "00" },
    { name: "v = 29", signature: "0x" + sigR + hex32(sigS) + "1d" },
    { name: "v = 2", signature: "0x" + sigR + hex32(sigS) + "02" },
    { name: "s = 0", signature: "0x" + sigR + hex32(0n) + "1b" },
    { name: "s = n", signature: "0x" + sigR + hex32(SECP256K1_N) + "1b" },
    { name: "r = 0", signature: "0x" + hex32(0n) + hex32(sigS) + "1b" },
    { name: "no 0x prefix", signature: masterKeyHex },
  ],
};

// ---------- scopes and blob names ----------

const longStream = "s".repeat(256 - "pdpp.c~.".length);
const scopes = {
  build: [
    {
      connector: "chatgpt",
      ns: NS,
      stream: "conversations",
      scope: `pdpp.chatgpt~${NS}.conversations`,
    },
    { connector: "chatgpt", ns: NS, scope: `pdpp.chatgpt~${NS}` },
    {
      connector: "weather",
      ns: "",
      stream: "daily",
      scope: "pdpp.weather~.daily",
    },
    { connector: "weather", ns: "", scope: "pdpp.weather~" },
    { connector: "c", ns: "", stream: "a.b~c", scope: "pdpp.c~.a.b~c" },
    {
      connector: "c",
      ns: "",
      stream: longStream,
      scope: `pdpp.c~.${longStream}`,
    },
  ],
  buildErrors: [
    { connector: "", ns: "", stream: "s", why: "empty connector" },
    { connector: "a~b", ns: "", stream: "s", why: "connector contains ~" },
    {
      connector: "c",
      ns: "ABCDEF0123456789",
      stream: "s",
      why: "uppercase ns",
    },
    { connector: "c", ns: "0123", stream: "s", why: "short ns" },
    { connector: "c", ns: "", stream: "", why: "empty stream" },
    { connector: "c", ns: "", stream: longStream + "s", why: "257 bytes" },
    {
      connector: "c",
      ns: "",
      stream: "é".repeat(125),
      why: "over 256 UTF-8 bytes, under 256 code units",
    },
  ],
  parse: [
    {
      name: `pdpp.chatgpt~${NS}.conversations`,
      parsed: {
        kind: "stream",
        connector: "chatgpt",
        ns: NS,
        stream: "conversations",
      },
    },
    {
      name: `pdpp.chatgpt~${NS}`,
      parsed: { kind: "control", connector: "chatgpt", ns: NS },
    },
    {
      name: "pdpp.weather~.daily",
      parsed: { kind: "stream", connector: "weather", ns: "", stream: "daily" },
    },
    {
      name: "pdpp.weather~",
      parsed: { kind: "control", connector: "weather", ns: "" },
    },
    {
      name: "pdpp.c~.a.b~c",
      parsed: { kind: "stream", connector: "c", ns: "", stream: "a.b~c" },
    },
    {
      name: `pdpp.c~${NS}.x.y`,
      parsed: { kind: "stream", connector: "c", ns: NS, stream: "x.y" },
    },
    {
      name: "pdpp.a.b~",
      parsed: { kind: "control", connector: "a.b", ns: "" },
    },
    {
      name: `pdpp.c~.${longStream}`,
      parsed: { kind: "stream", connector: "c", ns: "", stream: longStream },
    },
    {
      name: "pdpp.chatgpt.conversations",
      parsed: null,
      why: "old raw name: no ~",
    },
    { name: "pdpp.chatgpt", parsed: null, why: "no ~" },
    { name: "pdpp.~0123456789abcdef.s", parsed: null, why: "empty connector" },
    { name: "other.c~.s", parsed: null, why: "not pdpp." },
    { name: "pdpp.c~0123456789ABCDEF.s", parsed: null, why: "uppercase ns" },
    { name: "pdpp.c~0123456789abcde.s", parsed: null, why: "15 hex ns" },
    { name: "pdpp.c~0123456789abcdef0.s", parsed: null, why: "17 hex ns" },
    { name: "pdpp.c~0123456789abcdef.", parsed: null, why: "empty stream" },
    { name: "pdpp.c~.", parsed: null, why: "empty stream, empty ns" },
    { name: "pdpp.c~xyz", parsed: null, why: "ns not hex and no ." },
    { name: `pdpp.c~.${longStream}s`, parsed: null, why: "257 bytes" },
  ],
  blobs: [
    {
      kind: "head",
      hash: keccak("x").slice(2),
      name: `h-${keccak("x").slice(2)}`,
    },
    { kind: "part", generation: 1, hash: sha("x"), name: `g1-p-${sha("x")}` },
    { kind: "part", generation: 12, hash: sha("y"), name: `g12-p-${sha("y")}` },
  ],
  blobParse: [
    {
      name: `h-${keccak("x").slice(2)}`,
      parsed: { kind: "head", keccak: keccak("x").slice(2) },
    },
    {
      name: `g3-p-${sha("x")}`,
      parsed: { kind: "part", generation: 3, sha256: sha("x") },
    },
    { name: `g0-p-${sha("x")}`, parsed: null, why: "generation 0" },
    { name: `g01-p-${sha("x")}`, parsed: null, why: "leading zero" },
    {
      name: `h-${keccak("x").slice(2).toUpperCase()}`,
      parsed: null,
      why: "uppercase",
    },
    { name: `p-${sha("x")}`, parsed: null, why: "no generation" },
    {
      name: `h-0x${keccak("x").slice(2)}`,
      parsed: null,
      why: "0x in blob name",
    },
  ],
};

// ---------- pkHash and lines ----------

const pkCases = [
  { primaryKey: ["id"], record: { id: "a", body: 1 } },
  { primaryKey: ["id"], record: { id: 7 } },
  { primaryKey: ["id"], record: { id: null } },
  { primaryKey: ["a", "b"], record: { b: 2, a: "x", c: true } },
  { primaryKey: ["id"], record: { id: { z: 1, a: [1, "é"] } } },
].map((c) => {
  const keyJson = cj(c.primaryKey.map((f) => c.record[f]));
  const pkHash = sha(keyJson);
  return {
    ...c,
    keyJson,
    pkHash,
    shard: parseInt(pkHash.slice(0, 2), 16),
    bits16: bits(pkHash, 16),
  };
});

const lines = {
  encode: [
    { line: { o: 1700000000000, r: "run-1", v: { id: "a", n: 1 } } },
    { line: { o: 0, r: "seed", v: { z: 1, a: { y: [2, 1], b: null } } } },
    { line: { o: 5, r: "r", v: { s: 'é\u0000\n"' } } },
  ].map((c) => ({ ...c, text: lineText(c.line) })),
  decodeErrors: [
    { text: '{"r":"x","o":1,"v":{}}', why: "keys not sorted (not canonical)" },
    { text: '{"o":1,"r":"x","v":{}} ', why: "trailing space" },
    { text: '{"o":-1,"r":"x","v":{}}', why: "negative o" },
    { text: '{"o":1.5,"r":"x","v":{}}', why: "fractional o" },
    { text: '{"o":1,"r":"","v":{}}', why: "empty r" },
    { text: '{"o":1,"r":"x","v":[]}', why: "v not an object" },
    { text: '{"o":1,"r":"x","v":{},"w":1}', why: "extra field" },
    { text: '{"o":1,"r":"x"}', why: "missing v" },
    { text: "not json", why: "not JSON" },
  ],
};

// ---------- frames (format 2) ----------

const shaBytes = (text) => sha(text);
const frameCase = (name, primaryKey, record, o, r) => {
  const body = cj(record);
  const k = sha(cj(primaryKey.map((f) => record[f])));
  const envelope = cj({
    h: shaBytes(body),
    k,
    n: Buffer.byteLength(body),
    o,
    r,
  });
  return {
    name,
    primaryKey,
    record,
    o,
    r,
    bodyBytes: Buffer.byteLength(body),
    envelope,
    frame: `${envelope}\n${body}\n`,
  };
};
const frameCases = [
  frameCase("small", ["id"], { id: "a", body: 1 }, 1700000000000, "run-1"),
  frameCase("unicode", ["id"], { id: "é", t: "日本語" }, 5, "r"),
  frameCase("composite key", ["a", "b"], { b: 2, a: "x", c: true }, 0, "run-2"),
].sort((x, y) =>
  JSON.parse(x.envelope).k < JSON.parse(y.envelope).k ? -1 : 1,
);
const longCount = 1024 * 1024 + 5;
const longBody = cj({ id: "big", x: "a".repeat(longCount) });
const longK = sha(cj(["big"]));
const frames = {
  description:
    "Format 2 frame = envelope LF body LF. Envelope = canonical JSON {h: sha256(body) hex, k: pkHash, n: body bytes, o, r}; body = canonical JSON of the record. A part is frames sorted strictly by k (or the pieces of one long frame). No record size limit.",
  cases: frameCases,
  part: (() => {
    const text = frameCases.map((c) => c.frame).join("");
    return {
      prefix: "",
      frames: frameCases.map((c) => c.name),
      text,
      bytes: Buffer.byteLength(text),
      count: frameCases.length,
      hash: sha(text),
    };
  })(),
  long: {
    description:
      'Record {"id":"big","x":<count x "a">} as a frame; only digests are listed.',
    primaryKey: ["id"],
    count: longCount,
    o: 9,
    r: "run-long",
    bodyBytes: Buffer.byteLength(longBody),
    bodyHash: sha(longBody),
    k: longK,
    envelope: cj({
      h: sha(longBody),
      k: longK,
      n: Buffer.byteLength(longBody),
      o: 9,
      r: "run-long",
    }),
  },
  envelopeErrors: [
    { text: '{"h":"x","k":"y","n":1,"o":1,"r":"r"}', why: "hash not hex64" },
    {
      text: `{"h":"${"0".repeat(64)}","k":"${"0".repeat(64)}","n":-1,"o":1,"r":"r"}`,
      why: "negative n",
    },
    {
      text: `{"k":"${"0".repeat(64)}","h":"${"0".repeat(64)}","n":1,"o":1,"r":"r"}`,
      why: "not canonical order",
    },
    {
      text: `{"h":"${"0".repeat(64)}","k":"${"0".repeat(64)}","n":1,"o":1,"r":""}`,
      why: "empty r",
    },
    {
      text: `{"h":"${"0".repeat(64)}","k":"${"0".repeat(64)}","n":1,"o":1,"r":"r","z":1}`,
      why: "extra field",
    },
    { text: "not json", why: "not JSON" },
  ],
};

// ---------- merge ----------

function mergeCase(name, primaryKey, feed, prefix = "", limitBytes) {
  const best = new Map();
  for (const l of feed) {
    const k = sha(cj(primaryKey.map((f) => l.v[f])));
    const cur = best.get(k);
    if (!cur || l.o > cur.o || (l.o === cur.o && l.r >= cur.r)) best.set(k, l);
  }
  const keys = [...best.keys()].sort();
  const winners = keys.map((k) => ({ pkHash: k, text: lineText(best.get(k)) }));
  const partText = winners.map((w) => w.text + "\n").join("");
  const bytes = Buffer.byteLength(partText, "utf8");
  if (limitBytes !== undefined && bytes > limitBytes) {
    // Ruling Q4: over the limit, split below the 16-bit cap; too large at it.
    return {
      name,
      primaryKey,
      prefix,
      limitBytes,
      feed,
      expected: {
        kind: prefix.length < 16 ? "split" : "bucket_too_large",
        prefix,
        bytes,
      },
    };
  }
  return {
    name,
    primaryKey,
    prefix,
    ...(limitBytes === undefined ? {} : { limitBytes }),
    feed,
    expected: {
      winners,
      bytes: Buffer.byteLength(partText, "utf8"),
      partText,
      sha256: winners.length ? sha(partText) : null,
    },
  };
}
const manyVersions = [];
for (let i = 0; i < 40; i += 1) {
  const o = (i * 7919) % 41; // a permutation of 0..40 without 40's peak first
  manyVersions.push({ o: 1000 + o, r: `run-${o}`, v: { id: "k", value: o } });
}
const merge = [
  mergeCase(
    "newer o wins over older",
    ["id"],
    [
      { o: 10, r: "a", v: { id: 1, x: "old" } },
      { o: 20, r: "a", v: { id: 1, x: "new" } },
    ],
  ),
  mergeCase(
    "older line fed later loses",
    ["id"],
    [
      { o: 20, r: "a", v: { id: 1, x: "new" } },
      { o: 10, r: "z", v: { id: 1, x: "old" } },
    ],
  ),
  mergeCase(
    "equal o: greater r wins",
    ["id"],
    [
      { o: 10, r: "run-b", v: { id: 1, x: "b" } },
      { o: 10, r: "run-a", v: { id: 1, x: "a" } },
    ],
  ),
  mergeCase(
    "equal (o, r): later line wins",
    ["id"],
    [
      { o: 10, r: "run-a", v: { id: 1, x: "first" } },
      { o: 10, r: "run-a", v: { id: 1, x: "second" } },
    ],
  ),
  mergeCase(
    "seed line (o = 0) loses to any run line",
    ["id"],
    [
      { o: 0, r: "seed", v: { id: 1, x: "seed" } },
      { o: 1, r: "a", v: { id: 1, x: "run" } },
      { o: 0, r: "seed", v: { id: 2, x: "seed only" } },
    ],
  ),
  mergeCase("many versions of one key: greatest (o, r)", ["id"], manyVersions),
  mergeCase(
    "distinct keys kept, sorted by pkHash",
    ["a", "b"],
    [
      { o: 1, r: "r", v: { a: 1, b: 1 } },
      { o: 1, r: "r", v: { a: 1, b: 2 } },
      { o: 1, r: "r", v: { a: 2, b: 1 } },
      { o: 2, r: "r", v: { a: 1, b: 2, extra: true } },
    ],
  ),
  mergeCase("empty feed: no part", ["id"], []),
  mergeCase(
    "over the limit below the cap: split (Q4)",
    ["id"],
    [
      { o: 1, r: "r", v: { id: 1, pad: "x".repeat(200) } },
      { o: 1, r: "r", v: { id: 2, pad: "y".repeat(200) } },
    ],
    "",
    300,
  ),
  mergeCase(
    "over the limit at the 16-bit cap: bucket_too_large (Q4)",
    ["id"],
    [{ o: 1, r: "r", v: { id: 1, pad: "x".repeat(200) } }],
    bits(sha(cj([1])), 16),
    100,
  ),
  mergeCase(
    "at the limit exactly: ok",
    ["id"],
    [{ o: 1, r: "r", v: { id: 1 } }],
    "",
    Buffer.byteLength(lineText({ o: 1, r: "r", v: { id: 1 } }) + "\n"),
  ),
];

// ---------- planner (expectations derived by hand in the comments) ----------

const zeros = () => new Array(256).fill(0);
const T4 = 4 * 1024 * 1024;
const uniform = zeros().fill(1000);
const skewed = zeros();
skewed[0] = 10_000_000;
const skewedCounts = zeros();
skewedCounts[0] = 6_000_000;
skewedCounts[1] = 4_000_000;
const twoShards = zeros();
twoShards[0] = 5_000_000;
twoShards[255] = 5_000_000;
const runShard0 = zeros();
runShard0[0] = 2_000_000;
const planner = [
  {
    name: "empty stream: no buckets",
    input: { targetBytes: T4, baseParts: [], shardBytes: zeros() },
    expected: { kind: "plan", buckets: [] },
  },
  {
    name: "small stream: one root bucket",
    input: { targetBytes: T4, baseParts: [], shardBytes: uniform },
    expected: {
      kind: "plan",
      buckets: [{ prefix: "", estimate: 256000, capped: false }],
    },
  },
  {
    // 256000 > 64000 → split; halves 128000 > 64000 → split; quarters 64000 ≤ 64000.
    name: "uniform: split to 2 bits",
    input: { targetBytes: 64000, baseParts: [], shardBytes: uniform },
    expected: {
      kind: "plan",
      buckets: ["00", "01", "10", "11"].map((prefix) => ({
        prefix,
        estimate: 64000,
        capped: false,
      })),
    },
  },
  {
    // shard 0 alone is 10 MB: split down to 8 bits, then a counting pass for shard 0.
    name: "skewed: needs a counting pass for shard 0",
    input: { targetBytes: T4, baseParts: [], shardBytes: skewed },
    expected: { kind: "needs_counts", shards: [0] },
  },
  {
    // With counts: 6 MB at 0x0000 and 4 MB at 0x0001. Splits reach 16 bits:
    // 0x0000 is still 6 MB > 4 MiB, capped; 0x0001 is 4 MB ≤ 4 MiB.
    name: "skewed with counts: split to the 16-bit cap",
    input: {
      targetBytes: T4,
      baseParts: [],
      shardBytes: skewed,
      prefix16Bytes: { 0: skewedCounts },
    },
    expected: {
      kind: "plan",
      buckets: [
        { prefix: "0000000000000000", estimate: 6_000_000, capped: true },
        { prefix: "0000000000000001", estimate: 4_000_000, capped: false },
      ],
    },
  },
  {
    name: "two hot shards: one counting pass each",
    input: { targetBytes: T4, baseParts: [], shardBytes: twoShards },
    expected: { kind: "needs_counts", shards: [0, 255] },
  },
  {
    // Root 3M+1M+2M = 6M > T: split. "0": 3M + 2M = 5M > T: split.
    // "00": 3M/2 + 2M = 3.5M; "01": 1.5M; "1": 1M.
    name: "coarse base parts count in proportion",
    question: "Q3",
    input: {
      targetBytes: T4,
      baseParts: [
        { prefix: "0", bytes: 3_000_000 },
        { prefix: "1", bytes: 1_000_000 },
      ],
      shardBytes: runShard0,
    },
    expected: {
      kind: "plan",
      buckets: [
        { prefix: "00", estimate: 3_500_000, capped: false },
        { prefix: "01", estimate: 1_500_000, capped: false },
        { prefix: "1", estimate: 1_000_000, capped: false },
      ],
    },
  },
  {
    name: "fine base parts sum into a coarse bucket",
    input: {
      targetBytes: T4,
      baseParts: [
        { prefix: "00", bytes: 100 },
        { prefix: "01", bytes: 200 },
      ],
      shardBytes: zeros(),
    },
    expected: {
      kind: "plan",
      buckets: [{ prefix: "", estimate: 300, capped: false }],
    },
  },
  {
    name: "counting pass that does not sum to its shard is rejected",
    input: {
      targetBytes: T4,
      baseParts: [],
      shardBytes: skewed,
      prefix16Bytes: { 0: zeros() },
    },
    expected: { kind: "error" },
  },
];

// ---------- heads ----------

const partA = "x\n";
const baseHead = {
  complete: true,
  connector: "chatgpt",
  format: 1,
  generation: "3",
  keyCheck,
  ns: NS,
  observedAt: 1700000000000,
  parts: [
    { bytes: 120, count: 2, hash: sha("p0"), prefix: "0" },
    { bytes: 64, count: 1, hash: sha("p1"), prefix: "10" },
  ],
  primaryKey: ["id"],
  profile: { key: "conversations", version: "1.4.0" },
  recordCount: 3,
  stream: "conversations",
};
const emptyHead = {
  ...baseHead,
  complete: false,
  connector: "weather",
  generation: "1",
  ns: "",
  parts: [],
  profile: { key: null, version: "0.1.0" },
  recordCount: 0,
  stream: "daily",
};
void partA;
const headEncode = [
  { name: "two parts", head: baseHead },
  { name: "identity-less, no records", head: emptyHead },
].map((c) => {
  const text = cj(c.head);
  return {
    ...c,
    text,
    dataHash: keccak(text),
    blobName: `h-${keccak(text).slice(2)}`,
  };
});
const mutate = (patch) => cj({ ...baseHead, ...patch });
const headDecode = [
  { name: "valid", text: cj(baseHead), expected: "ok" },
  {
    name: "format 3",
    text: mutate({ format: 3 }),
    expected: "unsupported_format",
  },
  {
    name: "format missing",
    text: cj(
      Object.fromEntries(
        Object.entries(baseHead).filter(([k]) => k !== "format"),
      ),
    ),
    expected: "unsupported_format",
  },
  {
    name: 'format "1" string',
    text: mutate({ format: "1" }),
    expected: "unsupported_format",
  },
  {
    name: "not canonical (spaces)",
    text: JSON.stringify(baseHead, null, 1),
    expected: "malformed",
  },
  { name: "extra field", text: mutate({ extra: 1 }), expected: "malformed" },
  {
    name: "generation as number",
    text: mutate({ generation: 3 }),
    expected: "malformed",
  },
  {
    name: "generation 0",
    text: mutate({ generation: "0" }),
    expected: "malformed",
  },
  {
    name: "generation leading zero",
    text: mutate({ generation: "03" }),
    expected: "malformed",
  },
  {
    name: "recordCount mismatch",
    text: mutate({ recordCount: 4 }),
    expected: "malformed",
  },
  {
    name: "parts not sorted",
    text: mutate({ parts: [...baseHead.parts].reverse() }),
    expected: "malformed",
  },
  {
    name: "parts not prefix-free",
    text: mutate({
      parts: [{ ...baseHead.parts[0], prefix: "1" }, baseHead.parts[1]],
    }),
    expected: "malformed",
  },
  {
    name: "empty part entry",
    text: mutate({
      parts: [{ ...baseHead.parts[0], count: 0 }],
      recordCount: 0,
    }),
    expected: "malformed",
  },
  {
    name: "prefix over 16 bits",
    text: mutate({
      parts: [{ ...baseHead.parts[0], prefix: "0".repeat(17) }],
      recordCount: 2,
    }),
    expected: "malformed",
  },
  {
    name: "part over 16 MiB",
    text: mutate({
      parts: [{ ...baseHead.parts[0], bytes: 16 * 1024 * 1024 + 1 }],
      recordCount: 2,
    }),
    expected: "malformed",
  },
  {
    name: "bad keyCheck",
    text: mutate({ keyCheck: "XYZ" }),
    expected: "malformed",
  },
  {
    name: "profile missing version",
    text: mutate({ profile: { key: null } }),
    expected: "malformed",
  },
  {
    name: "connector with ~",
    text: mutate({ connector: "a~b" }),
    expected: "malformed",
  },
  { name: "not JSON", text: "{", expected: "malformed" },
];
const otherKeyCheck = "ffffffffffffffff";
const goodText = cj(baseHead);
const verifyExpect = {
  dataHash: keccak(goodText),
  connector: "chatgpt",
  ns: NS,
  stream: "conversations",
  keyCheck,
};
const headVerify = [
  { name: "ok", text: goodText, expect: verifyExpect, result: "ok" },
  {
    name: "hash mismatch",
    text: goodText,
    expect: { ...verifyExpect, dataHash: keccak("other") },
    result: "hash_mismatch",
  },
  {
    name: "stream mismatch",
    text: goodText,
    expect: { ...verifyExpect, stream: "messages" },
    result: "name_mismatch",
  },
  {
    name: "ns mismatch",
    text: goodText,
    expect: { ...verifyExpect, ns: NS2 },
    result: "name_mismatch",
  },
  {
    name: "key mismatch",
    text: goodText,
    expect: { ...verifyExpect, keyCheck: otherKeyCheck },
    result: "key_mismatch",
  },
  {
    name: "unsupported format is reported before name and key",
    text: mutate({ format: 3 }),
    expect: {
      ...verifyExpect,
      dataHash: keccak(mutate({ format: 3 })),
      keyCheck: otherKeyCheck,
    },
    result: "unsupported_format",
  },
];

// ---------- head rules ----------

const A = (g) => ({ kind: "active", generation: g });
const D = (v) => ({ kind: "deleted", version: v });
const F = (v) => ({ kind: "foreign", version: v });
const ABSENT = { kind: "absent" };
const UNKNOWN = { kind: "unknown" };

const headRules = {
  liveness: [
    { control: A(3), streamRow: "present", headGeneration: 3, live: true },
    { control: A(3), streamRow: "present", headGeneration: 1, live: false },
    { control: A(3), streamRow: "tombstoned", headGeneration: 3, live: false },
    { control: A(3), streamRow: "absent", headGeneration: null, live: false },
    { control: D(4), streamRow: "present", headGeneration: 3, live: false },
    { control: F(3), streamRow: "present", headGeneration: 3, live: false },
    { control: ABSENT, streamRow: "present", headGeneration: 1, live: false },
  ],
  // Ruling F1: three outcomes.
  chooseBase: [
    { streamRow: "present", headGeneration: 3, target: 3, base: "base" },
    { streamRow: "present", headGeneration: 1, target: 3, base: "empty" },
    {
      streamRow: "present",
      headGeneration: 3,
      target: 1,
      base: "stale_generation",
    },
    {
      streamRow: "present",
      headGeneration: 4,
      target: 3,
      base: "stale_generation",
    },
    { streamRow: "tombstoned", headGeneration: 3, target: 3, base: "empty" },
    { streamRow: "tombstoned", headGeneration: 5, target: 3, base: "empty" },
    { streamRow: "absent", headGeneration: null, target: 1, base: "empty" },
  ],
  writerCompatibility: [
    {
      basePrimaryKey: null,
      writerPrimaryKey: ["id"],
      writerVersusBase: "lower",
      result: "use_base",
    },
    {
      basePrimaryKey: ["id"],
      writerPrimaryKey: ["id"],
      writerVersusBase: "lower",
      result: "use_base",
    },
    {
      basePrimaryKey: ["id"],
      writerPrimaryKey: ["id"],
      writerVersusBase: "higher",
      result: "use_base",
    },
    {
      basePrimaryKey: ["id"],
      writerPrimaryKey: ["id", "ts"],
      writerVersusBase: "higher",
      result: "empty_base",
    },
    {
      basePrimaryKey: ["id", "ts"],
      writerPrimaryKey: ["id"],
      writerVersusBase: "lower",
      result: "connector_update_required",
    },
    {
      basePrimaryKey: ["a", "b"],
      writerPrimaryKey: ["b", "a"],
      writerVersusBase: "equal",
      result: "connector_update_required",
      question: "Q5",
    },
  ],
  complete: [
    { full: true, baseComplete: false, seedMerged: false, complete: true },
    { full: false, baseComplete: true, seedMerged: false, complete: true },
    { full: false, baseComplete: false, seedMerged: true, complete: true },
    { full: false, baseComplete: false, seedMerged: false, complete: false },
  ],
  noop: [
    {
      name: "same parts and complete",
      base: "baseHead",
      parts: baseHead.parts,
      complete: true,
      noop: true,
    },
    {
      name: "complete changed",
      base: "baseHead",
      parts: baseHead.parts,
      complete: false,
      noop: false,
    },
    {
      name: "a part changed",
      base: "baseHead",
      parts: [baseHead.parts[0], { ...baseHead.parts[1], hash: sha("p2") }],
      complete: true,
      noop: false,
    },
    {
      name: "a part added",
      base: "baseHead",
      parts: [
        ...baseHead.parts,
        { bytes: 1, count: 1, hash: sha("p3"), prefix: "11" },
      ],
      complete: true,
      noop: false,
    },
    { name: "no base", base: null, parts: [], complete: false, noop: false },
  ],
};

// ---------- control ----------

const control = [
  { name: "no row", read: { found: false }, expected: ABSENT },
  {
    name: "own active",
    read: {
      found: true,
      version: 1,
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
      deleted: false,
    },
    expected: A(1),
  },
  {
    name: "own active, uppercase hex",
    read: {
      found: true,
      version: 5,
      dataHash: "0x" + hashes.activeData.slice(2).toUpperCase(),
      metadataHash: hashes.activeMetadata,
      deleted: false,
    },
    expected: A(5),
  },
  {
    name: "tombstone",
    read: {
      found: true,
      version: 2,
      dataHash: hashes.tombstoneData,
      metadataHash: hashes.tombstoneMetadata,
      deleted: true,
    },
    expected: D(2),
  },
  {
    name: "tombstone hashes, deleted flag not yet set",
    read: {
      found: true,
      version: 2,
      dataHash: hashes.tombstoneData,
      metadataHash: hashes.tombstoneMetadata,
      deleted: false,
    },
    expected: D(2),
  },
  {
    name: "another key's active row",
    read: {
      found: true,
      version: 3,
      dataHash: keccak(
        "pdpp.stream-sync.connection.active.v1:" + otherKeyCheck,
      ),
      metadataHash: hashes.activeMetadata,
      deleted: false,
    },
    expected: F(3),
  },
];

// ---------- decide (one case per table cell; hand-written from §2.4) ----------

const DISCARD = {
  kind: "discard",
  recollect: false,
  clearCheckpoints: false,
  restartFull: false,
};
const row = (rowLabel, start, current, flags, expected, extra = {}) => ({
  row: rowLabel,
  start,
  current,
  userConnect: flags.uc ?? false,
  full: flags.full ?? false,
  phase: flags.phase ?? "first",
  expected,
  ...extra,
});
const decide = [
  row(
    "unknown | any → discard, recollect",
    UNKNOWN,
    ABSENT,
    {},
    { ...DISCARD, recollect: true },
  ),
  row(
    "unknown | any → discard, recollect",
    UNKNOWN,
    A(1),
    { uc: true, full: true },
    { ...DISCARD, recollect: true },
  ),
  row(
    "unknown | any → discard, recollect",
    UNKNOWN,
    D(2),
    { uc: true, full: true },
    { ...DISCARD, recollect: true },
  ),
  row(
    "absent | absent → create v1",
    ABSENT,
    ABSENT,
    {},
    { kind: "create", target: 1 },
  ),
  row(
    "absent | active(1) → T = 1",
    ABSENT,
    A(1),
    {},
    { kind: "publish", target: 1 },
  ),
  row("absent | other → discard", ABSENT, A(2), {}, DISCARD),
  row(
    "absent | other → discard",
    ABSENT,
    D(2),
    { uc: true, full: true },
    DISCARD,
  ),
  row(
    "active(g0) | active(g0) → T = g0",
    A(3),
    A(3),
    {},
    { kind: "publish", target: 3 },
  ),
  row(
    "active(g0) | absent → re-read once",
    A(3),
    ABSENT,
    {},
    { kind: "reread" },
  ),
  row(
    "active(g0) | absent, still so → keep pending, registry_inconsistent",
    A(3),
    ABSENT,
    { phase: "reread" },
    { kind: "keep_pending", reason: "registry_inconsistent" },
  ),
  row(
    "active(g0) | active(g < g0) → re-read once",
    A(3),
    A(1),
    {},
    { kind: "reread" },
  ),
  row(
    "active(g0) | active(g < g0), still so → keep pending, registry_inconsistent",
    A(3),
    A(1),
    { phase: "reread" },
    { kind: "keep_pending", reason: "registry_inconsistent" },
  ),
  row(
    "active(g0) | other → discard, clear checkpoints",
    A(3),
    D(4),
    {},
    { ...DISCARD, clearCheckpoints: true },
  ),
  row(
    "active(g0) | other → discard, clear checkpoints",
    A(1),
    A(5),
    { uc: true, full: true },
    { ...DISCARD, clearCheckpoints: true },
  ),
  row(
    "deleted(v0) | deleted(v0), userConnect and full → reconnect v0+1",
    D(2),
    D(2),
    { uc: true, full: true },
    { kind: "reconnect", target: 3 },
  ),
  row(
    "deleted(v0) | active(v0+1), userConnect and full → T = v0+1",
    D(2),
    A(3),
    { uc: true, full: true },
    { kind: "publish", target: 3 },
  ),
  row(
    "deleted(v0) | not userConnect → discard",
    D(2),
    D(2),
    { full: true },
    DISCARD,
  ),
  row(
    "deleted(v0) | not userConnect → discard",
    D(2),
    A(3),
    { full: true },
    DISCARD,
  ),
  row(
    "deleted(v0) | not full → discard, host restarts a full run",
    D(2),
    D(2),
    { uc: true },
    { ...DISCARD, restartFull: true },
  ),
  row(
    "deleted(v0) | not full → discard, host restarts a full run",
    D(2),
    A(3),
    { uc: true },
    { ...DISCARD, restartFull: true },
  ),
  row(
    "deleted(v0) | other → discard",
    D(2),
    D(4),
    { uc: true, full: true },
    DISCARD,
  ),
  row(
    "deleted(v0) | other → discard",
    D(2),
    A(5),
    { uc: true, full: true },
    DISCARD,
  ),
  row("deleted(v0) | other → discard", D(2), D(4), { uc: true }, DISCARD),
  row(
    "any | foreign → keep pending, key_mismatch",
    ABSENT,
    F(1),
    {},
    { kind: "keep_pending", reason: "key_mismatch" },
  ),
  row(
    "any | foreign → keep pending, key_mismatch",
    A(3),
    F(5),
    {},
    { kind: "keep_pending", reason: "key_mismatch" },
  ),
  row(
    "any | foreign → keep pending, key_mismatch",
    D(2),
    F(3),
    { uc: true, full: true },
    { kind: "keep_pending", reason: "key_mismatch" },
  ),
  row(
    "any | foreign → keep pending, key_mismatch (S unknown)",
    UNKNOWN,
    F(1),
    {},
    { kind: "keep_pending", reason: "key_mismatch" },
    { question: "Q1" },
  ),
  row(
    "S foreign: no table row → discard",
    F(1),
    A(3),
    { uc: true, full: true },
    DISCARD,
    { question: "Q2" },
  ),
  row(
    "after create: C re-reads active(T) → publish",
    ABSENT,
    A(1),
    { phase: "after_write" },
    { kind: "publish", target: 1 },
  ),
  row(
    "after create: C still absent → discard",
    ABSENT,
    ABSENT,
    { phase: "after_write" },
    DISCARD,
  ),
  row(
    "after create replayed, C deleted → discard (trace A)",
    ABSENT,
    D(2),
    { phase: "after_write" },
    DISCARD,
  ),
  row(
    "after create: C foreign → discard",
    ABSENT,
    F(1),
    { phase: "after_write" },
    DISCARD,
    { question: "Q8" },
  ),
  row(
    "after reconnect: C re-reads active(T) → publish",
    D(2),
    A(3),
    { uc: true, full: true, phase: "after_write" },
    { kind: "publish", target: 3 },
  ),
  row(
    "after reconnect: C deleted again → discard",
    D(2),
    D(4),
    { uc: true, full: true, phase: "after_write" },
    DISCARD,
  ),
  row(
    "after reconnect: C still deleted(v0) → discard",
    D(2),
    D(2),
    { uc: true, full: true, phase: "after_write" },
    DISCARD,
  ),
  // Ruling F1: re-read after chooseBase returned stale_generation.
  row(
    "stale base: start older than control → discard by the table",
    A(1),
    A(3),
    { phase: "stale_base" },
    { ...DISCARD, clearCheckpoints: true },
  ),
  row(
    "stale base: start older than control → discard by the table",
    ABSENT,
    A(3),
    { uc: true, full: true, phase: "stale_base" },
    DISCARD,
  ),
  row(
    "stale base: control still admits T → keep pending, registry_inconsistent",
    A(3),
    A(3),
    { phase: "stale_base" },
    { kind: "keep_pending", reason: "registry_inconsistent" },
  ),
  row(
    "stale base: control still admits T → keep pending, registry_inconsistent",
    ABSENT,
    A(1),
    { phase: "stale_base" },
    { kind: "keep_pending", reason: "registry_inconsistent" },
  ),
  row(
    "stale base: control would create or reconnect → keep pending, registry_inconsistent",
    ABSENT,
    ABSENT,
    { phase: "stale_base" },
    { kind: "keep_pending", reason: "registry_inconsistent" },
  ),
  row(
    "stale base: control would create or reconnect → keep pending, registry_inconsistent",
    D(2),
    D(2),
    { uc: true, full: true, phase: "stale_base" },
    { kind: "keep_pending", reason: "registry_inconsistent" },
  ),
  row(
    "stale base: foreign → keep pending, key_mismatch",
    A(1),
    F(3),
    { phase: "stale_base" },
    { kind: "keep_pending", reason: "key_mismatch" },
  ),
];

const startState = [
  { start: null, ns: NS, expected: UNKNOWN },
  { start: {}, ns: NS, expected: ABSENT },
  { start: { [NS2]: A(4) }, ns: NS, expected: ABSENT },
  { start: { [NS]: A(4), [NS2]: D(2) }, ns: NS, expected: A(4) },
  { start: { [NS]: D(2) }, ns: NS, expected: D(2) },
  { start: { "": A(1) }, ns: "", expected: A(1) },
];

// ---------- traces (sequences of decide and checkpoint calls) ----------

const committed = (generation, complete = true) => ({
  state: "committed",
  generation,
  complete,
});
const traces = [
  {
    name: "late head from an older generation (F1)",
    description:
      "A run admitted at g=1 resumes after a delete (v2) and a reconnect elsewhere that committed a g=3 head. chooseBase returns stale_generation; the re-read decides discard and clears checkpoints. Nothing is published, so the g=3 keys stay intact.",
    start: { [NS]: A(1) },
    ns: NS,
    userConnect: false,
    full: false,
    steps: [
      {
        op: "decide",
        current: A(1),
        phase: "first",
        expected: { kind: "publish", target: 1 },
      },
      {
        op: "chooseBase",
        streamRow: "present",
        headGeneration: 3,
        target: 1,
        expected: "stale_generation",
      },
      {
        op: "decide",
        current: A(3),
        phase: "stale_base",
        expected: { ...DISCARD, clearCheckpoints: true },
      },
    ],
  },
  {
    name: "replay after delete (trace A)",
    description:
      "Create v1 reply is lost. Another device deletes (v2). The resend is `replayed`. Re-read shows deleted(2): discard, no publish.",
    start: {},
    ns: NS,
    userConnect: true,
    full: true,
    steps: [
      {
        op: "decide",
        current: ABSENT,
        phase: "first",
        expected: { kind: "create", target: 1 },
      },
      { op: "decide", current: D(2), phase: "after_write", expected: DISCARD },
    ],
  },
  {
    name: "split run",
    description:
      "First connect. Stream s1 creates and commits at g=1. Another device deletes (v2), then a reconnect elsewhere makes active(3). Stream s2 must not reconnect or commit at a new generation, and the run saves no checkpoint.",
    start: {},
    ns: NS,
    userConnect: true,
    full: true,
    steps: [
      {
        op: "decide",
        stream: "s1",
        current: ABSENT,
        phase: "first",
        expected: { kind: "create", target: 1 },
      },
      {
        op: "decide",
        stream: "s1",
        current: A(1),
        phase: "after_write",
        expected: { kind: "publish", target: 1 },
      },
      {
        op: "decide",
        stream: "s2",
        current: D(2),
        phase: "first",
        expected: DISCARD,
      },
      {
        op: "decide",
        stream: "s2",
        current: A(3),
        phase: "first",
        expected: DISCARD,
      },
      {
        op: "checkpoint",
        target: 1,
        streams: { s1: committed(1), s2: { state: "discarded" } },
        control: D(2),
        seedReceiptsPending: false,
        expected: { kind: "skip", reason: "stream_not_committed" },
      },
      {
        op: "checkpoint",
        target: 1,
        streams: { s1: committed(1), s2: { state: "discarded" } },
        control: A(3),
        seedReceiptsPending: false,
        expected: { kind: "skip", reason: "stream_not_committed" },
      },
    ],
  },
  {
    name: "split run, delete between streams of a run at g0",
    description:
      "Run starts with active(1). s1 commits at 1. Another device deletes (v2). s2 discards and clears checkpoints; no checkpoint is saved.",
    start: { [NS]: A(1) },
    ns: NS,
    userConnect: false,
    full: false,
    steps: [
      {
        op: "decide",
        stream: "s1",
        current: A(1),
        phase: "first",
        expected: { kind: "publish", target: 1 },
      },
      {
        op: "decide",
        stream: "s2",
        current: D(2),
        phase: "first",
        expected: { ...DISCARD, clearCheckpoints: true },
      },
      {
        op: "checkpoint",
        target: 1,
        streams: { s1: committed(1, false), s2: { state: "discarded" } },
        control: D(2),
        seedReceiptsPending: false,
        expected: { kind: "skip", reason: "stream_not_committed" },
      },
    ],
  },
  {
    name: "stale userConnect entry (trace B)",
    description:
      "A userConnect run started at deleted(2). Before it publishes, another device reconnects (3) and deletes again (4). The stale entry discards.",
    start: { [NS]: D(2) },
    ns: NS,
    userConnect: true,
    full: true,
    steps: [{ op: "decide", current: D(4), phase: "first", expected: DISCARD }],
  },
  {
    name: "reconnect happy path",
    start: { [NS]: D(2) },
    ns: NS,
    userConnect: true,
    full: true,
    steps: [
      {
        op: "decide",
        stream: "s1",
        current: D(2),
        phase: "first",
        expected: { kind: "reconnect", target: 3 },
      },
      {
        op: "decide",
        stream: "s1",
        current: A(3),
        phase: "after_write",
        expected: { kind: "publish", target: 3 },
      },
      {
        op: "decide",
        stream: "s2",
        current: A(3),
        phase: "first",
        expected: { kind: "publish", target: 3 },
      },
      {
        op: "checkpoint",
        target: 3,
        streams: {
          s1: committed(3),
          s2: { state: "noop", generation: 3, complete: true },
        },
        control: A(3),
        seedReceiptsPending: false,
        expected: { kind: "save", generation: 3 },
      },
    ],
  },
  {
    name: "offline run at g=1 against active(5)",
    start: { [NS]: A(1) },
    ns: NS,
    userConnect: false,
    full: false,
    steps: [
      {
        op: "decide",
        current: A(5),
        phase: "first",
        expected: { ...DISCARD, clearCheckpoints: true },
      },
    ],
  },
  {
    name: "registry read behind the listing",
    start: { [NS]: A(3) },
    ns: NS,
    userConnect: false,
    full: false,
    steps: [
      {
        op: "decide",
        current: A(2),
        phase: "first",
        expected: { kind: "reread" },
      },
      {
        op: "decide",
        current: A(3),
        phase: "reread",
        expected: { kind: "publish", target: 3 },
      },
    ],
  },
  {
    name: "no listing in this app session",
    start: null,
    ns: NS,
    userConnect: true,
    full: true,
    steps: [
      {
        op: "decide",
        current: A(1),
        phase: "first",
        expected: { ...DISCARD, recollect: true },
      },
    ],
  },
  {
    name: "no-op onto a complete:false base (ruling Q9)",
    description:
      "An old DELETE tombstoned s; another device published an empty complete:false head at g=1 and left. This device's incremental run finds nothing new: its parts equal the base and complete stays false, so it is a no-op. The no-op sets needsFull and saves no checkpoint. The next run is full, publishes complete:true, clears needsFull and saves the checkpoint.",
    start: { [NS]: A(1) },
    ns: NS,
    userConnect: false,
    full: false,
    needsFull: [],
    steps: [
      { op: "noop", baseComplete: false, complete: false, expected: true },
      {
        op: "afterCommit",
        commit: {
          connector: "chatgpt",
          ns: NS,
          stream: "s",
          complete: false,
          runFull: false,
        },
        expected: {
          needsFull: [{ connector: "chatgpt", ns: NS, stream: "s" }],
          clearCheckpoint: true,
        },
        mustBeFull: { chatgpt: true },
      },
      {
        op: "checkpoint",
        target: 1,
        streams: { s: { state: "noop", generation: 1, complete: false } },
        control: A(1),
        seedReceiptsPending: false,
        expected: { kind: "skip", reason: "published_incomplete" },
      },
      {
        op: "afterCommit",
        commit: {
          connector: "chatgpt",
          ns: NS,
          stream: "s",
          complete: true,
          runFull: true,
        },
        expected: { needsFull: [], clearCheckpoint: false },
        mustBeFull: { chatgpt: false },
      },
      {
        op: "checkpoint",
        target: 1,
        streams: { s: committed(1) },
        control: A(1),
        seedReceiptsPending: false,
        expected: { kind: "save", generation: 1 },
      },
    ],
  },
];

const checkpoint = [
  {
    name: "all committed complete, control active(T)",
    target: 2,
    streams: {
      a: committed(2),
      b: { state: "noop", generation: 2, complete: true },
    },
    control: A(2),
    seedReceiptsPending: false,
    expected: { kind: "save", generation: 2 },
  },
  {
    name: "no-op of an incomplete head blocks (ruling Q9)",
    target: 2,
    streams: { a: { state: "noop", generation: 2, complete: false } },
    control: A(2),
    seedReceiptsPending: false,
    expected: { kind: "skip", reason: "published_incomplete" },
  },
  {
    name: "a stream published complete:false",
    target: 2,
    streams: { a: committed(2), b: committed(2, false) },
    control: A(2),
    seedReceiptsPending: false,
    expected: { kind: "skip", reason: "published_incomplete" },
  },
  {
    name: "a stream still pending (e.g. bucket_too_large)",
    target: 2,
    streams: { a: committed(2), b: { state: "pending" } },
    control: A(2),
    seedReceiptsPending: false,
    expected: { kind: "skip", reason: "stream_not_committed" },
  },
  {
    name: "a stream committed at another generation",
    target: 2,
    streams: { a: committed(2), b: committed(3) },
    control: A(2),
    seedReceiptsPending: false,
    expected: { kind: "skip", reason: "stream_not_committed" },
  },
  {
    name: "control changed after the last commit",
    target: 2,
    streams: { a: committed(2) },
    control: D(3),
    seedReceiptsPending: false,
    expected: { kind: "skip", reason: "control_changed" },
  },
  {
    name: "control reconnected after the last commit",
    target: 2,
    streams: { a: committed(2) },
    control: A(4),
    seedReceiptsPending: false,
    expected: { kind: "skip", reason: "control_changed" },
  },
  {
    name: "seed receipts pending",
    target: 1,
    streams: { a: committed(1) },
    control: A(1),
    seedReceiptsPending: true,
    expected: { kind: "skip", reason: "seed_receipts_pending" },
  },
];

// ---------- needsFull (sequences) ----------

const k = (stream, ns = NS, connector = "chatgpt") => ({
  connector,
  ns,
  stream,
});
const needsFull = [
  {
    name: "incomplete publish sets it; full complete run clears it",
    initial: [],
    steps: [
      {
        commit: { ...k("s1"), complete: false, runFull: false },
        needsFull: [k("s1")],
        clearCheckpoint: true,
        mustBeFull: { chatgpt: true, spotify: false },
      },
      {
        commit: { ...k("s1"), complete: true, runFull: true },
        needsFull: [],
        clearCheckpoint: false,
        mustBeFull: { chatgpt: false },
      },
    ],
  },
  {
    name: "a non-full complete commit does not clear it",
    initial: [k("s1")],
    steps: [
      {
        commit: { ...k("s1"), complete: true, runFull: false },
        needsFull: [k("s1")],
        clearCheckpoint: false,
        mustBeFull: { chatgpt: true },
      },
    ],
  },
  {
    name: "setting twice keeps one entry; set stays sorted",
    initial: [k("s2")],
    steps: [
      {
        commit: { ...k("s1"), complete: false, runFull: true },
        needsFull: [k("s1"), k("s2")],
        clearCheckpoint: true,
        mustBeFull: { chatgpt: true },
      },
      {
        commit: { ...k("s1"), complete: false, runFull: true },
        needsFull: [k("s1"), k("s2")],
        clearCheckpoint: true,
        mustBeFull: { chatgpt: true },
      },
      {
        commit: { ...k("s2"), complete: true, runFull: true },
        needsFull: [k("s1")],
        clearCheckpoint: false,
        mustBeFull: { chatgpt: true },
      },
      {
        commit: { ...k("s1"), complete: true, runFull: true },
        needsFull: [],
        clearCheckpoint: false,
        mustBeFull: { chatgpt: false },
      },
    ],
  },
  {
    name: "entries are per (connector, ns, stream)",
    initial: [k("s1", NS2)],
    steps: [
      {
        commit: { ...k("s1"), complete: true, runFull: true },
        needsFull: [k("s1", NS2)],
        clearCheckpoint: false,
        mustBeFull: { chatgpt: true },
      },
    ],
  },
];

// ---------- eligible ----------

const conn = (ns, control, reg, streams) => ({
  ns,
  control,
  latestHeadRegistration: reg,
  streams,
});
const S = (live, complete) => ({ live, complete });
const logical = (...streams) => ({ kind: "logical", streams });
const eligibleCases = [
  {
    name: "complete view is served",
    connections: [conn(NS, A(1), 10, { s: S(true, true) })],
    target: logical("s"),
    legacyFile: false,
    expected: { kind: "view", ns: NS },
  },
  {
    name: "one-way: complete view beats a legacy file",
    connections: [conn(NS, A(1), 10, { s: S(true, true) })],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "view", ns: NS },
  },
  {
    name: "incomplete view falls back to legacy",
    connections: [conn(NS, A(1), 10, { s: S(true, false) })],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "legacy" },
  },
  {
    name: "join: one needed stream missing → legacy",
    connections: [conn(NS, A(1), 10, { a: S(true, true) })],
    target: logical("a", "b"),
    legacyFile: true,
    expected: { kind: "legacy" },
  },
  {
    name: "join: every needed stream live and complete",
    connections: [conn(NS, A(1), 10, { a: S(true, true), b: S(true, true) })],
    target: logical("a", "b"),
    legacyFile: true,
    expected: { kind: "view", ns: NS },
  },
  {
    name: "not live (old generation head) → legacy",
    connections: [conn(NS, A(2), 10, { s: S(false, true) })],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "legacy" },
  },
  {
    name: "deleted connection suppresses legacy",
    connections: [conn(NS, D(2), null, {})],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "unavailable", reason: "deleted" },
  },
  {
    name: "deleted account B suppresses legacy while live A is incomplete",
    connections: [
      conn(NS, A(1), 10, { s: S(true, false) }),
      conn(NS2, D(2), null, {}),
    ],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "unavailable", reason: "deleted" },
  },
  {
    name: "deleted account B does not hide live complete A",
    connections: [
      conn(NS, A(1), 10, { s: S(true, true) }),
      conn(NS2, D(2), null, {}),
    ],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "view", ns: NS },
  },
  {
    name: "reconnected connection no longer suppresses",
    connections: [conn(NS, A(3), null, {})],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "legacy" },
  },
  {
    name: "nothing at all",
    connections: [],
    target: logical("s"),
    legacyFile: false,
    expected: { kind: "unavailable", reason: "no_data" },
  },
  {
    name: "legacy only",
    connections: [],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "legacy" },
  },
  {
    name: "most recently registered connection is selected",
    connections: [
      conn(NS, A(1), 10, { s: S(true, true) }),
      conn(NS2, A(1), 20, { s: S(true, true) }),
    ],
    target: logical("s"),
    legacyFile: false,
    expected: { kind: "view", ns: NS2 },
  },
  {
    name: "selected connection incomplete: no fall-through to another connection",
    connections: [
      conn(NS, A(1), 10, { s: S(true, true) }),
      conn(NS2, A(1), 20, { s: S(true, false) }),
    ],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "legacy" },
  },
  {
    name: "foreign connection is never selected",
    connections: [conn(NS, F(1), 99, { s: S(true, true) })],
    target: logical("s"),
    legacyFile: true,
    expected: { kind: "legacy" },
  },
  {
    name: "tie on registration: lowest ns",
    connections: [
      conn(NS2, A(1), 10, { s: S(true, true) }),
      conn(NS, A(1), 10, { s: S(true, true) }),
    ],
    target: logical("s"),
    legacyFile: false,
    expected: { kind: "view", ns: NS < NS2 ? NS : NS2 },
    question: "Q6",
  },
  {
    name: "physical name selects its own connection",
    connections: [
      conn(NS, A(1), 10, { s: S(true, true) }),
      conn(NS2, A(1), 20, { s: S(true, true) }),
    ],
    target: { kind: "physical", ns: NS, streams: ["s"] },
    legacyFile: false,
    expected: { kind: "view", ns: NS },
  },
  {
    name: "physical name of a deleted connection",
    connections: [conn(NS, D(2), null, {})],
    target: { kind: "physical", ns: NS, streams: ["s"] },
    legacyFile: false,
    expected: { kind: "unavailable", reason: "deleted" },
  },
  {
    name: "prototype names are not streams",
    connections: [conn(NS, A(1), 10, {})],
    target: logical("constructor"),
    legacyFile: false,
    expected: { kind: "unavailable", reason: "no_data" },
  },
].map((c) => ({ ...c, ready: c.expected.kind !== "unavailable" }));

// ---------- write ----------

const vectors = {
  format: "pdpp-stream-sync-vectors",
  version: 1,
  design: "Whole-file stream sync, revision 4.1, section 2",
  notes: [
    "All text is UTF-8. Hashes: SHA-256 and Keccak-256 as lowercase hex; registry hashes (dataHash, control hashes) are 0x-prefixed.",
    "Canonical JSON: object keys sorted by UTF-16 code unit, no whitespace, ECMAScript number and string printing.",
    "A part is the canonical lines of its winners, sorted by pkHash, each followed by \\n.",
    "Head text is the canonical JSON of the head; generation is a decimal string.",
    "Control states: {kind:absent} | {kind:active,generation} | {kind:deleted,version} | {kind:foreign,version}; start state adds {kind:unknown}.",
    "Cases with a `question` field follow a provisional reading; see DESIGN-QUESTIONS.md.",
  ],
  namespace,
  streamMasterKey,
  scopes,
  pkHash: pkCases,
  lines,
  frames,
  merge,
  planner,
  heads: {
    encode: headEncode,
    decode: headDecode,
    verify: headVerify,
    base: baseHead,
  },
  headRules,
  control: { controlHashes: hashes, cases: control },
  startState,
  decide,
  traces,
  checkpoint,
  needsFull,
  eligible: eligibleCases,
};

const text = JSON.stringify(vectors, null, 2) + "\n";
if (process.argv.includes("--check")) {
  const current = readFileSync(out, "utf8");
  if (JSON.stringify(JSON.parse(current)) !== JSON.stringify(vectors)) {
    console.error("vectors/v1.json is stale: run generate-vectors.mjs");
    process.exit(1);
  }
  console.log("vectors/v1.json is current");
} else {
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}
