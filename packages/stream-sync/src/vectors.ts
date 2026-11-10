/* eslint-disable @typescript-eslint/no-explicit-any -- vectors are untyped JSON */
/**
 * Conformance runner for `vectors/v2.json`. A host loads the JSON itself and
 * passes its own crypto ports, so the same file checks this package and each
 * host's adapters (for example an HMAC port that keeps `K_ns` in a closure).
 * The runner does no I/O.
 */

import { toHex, utf8, type HashPorts, type NamespaceHmac } from "./bytes.js";
import { classifyControl, type ControlState } from "./control.js";
import {
  checkpointDecision,
  decide,
  startState,
  type StartState,
} from "./decide.js";
import { eligible, isReady } from "./eligible.js";
import {
  chooseBase,
  decodeHead,
  digestHead,
  encodeHead,
  headComplete,
  isHeadLive,
  isNoop,
  verifyHead,
  writerCompatibility,
  type Head,
} from "./head.js";
import { canonicalJson } from "./json.js";
import { mergeLines } from "./merge.js";
import {
  controlScope,
  headBlobName,
  parseBlobName,
  parseScope,
  partBlobName,
  streamScope,
} from "./names.js";
import { controlHashes, deriveKeyCheck, deriveNs } from "./namespace.js";
import { streamMasterKeyFromSignature } from "./master-key.js";
import { afterCommit, runMustBeFull, type NeedsFull } from "./needs-full.js";
import { decodeEnvelope, encodeEnvelope, frameOfBody } from "./frames.js";
import { encodeFramePart } from "./part-frames.js";
import { decodePart, encodePart } from "./parts.js";
import { planBuckets } from "./planner.js";
import {
  decodeLine,
  encodeLine,
  pkHash,
  pkHashBits,
  shardOf,
} from "./records.js";

export interface VectorPorts extends HashPorts {
  /** An HMAC-SHA256 port keyed with the given raw `K_ns` bytes. */
  readonly namespaceHmac: (kNs: Uint8Array) => NamespaceHmac;
  /**
   * The host's `K_ns` derivation from a master key:
   * `deriveScopeKey(masterKey, NAMESPACE_KEY_LABEL)`.
   */
  readonly namespaceKey: (masterKey: Uint8Array) => Uint8Array;
}

export interface VectorReport {
  /** Number of checks run. */
  readonly checks: number;
  /** One line per failed check; empty when the host conforms. */
  readonly failures: readonly string[];
}

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function wireToHead(wire: any): Head {
  return { ...wire, generation: Number(wire.generation) };
}

export async function runVectors(
  vectors: any,
  ports: VectorPorts,
): Promise<VectorReport> {
  const failures: string[] = [];
  let checks = 0;
  const eq = (label: string, actual: unknown, expected: unknown): void => {
    checks += 1;
    const a = canonicalJson(actual ?? null);
    const e = canonicalJson(expected ?? null);
    if (a !== e) failures.push(`${label}: expected ${e}, got ${a}`);
  };
  const throws = async (label: string, fn: () => unknown): Promise<void> => {
    checks += 1;
    try {
      await fn();
      failures.push(`${label}: expected an error`);
    } catch {
      // expected
    }
  };

  if (vectors?.format !== "pdpp-stream-sync-vectors" || vectors.version !== 2) {
    return { checks: 1, failures: ["not a version-2 stream-sync vector file"] };
  }

  // namespace
  const ns = vectors.namespace;
  const hmac = ports.namespaceHmac(hexBytes(ns.kNsHex));
  eq("keyCheck", await deriveKeyCheck(hmac), ns.keyCheck);
  eq(
    "controlHashes",
    await controlHashes(ports.keccak256, ns.keyCheck),
    ns.controlHashes,
  );
  for (const c of ns.cases) {
    eq(
      `ns ${c.connector}/${c.accountId}`,
      await deriveNs(hmac, c.connector, c.accountId),
      c.ns,
    );
    eq(
      `ns message ${c.connector}`,
      canonicalJson([c.connector, c.accountId]),
      c.message,
    );
  }

  // stream master key (ruling R4): every encoding gives one key, ns and keyCheck
  const smk = vectors.streamMasterKey;
  for (const e of smk.encodings) {
    const masterKey = streamMasterKeyFromSignature(e.signature);
    eq(`streamMasterKey ${e.name}`, toHex(masterKey), smk.masterKeyHex);
    const kNs = ports.namespaceKey(masterKey);
    eq(`streamMasterKey K_ns ${e.name}`, toHex(kNs), smk.kNsHex);
    const encodingHmac = ports.namespaceHmac(kNs);
    eq(
      `streamMasterKey keyCheck ${e.name}`,
      await deriveKeyCheck(encodingHmac),
      smk.keyCheck,
    );
    eq(
      `streamMasterKey ns ${e.name}`,
      await deriveNs(encodingHmac, smk.ns.connector, smk.ns.accountId),
      smk.ns.ns,
    );
  }
  for (const bad of smk.invalid) {
    await throws(`streamMasterKey rejects ${bad.name}`, () =>
      streamMasterKeyFromSignature(bad.signature),
    );
  }

  // scopes
  const sc = vectors.scopes;
  for (const c of sc.build) {
    const built =
      c.stream === undefined
        ? controlScope(c.connector, c.ns)
        : streamScope(c.connector, c.ns, c.stream);
    eq(`build ${c.scope}`, built, c.scope);
    eq(`round-trip ${c.scope}`, parseScope(built), {
      kind: c.stream === undefined ? "control" : "stream",
      connector: c.connector,
      ns: c.ns,
      ...(c.stream === undefined ? {} : { stream: c.stream }),
    });
  }
  for (const c of sc.buildErrors) {
    await throws(`build error ${c.why}`, () =>
      streamScope(c.connector, c.ns, c.stream),
    );
  }
  for (const c of sc.parse) eq(`parse ${c.name}`, parseScope(c.name), c.parsed);
  for (const c of sc.blobs) {
    eq(
      `blob ${c.name}`,
      c.kind === "head"
        ? headBlobName(c.hash)
        : partBlobName(c.generation, c.hash),
      c.name,
    );
  }
  for (const c of sc.blobParse)
    eq(`blob parse ${c.name}`, parseBlobName(c.name), c.parsed);

  // pkHash
  for (const c of vectors.pkHash) {
    const hash = await pkHash(ports.sha256, c.record, c.primaryKey);
    eq(`pkHash ${c.keyJson}`, hash, c.pkHash);
    eq(`shard ${c.keyJson}`, shardOf(hash), c.shard);
    eq(`bits16 ${c.keyJson}`, pkHashBits(hash, 16), c.bits16);
  }

  // lines
  for (const c of vectors.lines.encode) {
    eq(`encodeLine ${c.text}`, encodeLine(c.line), c.text);
    eq(`decodeLine ${c.text}`, decodeLine(c.text), c.line);
  }
  for (const c of vectors.lines.decodeErrors) {
    await throws(`decodeLine ${c.why}`, () => decodeLine(c.text));
  }

  // frames (format 2)
  for (const c of vectors.frames.cases) {
    const body = utf8(canonicalJson(c.record));
    const key = await pkHash(ports.sha256, c.record, c.primaryKey);
    const envelope = {
      h: toHex(await ports.sha256(body)),
      k: key,
      n: body.length,
      o: c.o,
      r: c.r,
    };
    eq(
      `envelope ${c.name}`,
      new TextDecoder().decode(encodeEnvelope(envelope)),
      c.envelope,
    );
    eq(`decodeEnvelope ${c.name}`, decodeEnvelope(utf8(c.envelope)), envelope);
    eq(
      `frame ${c.name}`,
      new TextDecoder().decode(frameOfBody(envelope, body)),
      c.frame,
    );
  }
  {
    const part = vectors.frames.part;
    const framed = vectors.frames.cases.map((c: any) => ({
      k: JSON.parse(c.envelope).k as string,
      bytes: utf8(c.frame),
    }));
    const encoded = await encodeFramePart(ports.sha256, part.prefix, framed);
    eq(
      "frame part",
      encoded && new TextDecoder().decode(encoded.data),
      part.text,
    );
    eq("frame part entry", encoded?.entry, {
      bytes: part.bytes,
      count: part.count,
      hash: part.hash,
      prefix: part.prefix,
    });
  }
  {
    const long = vectors.frames.long;
    const body = utf8(canonicalJson({ id: "big", x: "a".repeat(long.count) }));
    eq("long body bytes", body.length, long.bodyBytes);
    eq("long body hash", toHex(await ports.sha256(body)), long.bodyHash);
    eq(
      "long key",
      await pkHash(ports.sha256, { id: "big" }, long.primaryKey),
      long.k,
    );
    eq(
      "long envelope",
      new TextDecoder().decode(
        encodeEnvelope({
          h: long.bodyHash,
          k: long.k,
          n: long.bodyBytes,
          o: long.o,
          r: long.r,
        }),
      ),
      long.envelope,
    );
  }
  for (const c of vectors.frames.envelopeErrors) {
    await throws(`decodeEnvelope ${c.why}`, () => decodeEnvelope(utf8(c.text)));
  }

  // merge and parts
  for (const c of vectors.merge) {
    const entries = [];
    for (const line of c.feed) {
      entries.push({
        pkHash: await pkHash(ports.sha256, line.v, c.primaryKey),
        line,
      });
    }
    let result: ReturnType<typeof mergeLines>;
    try {
      result = mergeLines(entries, c.prefix, c.limitBytes);
    } catch (error) {
      // A wrong hash port puts keys outside the case's prefix.
      eq(`merge ${c.name}`, (error as Error).message, "no error");
      continue;
    }
    if (c.expected.kind !== undefined) {
      eq(`merge ${c.name}`, result, c.expected);
      continue;
    }
    if (result.kind !== "ok") {
      eq(`merge ${c.name}`, result.kind, "ok");
      continue;
    }
    eq(`merge ${c.name}`, result.winners, c.expected.winners);
    eq(`merge bytes ${c.name}`, result.bytes, c.expected.bytes);
    const part = await encodePart(ports.sha256, result);
    eq(
      `part ${c.name}`,
      part && {
        text: new TextDecoder().decode(part.data),
        sha256: part.entry.hash,
      },
      c.expected.sha256 === null
        ? null
        : { text: c.expected.partText, sha256: c.expected.sha256 },
    );
    if (part) {
      const decoded = await decodePart(
        ports.sha256,
        part.data,
        part.entry,
        c.primaryKey,
      );
      eq(
        `decodePart ${c.name}`,
        decoded.map((d) => d.text),
        c.expected.winners.map((w: any) => w.text),
      );
    }
  }

  // planner
  for (const c of vectors.planner) {
    if (c.expected.kind === "error") {
      await throws(`planner ${c.name}`, () => planBuckets(c.input));
    } else {
      eq(`planner ${c.name}`, planBuckets(c.input), c.expected);
    }
  }

  // heads
  for (const c of vectors.heads.encode) {
    const bytes = encodeHead(wireToHead(c.head));
    eq(`head text ${c.name}`, new TextDecoder().decode(bytes), c.text);
    eq(`head digest ${c.name}`, await digestHead(ports.keccak256, bytes), {
      dataHash: c.dataHash,
      blobName: c.blobName,
    });
    const decoded = decodeHead(bytes);
    eq(
      `head decode round-trip ${c.name}`,
      decoded.kind === "ok"
        ? new TextDecoder().decode(encodeHead(decoded.head))
        : decoded.kind,
      c.text,
    );
  }
  for (const c of vectors.heads.decode) {
    eq(`head decode ${c.name}`, decodeHead(utf8(c.text)).kind, c.expected);
  }
  for (const c of vectors.heads.verify) {
    eq(
      `head verify ${c.name}`,
      (await verifyHead(ports.keccak256, utf8(c.text), c.expect)).kind,
      c.result,
    );
  }

  // head rules
  const base = wireToHead(vectors.heads.base);
  const hr = vectors.headRules;
  for (const c of hr.liveness) {
    eq(
      `live ${canonicalJson(c)}`,
      isHeadLive(c.control, c.streamRow, c.headGeneration),
      c.live,
    );
  }
  for (const c of hr.chooseBase) {
    const head =
      c.headGeneration === null
        ? null
        : { ...base, generation: c.headGeneration };
    eq(
      `chooseBase ${canonicalJson(c)}`,
      chooseBase(c.streamRow, head, c.target).kind,
      c.base,
    );
  }
  for (const c of hr.writerCompatibility) {
    const head =
      c.basePrimaryKey === null
        ? null
        : { ...base, primaryKey: c.basePrimaryKey };
    eq(
      `writer ${canonicalJson(c)}`,
      writerCompatibility(head, c.writerPrimaryKey, c.writerVersusBase).kind,
      c.result,
    );
  }
  for (const c of hr.complete)
    eq(`complete ${canonicalJson(c)}`, headComplete(c), c.complete);
  for (const c of hr.noop) {
    eq(
      `noop ${c.name}`,
      isNoop(c.base === null ? null : base, c.parts, c.complete),
      c.noop,
    );
  }

  // control
  for (const c of vectors.control.cases) {
    eq(
      `control ${c.name}`,
      classifyControl(c.read, vectors.control.controlHashes),
      c.expected,
    );
  }

  // decide
  for (const c of vectors.startState) {
    eq(`startState ${canonicalJson(c)}`, startState(c.start, c.ns), c.expected);
  }
  for (const c of vectors.decide) {
    eq(
      `decide ${c.row} [${canonicalJson([c.start, c.current, c.userConnect, c.full, c.phase])}]`,
      decide(c),
      c.expected,
    );
  }
  for (const t of vectors.traces) {
    const s: StartState = startState(t.start, t.ns);
    let needsFull: NeedsFull = t.needsFull ?? [];
    t.steps.forEach((step: any, i: number) => {
      const label = `trace ${t.name} step ${i}`;
      if (step.op === "noop") {
        eq(
          label,
          isNoop(
            { ...base, complete: step.baseComplete },
            base.parts,
            step.complete,
          ),
          step.expected,
        );
      } else if (step.op === "afterCommit") {
        const effect = afterCommit(needsFull, step.commit);
        eq(label, effect, step.expected);
        needsFull = effect.needsFull;
        for (const [connector, must] of Object.entries(step.mustBeFull)) {
          eq(
            `${label} mustBeFull ${connector}`,
            runMustBeFull(needsFull, connector),
            must,
          );
        }
      } else if (step.op === "decide") {
        eq(
          label,
          decide({
            start: s,
            current: step.current as ControlState,
            userConnect: t.userConnect,
            full: t.full,
            phase: step.phase,
          }),
          step.expected,
        );
      } else if (step.op === "chooseBase") {
        const head =
          step.headGeneration === null
            ? null
            : { ...base, generation: step.headGeneration };
        eq(
          label,
          chooseBase(step.streamRow, head, step.target).kind,
          step.expected,
        );
      } else if (step.op === "checkpoint") {
        eq(label, checkpointDecision(step), step.expected);
      } else {
        throw new Error(`${label}: unknown op ${String(step.op)}`);
      }
    });
  }
  for (const c of vectors.checkpoint)
    eq(`checkpoint ${c.name}`, checkpointDecision(c), c.expected);

  // needsFull
  for (const c of vectors.needsFull) {
    let set: NeedsFull = c.initial;
    c.steps.forEach((step: any, i: number) => {
      const effect = afterCommit(set, step.commit);
      eq(`needsFull ${c.name} step ${i}`, effect, {
        needsFull: step.needsFull,
        clearCheckpoint: step.clearCheckpoint,
      });
      set = effect.needsFull;
      for (const [connector, must] of Object.entries(step.mustBeFull)) {
        eq(
          `mustBeFull ${c.name} step ${i} ${connector}`,
          runMustBeFull(set, connector),
          must,
        );
      }
    });
  }

  // eligible
  for (const c of vectors.eligible) {
    eq(`eligible ${c.name}`, eligible(c), c.expected);
    eq(`ready ${c.name}`, isReady(c), c.ready);
  }

  return { checks, failures };
}
