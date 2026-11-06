/**
 * Trace-replay conformance: replays TLC traces of `formal/StreamSync.tla`
 * against the package and reports every step where the package decides
 * differently from the model. README.md in this directory has the mapping
 * table and the list of model abstractions.
 *
 * The oracle is the model itself: the step TLC took (read from the next
 * state) and the model operators the trace export evaluated in each state
 * (`TraceAlias` in StreamSyncConformance.tla). The few model expressions
 * that live inside an action's LET and so cannot be exported are restated
 * here, each marked "restated from StreamSync.tla".
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import * as pkg from "../src/index.js";
import type {
  ControlState,
  Decision,
  DecidePhase,
  Head,
  HeadPart,
  Line,
  NeedsFull,
  StartState,
  StreamRunResult,
} from "../src/index.js";

// ---------------------------------------------------------------- corpus

/**
 * A TLA+ value as TLC writes it to JSON. The model, not a TypeScript type,
 * defines the shape; the replay reads fields by their model names.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ModelValue = any;

/** A TLA+ state as written by `TraceAlias`. */
export type ModelState = Record<string, ModelValue>;

export interface CorpusTrace {
  readonly id: string;
  readonly kind: "fixed" | "sim";
  readonly profile: string;
  readonly invariant?: string;
  readonly seed?: number;
  readonly holds?: boolean;
  readonly timedOut?: number;
  readonly steps?: readonly { a: string; p?: Record<string, ModelValue> }[];
  readonly states?: readonly ModelState[];
}

export interface CorpusMeta {
  readonly kind: "meta";
  readonly model: {
    readonly ref: string;
    readonly streamSyncSha256: string;
    readonly staleGeneration: boolean;
    /** The model's design constants (configs.mjs DESIGN) the corpus ran with. */
    readonly design?: Readonly<Record<string, string>>;
  };
  readonly profiles: Record<string, Record<string, unknown>>;
}

/** The committed corpus. */
export const CORPUS_URL = new URL("./corpus/corpus.ndjson.gz", import.meta.url);

/** Corpus text from a `.ndjson` or `.ndjson.gz` file. */
export function readCorpus(file: string | URL = CORPUS_URL): string {
  const bytes = readFileSync(file);
  return (String(file).endsWith(".gz") ? gunzipSync(bytes) : bytes).toString(
    "utf8",
  );
}

export function parseCorpus(text: string): {
  meta: CorpusMeta;
  traces: CorpusTrace[];
} {
  const lines = text.split("\n").filter((l) => l !== "");
  const [first, ...rest] = lines.map((l) => JSON.parse(l));
  return { meta: first as CorpusMeta, traces: rest as CorpusTrace[] };
}

/** Full states from the first state and the per-step changed fields. */
export function expandStates(trace: CorpusTrace): ModelState[] {
  const out: ModelState[] = [];
  for (const delta of trace.states ?? []) {
    out.push(out.length === 0 ? delta : { ...out.at(-1), ...delta });
  }
  return out;
}

// ------------------------------------------------------- value mappings

export const CONNECTOR = "c";
const DESKTOP = "d1";
const LEGACY_FROM = "s1";

/** Model namespace (an account model value, or "" when identity-less). */
export function nsHex(n: string): string {
  if (n === "") return "";
  const hex = Buffer.from(n, "utf8").toString("hex");
  return hex.padStart(16, "0").slice(-16);
}

function keyCheckOf(key: string): string {
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

/** Model control state `[k, g]` as the package's `ControlState`. */
export function toControl(st: { k: string; g: number }): ControlState {
  switch (st.k) {
    case "absent":
      return { kind: "absent" };
    case "active":
      return { kind: "active", generation: st.g };
    case "deleted":
      return { kind: "deleted", version: st.g };
    case "foreign":
      return { kind: "foreign", version: st.g };
  }
  throw new Error(`not a control state: ${JSON.stringify(st)}`);
}

export function toStart(st: { k: string; g: number }): StartState {
  return st.k === "unknown" ? { kind: "unknown" } : toControl(st);
}

/** A model line `<<pk, rid, acct, origin>>`. */
type ModelLine = [string, number, string, string];

/** Run lines: `o` = run id (run start order), `r` = the run id as text. */
export function toLine(l: ModelLine): Line {
  const [pk, rid, acct, origin] = l;
  if (origin === "run") {
    return {
      o: rid,
      r: `run-${String(rid).padStart(6, "0")}`,
      v: { id: pk, acct },
    };
  }
  if (origin === "seed") {
    return { o: pkg.SEED_OBSERVED_AT, r: pkg.SEED_RUN_ID, v: { id: pk, acct } };
  }
  if (origin === "raw") return { o: 0, r: "raw", v: { id: pk, acct } };
  throw new Error(`no package line for origin ${origin}`);
}

export function fromLine(line: Line): string {
  const v = line.v as { id: string; acct: string };
  const origin =
    line.r === pkg.SEED_RUN_ID ? "seed" : line.r === "raw" ? "raw" : "run";
  const rid = origin === "run" ? line.o : 0;
  return JSON.stringify([v.id, rid, v.acct, origin]);
}

const lineKey = (l: ModelLine): string => JSON.stringify(l);

/** The package's stream row for a model row chain (TombHead: key "old"). */
function rowOf(rows: readonly { key: string }[]): pkg.StreamRow {
  const top = rows.at(-1);
  if (!top) return "absent";
  return top.key === "old" ? "tombstoned" : "present";
}

// ------------------------------------------------------------- hashing

export const sha256: pkg.Sha256 = async (data) =>
  new Uint8Array(createHash("sha256").update(data).digest());

const pkHashCache = new Map<string, string>();
async function pkHashOf(pk: string): Promise<string> {
  let hash = pkHashCache.get(pk);
  if (!hash) {
    hash = await pkg.pkHash(sha256, { id: pk }, ["id"]);
    pkHashCache.set(pk, hash);
  }
  return hash;
}

interface Built {
  readonly head: Head;
  /** Part bytes by part hash. */
  readonly data: Map<string, Uint8Array>;
}

/** Merge lines in the package (base first) and encode one part per bucket. */
async function reduceLines(groups: readonly (readonly Line[])[]): Promise<{
  winners: pkg.Winner[];
  parts: HeadPart[];
  data: Map<string, Uint8Array>;
}> {
  const reducer = new pkg.BucketReducer("");
  for (const lines of groups) {
    for (const line of lines) {
      reducer.add(await pkHashOf((line.v as { id: string }).id), line);
    }
  }
  const bucket = reducer.finish();
  if (bucket.kind !== "ok")
    throw new Error("bucket too large in a model trace");
  const part = await pkg.encodePart(sha256, bucket);
  const data = new Map<string, Uint8Array>();
  if (part) data.set(part.entry.hash, part.data);
  return {
    winners: [...bucket.winners],
    parts: part ? [part.entry] : [],
    data,
  };
}

/** A model head row as a package head (built with the package's encoders). */
async function toHead(
  n: string,
  s: string,
  h: {
    g: number;
    lines: ModelLine[];
    complete: boolean;
    key: string;
    at: number;
  },
): Promise<Built> {
  const { parts, data } = await reduceLines([h.lines.map(toLine)]);
  const head: Head = {
    complete: h.complete,
    connector: CONNECTOR,
    format: 1,
    generation: h.g,
    keyCheck: keyCheckOf(h.key),
    ns: nsHex(n),
    observedAt: h.at,
    parts,
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
    recordCount: parts.reduce((sum, p) => sum + p.count, 0),
    stream: s,
  };
  const decoded = pkg.decodeHead(pkg.encodeHead(head));
  if (decoded.kind !== "ok")
    throw new Error(`head did not round-trip: ${decoded.kind}`);
  return { head, data };
}

/** Lines of a package head, read back through `decodePart`. */
async function headLines(built: Built): Promise<Line[]> {
  const out: Line[] = [];
  for (const part of built.head.parts) {
    const lines = await pkg.decodePart(
      sha256,
      built.data.get(part.hash)!,
      part,
      ["id"],
    );
    out.push(...lines.map((l) => l.line));
  }
  return out;
}

// ------------------------------------------------- package adapters

function needsFullOf(st: ModelState, d: string): NeedsFull {
  const set: [string, string][] = st.needsFull[d] ?? [];
  return [...set]
    .map(([n, s]) => ({ connector: CONNECTOR, ns: nsHex(n), stream: s }))
    .sort((a, b) =>
      a.ns === b.ns ? (a.stream < b.stream ? -1 : 1) : a.ns < b.ns ? -1 : 1,
    );
}

const nfKeys = (nf: NeedsFull): string =>
  JSON.stringify(nf.map((k) => `${k.ns}/${k.stream}`).sort());

// --------------------------------------------------------- the replay

/**
 * The package functions the replay compares with the model. Tests swap one
 * for a mutant to show the corpus catches the change.
 */
export type DecisionApi = Pick<
  typeof pkg,
  | "isHeadLive"
  | "eligible"
  | "isReady"
  | "decide"
  | "targetFor"
  | "runMustBeFull"
  | "createOutboxEntry"
  | "chooseBase"
  | "headComplete"
  | "isNoop"
  | "afterCommit"
  | "checkpointDecision"
>;

export interface Divergence {
  readonly trace: string;
  /** Index of the step (1-based, as TLC numbers states: step i leads to state i + 1). */
  readonly step: number;
  readonly action: string;
  readonly check: string;
  readonly model: string;
  readonly package: string;
  readonly detail?: string;
}

export interface ReplayStats {
  traces: number;
  steps: number;
  /** Per check: decision points compared. */
  points: Record<string, number>;
  /** Per check: distinct decision inputs compared. */
  distinct: Record<string, number>;
  /** Model rules with no package function, and how often they applied. */
  modelOnly: Record<string, number>;
}

type Result = {
  state: "committed" | "noop";
  generation: number;
  complete: boolean;
};

const NO_ENTRY = (e: ModelValue): boolean => e === undefined || e.rid === 0;

export async function replayTrace(
  trace: CorpusTrace,
  /** The model's PK constant for the trace's profile. */
  pkConstant: readonly string[],
  api: DecisionApi,
  stats: ReplayStats,
  out: Divergence[],
  /** The model's design constants (`CorpusMeta.model.design`). */
  design: Readonly<Record<string, string>> = {},
): Promise<void> {
  const states = expandStates(trace);
  const steps = trace.steps ?? [];
  stats.traces += 1;
  stats.steps += steps.length;
  const seenInputs = new Map<string, Set<string>>();

  const point = (check: string, input: unknown): void => {
    stats.points[check] = (stats.points[check] ?? 0) + 1;
    let set = seenInputs.get(check);
    if (!set) seenInputs.set(check, (set = new Set()));
    const key = JSON.stringify(input);
    if (!set.has(key)) {
      set.add(key);
      stats.distinct[check] = (stats.distinct[check] ?? 0) + 1;
    }
  };
  const modelOnly = (rule: string): void => {
    stats.modelOnly[rule] = (stats.modelOnly[rule] ?? 0) + 1;
  };
  const diverge = (
    step: number,
    action: string,
    check: string,
    model: unknown,
    pkgOut: unknown,
    detail?: string,
  ): void => {
    out.push({
      trace: trace.id,
      step,
      action,
      check,
      model: typeof model === "string" ? model : JSON.stringify(model),
      package: typeof pkgOut === "string" ? pkgOut : JSON.stringify(pkgOut),
      ...(detail ? { detail } : {}),
    });
  };

  // Host-side memory the model keeps implicitly.
  const phase = new Map<string, DecidePhase>(); // `${d}/${s}` -> decide phase
  const results = new Map<string, Map<string, Result>>(); // d -> s -> result

  for (let i = 0; i < states.length; i += 1) {
    const st = states[i]!;
    checkState(st, i);
    if (i === steps.length) break;
    const next = states[i + 1]!;
    await checkStep(steps[i]!, st, next, i + 1);
  }

  // ---- state-level: liveness, eligibility, readiness, pending decisions
  function checkState(st: ModelState, index: number): void {
    const nss = Object.keys(st.xreg);
    for (const n of nss) {
      const reg = st.xreg[n];
      for (const s of Object.keys(reg.liveP)) {
        const rows = st.hd[n][s] as ModelValue[];
        const latest = rows.at(-1);
        const input = [reg.ctl, rows.length, latest?.g ?? null];
        point("isHeadLive", input);
        const row = rowOf(rows);
        const live = api.isHeadLive(
          toControl(reg.ctl),
          row,
          row === "present" ? latest.g : null,
        );
        if (live !== reg.liveP[s]) {
          diverge(
            index,
            "(state)",
            "isHeadLive",
            reg.liveP[s],
            live,
            `${n}/${s}`,
          );
        }
      }
    }

    const connections = nss.map((n) => {
      const reg = st.xreg[n];
      const streams: Record<string, pkg.StreamHeadView> = {};
      for (const s of Object.keys(reg.liveP)) {
        const latest = (st.hd[n][s] as ModelValue[]).at(-1);
        streams[s] = {
          live: reg.liveP[s],
          complete: latest ? latest.complete : false,
        };
      }
      return {
        ns: nsHex(n),
        control: toControl(reg.ctl),
        latestHeadRegistration: reg.stamp >= 0 ? reg.stamp : null,
        streams,
      };
    });
    for (const [legacy, variants] of Object.entries<ModelValue>(st.xread)) {
      for (const [age, names] of Object.entries<ModelValue>(variants)) {
        for (const [name, rd] of Object.entries<ModelValue>(names)) {
          const input = {
            connections,
            target: {
              kind: "logical" as const,
              streams: [name === "legacy" ? LEGACY_FROM : name],
            },
            legacyFile: rd.file as boolean,
          };
          point("eligible", input);
          const got = api.eligible(input);
          const want =
            rd.k === "view"
              ? `view:${(rd.vns as string[]).map(nsHex).join(",")}`
              : rd.k;
          const have = got.kind === "view" ? `view:${got.ns}` : got.kind;
          if (want !== have) {
            diverge(
              index,
              "(state)",
              "eligible",
              want,
              have,
              `${name}, legacy ${legacy}/${age}`,
            );
          }
          point("isReady", input);
          if (api.isReady(input) !== rd.ready) {
            diverge(
              index,
              "(state)",
              "isReady",
              rd.ready,
              !rd.ready,
              `${name}, legacy ${legacy}/${age}`,
            );
          }
        }
      }
    }

    // A stream the model leaves pending: its table value is -1 (keep
    // pending), so Decide is not enabled. The package must not publish,
    // create, reconnect or discard it.
    for (const [d, x] of Object.entries<ModelValue>(st.xdev)) {
      const e = st.ob[d];
      if (NO_ENTRY(e) || e.dead || x.t !== -1) continue;
      for (const [s, state] of Object.entries<string>(e.st)) {
        if (state !== "planned") continue;
        const ph = phase.get(`${d}/${s}`) ?? "first";
        const input = { S: x.S, C: x.C, uc: e.uc, full: e.full, ph };
        point("decide", input);
        const first = api.decide({
          start: toStart(x.S),
          current: toControl(x.C),
          userConnect: e.uc,
          full: e.full,
          phase: ph,
        });
        const okFirst =
          ph === "after_write"
            ? false
            : first.kind === "keep_pending" || first.kind === "reread";
        let reread: Decision | null = null;
        if (first.kind === "reread") {
          reread = api.decide({
            start: toStart(x.S),
            current: toControl(x.C),
            userConnect: e.uc,
            full: e.full,
            phase: "reread",
          });
        }
        if (!okFirst || (reread && reread.kind !== "keep_pending")) {
          diverge(
            index,
            "(state)",
            "decide",
            "keep_pending",
            describeDecision(reread ?? first),
            `${d}/${s} S=${fmt(x.S)} C=${fmt(x.C)} phase=${ph}`,
          );
        }
      }
    }
  }

  // ---- step-level
  async function checkStep(
    step: { a: string; p?: Record<string, ModelValue> },
    pre: ModelState,
    post: ModelState,
    index: number,
  ): Promise<void> {
    const p = step.p ?? {};
    const d: string = p.d;
    switch (step.a) {
      case "StartRun":
      case "StartRunFor":
      case "Rerun": {
        const e = post.ob[d];
        phaseReset(d);
        results.set(d, new Map());
        const noCk = pre.ckpt[d].n === "none";
        const nf = needsFullOf(pre, d);
        const pkgFull = noCk || api.runMustBeFull(nf, CONNECTOR);
        point("runMustBeFull", [noCk, nfKeys(nf)]);
        if (pkgFull !== e.full) {
          diverge(index, step.a, "runMustBeFull", e.full, pkgFull);
        }
        try {
          api.createOutboxEntry({
            runId: `run-${e.rid}`,
            connector: CONNECTOR,
            start: null,
            userConnect: e.uc,
            full: e.full,
            observedAt: e.rid,
            spoolRef: "spool",
            checkpointCandidate: null,
            needsFull: nf,
          });
        } catch (err) {
          diverge(
            index,
            step.a,
            "createOutboxEntry",
            "accepted",
            (err as Error).message,
          );
        }
        return;
      }
      case "NewSession":
        phaseReset(d);
        return;
      case "Leave":
        // The device's outbox entry, needsFull and checkpoint are gone.
        phaseReset(d);
        results.delete(d);
        return;
      case "Decide":
        return checkDecide(p.d, p.s, pre, post, index);
      case "CtlPost": {
        const s: string = p.s;
        const e = pre.ob[d];
        const n = e.n;
        const after = post.ob[d]?.st?.[s];
        if (after === "creating" || after === "reconnecting") return; // reply lost
        const ver: number = e.g[s];
        const inserted = post.ctl[n].length > pre.ctl[n].length;
        const row = pre.ctl[n][ver - 1];
        const replay =
          !inserted && row && row.k === "A" && row.key === pre.xdev[d].key;
        phase.set(`${d}/${s}`, inserted || replay ? "after_write" : "first");
        return;
      }
      case "Plan":
      case "PlanPublish":
      case "PlanStale":
      case "PlanNoop":
        return checkPlan(step.a, p.d, p.s, pre, post, index);
      case "Post":
        return checkPost(p.d, p.s, pre, post, index);
      case "Finish":
        return checkFinish(p.d, pre, post, index);
      default:
        return;
    }
  }

  function phaseReset(d: string): void {
    for (const key of [...phase.keys()])
      if (key.startsWith(`${d}/`)) phase.delete(key);
  }

  function checkDecide(
    d: string,
    s: string,
    pre: ModelState,
    post: ModelState,
    index: number,
  ): void {
    const e = pre.ob[d];
    const x = pre.xdev[d];
    const ph = phase.get(`${d}/${s}`) ?? "first";
    phase.set(`${d}/${s}`, "first");
    const pe = post.ob[d];
    let model: string;
    if (NO_ENTRY(pe)) {
      // restated from StreamSync.tla Decide: Discard(d, ClearOnGenChange /\ S.k = "active")
      model = `discard${x.S.k === "active" ? "+clear" : ""}`;
    } else if (pe.st[s] === "decided") model = `publish:${pe.g[s]}`;
    else if (pe.st[s] === "creating") model = "create:1";
    else if (pe.st[s] === "reconnecting") model = `reconnect:${pe.g[s]}`;
    else throw new Error(`${trace.id} step ${index}: unknown Decide outcome`);
    const t: number = x.t;
    const tableSays =
      t > 0
        ? `publish:${t}`
        : t === -2
          ? "create:1"
          : t === -3
            ? "reconnect"
            : "discard";
    if (!model.startsWith(tableSays)) {
      throw new Error(
        `${trace.id} step ${index}: export says ${tableSays}, step did ${model}`,
      );
    }
    point("decide", { S: x.S, C: x.C, uc: e.uc, full: e.full, ph });
    const got = api.decide({
      start: toStart(x.S),
      current: toControl(x.C),
      userConnect: e.uc,
      full: e.full,
      phase: ph,
    });
    const have = describeDecision(got);
    if (have !== model) {
      diverge(
        index,
        "Decide",
        "decide",
        model,
        have,
        `${d}/${s} S=${fmt(x.S)} C=${fmt(x.C)} uc=${e.uc} full=${e.full} phase=${ph}`,
      );
    }
    if (
      got.kind === "publish" ||
      got.kind === "create" ||
      got.kind === "reconnect"
    ) {
      point("targetFor", x.S);
      const target = api.targetFor(toStart(x.S));
      if (target !== got.target) {
        diverge(index, "Decide", "targetFor", got.target, target, fmt(x.S));
      }
    }
  }

  async function checkPlan(
    action: string,
    d: string,
    s: string,
    pre: ModelState,
    post: ModelState,
    index: number,
  ): Promise<void> {
    const e = pre.ob[d];
    const n: string = e.n;
    const T: number = e.g[s];
    const rows = pre.hd[n][s] as ModelValue[];
    const top = rows.at(-1); // AckImmutable: the base version is the latest row
    const row = rowOf(rows);
    const topBuilt = row === "present" ? await toHead(n, s, top) : null;
    point("chooseBase", [row, top?.g ?? null, T]);
    const chosen = api.chooseBase(row, topBuilt?.head ?? null, T);
    const pe = post.ob[d];

    if (action === "PlanStale") {
      // The host re-reads control and decides again with phase `stale_base`
      // (ruling F1).
      phase.set(`${d}/${s}`, "stale_base");
      if (chosen.kind !== "stale_generation") {
        diverge(
          index,
          action,
          "chooseBase",
          "stale_generation",
          chosen.kind,
          `${d}/${s} T=${T} row g=${top?.g}`,
        );
      }
      return;
    }
    if (chosen.kind === "stale_generation") {
      diverge(
        index,
        action,
        "chooseBase",
        "publish",
        chosen.kind,
        `${d}/${s} T=${T} row g=${top?.g}`,
      );
      return;
    }
    const base = chosen.kind === "base" ? topBuilt! : null;

    // restated from StreamSync.tla Plan: first, seeded, rawOK
    const first =
      d === DESKTOP &&
      n === pre.seedTarget &&
      !(pre.rcpt as [string, string][]).some(([m, t]) => m === n && t === s);
    const seeded = first && T === 1;
    const emits = (e.emit as string[]).includes(s);
    const rawOK =
      d !== DESKTOP &&
      T === 1 &&
      base === null &&
      s === LEGACY_FROM &&
      pre.rawF.present &&
      (pre.rawF.id === "none" || pre.rawF.id === e.a);

    const noop = pe.st[s] === "done";
    const baseComplete = base ? base.head.complete : false;
    if (noop && !emits && !seeded) {
      // An empty spool with no seed (a stream planned only for the seed
      // that gets none, or a stream the source emitted nothing for): the
      // host skips it and the receipt records "skipped" (§2.6, §2.9).
      // No package function decides this; isNoop needs a base.
      modelOnly("empty spool with no seed counts as no-op");
      return noopEffect();
    }

    const runLines: Line[] = emits
      ? (e.pks as string[]).map((pk) => toLine([pk, e.rid, e.a, "run"]))
      : [];
    // restated from StreamSync.tla Plan: seedLines == {<<p, 0, "desk", "seed">> : p \in PK}
    const seedLines: Line[] = seeded
      ? pkConstant.map((pk) => toLine([pk, 0, "desk", "seed"]))
      : [];
    const baseLines = base ? await headLines(base) : [];
    // restated from StreamSync.tla Plan: complete == ~e.sw /\ (full \/ base.complete \/ seeded)
    const pkgComplete = api.headComplete({
      full: e.full,
      baseComplete,
      seedMerged: seeded,
    });
    if (e.sw && pkgComplete)
      modelOnly(
        "account switch with a reused checkpoint publishes complete:false",
      );
    const complete = !e.sw && pkgComplete;

    const options = rawOK ? [false, true] : [false];
    const want = noop
      ? null
      : {
          lines: new Set((pe.req[s].h.lines as ModelLine[]).map(lineKey)),
          complete: pe.req[s].h.complete as boolean,
        };
    let matched = false;
    let last = "";
    for (const useRaw of options) {
      const rawLines = useRaw
        ? (pre.rawF.lines as ModelLine[]).map(toLine)
        : [];
      const merged = await reduceLines([
        baseLines,
        seedLines,
        rawLines,
        runLines,
      ]);
      const lines = new Set(
        merged.winners.map((w) => fromLine(pkg.decodeLine(w.text))),
      );
      const isNoop = api.isNoop(base?.head ?? null, merged.parts, complete);
      point("merge+isNoop", [
        rows.length,
        top ?? null,
        T,
        e.rid,
        e.pks,
        emits,
        seeded,
        useRaw,
        complete,
      ]);
      if (noop) {
        if (isNoop) matched = true;
        else last = `publish (complete=${complete}, ${lines.size} lines)`;
      } else if (
        !isNoop &&
        sameSet(lines, want!.lines) &&
        complete === want!.complete
      ) {
        matched = true;
      } else {
        last = isNoop
          ? "noop"
          : `publish ${[...lines].sort().join(" ")} complete=${complete}`;
      }
    }
    if (!matched) {
      diverge(
        index,
        action,
        "chooseBase+merge+isNoop",
        noop
          ? "noop"
          : `publish ${[...want!.lines].sort().join(" ")} complete=${want!.complete}`,
        last,
        `${d}/${s} T=${T} base=${chosen.kind} row g=${top?.g ?? "-"}`,
      );
    }

    if (noop) return noopEffect();

    // needsFull at publish time (§2.7): the model applies complete:false
    // when the request is persisted; the package's afterCommit gives the set.
    const h = pe.req[s].h;
    if (!h.complete) {
      const effect = api.afterCommit(needsFullOf(pre, d), {
        connector: CONNECTOR,
        ns: nsHex(n),
        stream: s,
        complete: false,
        runFull: e.full,
      });
      point("afterCommit", ["incomplete", nfKeys(needsFullOf(pre, d)), n, s]);
      const modelSet = nfKeys(needsFullOf(post, d));
      const modelClear = pre.ckpt[d].n !== "none" && post.ckpt[d].n === "none";
      if (nfKeys(effect.needsFull) !== modelSet) {
        diverge(
          index,
          action,
          "afterCommit.needsFull",
          modelSet,
          nfKeys(effect.needsFull),
        );
      }
      if (pre.ckpt[d].n !== "none" && effect.clearCheckpoint !== modelClear) {
        diverge(
          index,
          action,
          "afterCommit.clearCheckpoint",
          modelClear,
          effect.clearCheckpoint,
        );
      }
    }
    return;

    /** A no-op counts as committed at T with the base's `complete` (Q9). */
    function noopEffect(): void {
      results
        .get(d)
        ?.set(s, { state: "noop", generation: T, complete: baseComplete });
      if (base === null || baseComplete) return;
      if (design["NoOpNeedsFull"] !== "TRUE") {
        modelOnly("no-op onto a complete:false base (model without Q9)");
        return;
      }
      // Q9: a no-op onto a complete:false base has the effect of committing
      // that head again: needsFull set, checkpoint cleared (afterCommit).
      const effect = api.afterCommit(needsFullOf(pre, d), {
        connector: CONNECTOR,
        ns: nsHex(n),
        stream: s,
        complete: false,
        runFull: e.full,
      });
      point("afterCommit.noop", [nfKeys(needsFullOf(pre, d)), n, s]);
      const modelSet = nfKeys(needsFullOf(post, d));
      const modelClear = pre.ckpt[d].n !== "none" && post.ckpt[d].n === "none";
      if (nfKeys(effect.needsFull) !== modelSet) {
        diverge(
          index,
          action,
          "afterCommit.needsFull",
          modelSet,
          nfKeys(effect.needsFull),
          "no-op",
        );
      }
      if (pre.ckpt[d].n !== "none" && effect.clearCheckpoint !== modelClear) {
        diverge(
          index,
          action,
          "afterCommit.clearCheckpoint",
          modelClear,
          effect.clearCheckpoint,
          "no-op",
        );
      }
    }
  }

  function checkPost(
    d: string,
    s: string,
    pre: ModelState,
    post: ModelState,
    index: number,
  ): void {
    const e = pre.ob[d];
    const pe = post.ob[d];
    if (pe?.st?.[s] !== "done") return; // 409 (re-plan) or lost reply
    const h = e.req[s].h;
    results
      .get(d)
      ?.set(s, { state: "committed", generation: h.g, complete: h.complete });
    const effect = api.afterCommit(needsFullOf(pre, d), {
      connector: CONNECTOR,
      ns: nsHex(e.n),
      stream: s,
      complete: h.complete,
      runFull: e.full,
    });
    point("afterCommit", [
      h.complete,
      e.full,
      nfKeys(needsFullOf(pre, d)),
      e.n,
      s,
    ]);
    const modelSet = nfKeys(needsFullOf(post, d));
    if (nfKeys(effect.needsFull) !== modelSet) {
      diverge(
        index,
        "Post",
        "afterCommit.needsFull",
        modelSet,
        nfKeys(effect.needsFull),
      );
    }
  }

  function checkFinish(
    d: string,
    pre: ModelState,
    post: ModelState,
    index: number,
  ): void {
    const e = pre.ob[d];
    const runResults = results.get(d) ?? new Map<string, Result>();
    const streams: Record<string, StreamRunResult> = {};
    for (const [s, state] of Object.entries<string>(e.st)) {
      if (state === "none") continue;
      const r = runResults.get(s);
      if (!r)
        throw new Error(`${trace.id} step ${index}: no result for ${d}/${s}`);
      streams[s] = r;
    }
    // restated from StreamSync.tla Finish: rcptOk
    const rcptOk =
      !(d === DESKTOP && e.n === pre.seedTarget) ||
      Object.keys(e.st).every((s) =>
        (pre.rcpt as [string, string][]).some(([m, t]) => m === e.n && t === s),
      );
    const control = toControl(pre.xdev[d].C);
    point("checkpointDecision", [e.T, streams, pre.xdev[d].C, !rcptOk]);
    const got = api.checkpointDecision({
      target: e.T,
      streams,
      control,
      seedReceiptsPending: !rcptOk,
    });
    const saved =
      post.ckpt[d].rid === e.rid &&
      post.ckpt[d].n === e.n &&
      post.ckpt[d].g === e.T;
    const model = saved ? `save:${e.T}` : "skip";
    const have = got.kind === "save" ? `save:${got.generation}` : "skip";
    if (model !== have) {
      diverge(
        index,
        "Finish",
        "checkpointDecision",
        model,
        got.kind === "save" ? have : `skip ${got.reason}`,
        `${d} T=${e.T} control=${fmt(pre.xdev[d].C)} streams=${JSON.stringify(streams)} incomp=${e.incomp}`,
      );
    }
  }
}

function sameSet(a: Set<string>, b: Set<string>): boolean {
  return a.size === b.size && [...a].every((x) => b.has(x));
}

function fmt(st: { k: string; g: number }): string {
  return st.k === "absent" || st.k === "unknown" ? st.k : `${st.k}(${st.g})`;
}

export function describeDecision(d: Decision): string {
  switch (d.kind) {
    case "publish":
      return `publish:${d.target}`;
    case "create":
      return "create:1";
    case "reconnect":
      return `reconnect:${d.target}`;
    case "reread":
      return "reread";
    case "keep_pending":
      return `keep_pending:${d.reason}`;
    case "discard":
      return `discard${d.clearCheckpoints ? "+clear" : ""}`;
  }
}

/** Replay a whole corpus. */
export async function replayCorpus(
  text: string,
  impl: Partial<DecisionApi> = {},
): Promise<{
  meta: CorpusMeta;
  stats: ReplayStats;
  divergences: Divergence[];
  traces: CorpusTrace[];
}> {
  const { meta, traces } = parseCorpus(text);
  const stats: ReplayStats = {
    traces: 0,
    steps: 0,
    points: {},
    distinct: {},
    modelOnly: {},
  };
  const divergences: Divergence[] = [];
  for (const trace of traces) {
    if (!trace.states) continue;
    await replayTrace(
      trace,
      pkConstant(meta, trace),
      { ...pkg, ...impl },
      stats,
      divergences,
      meta.model.design ?? {},
    );
  }
  return { meta, stats, divergences, traces };
}

function pkConstant(meta: CorpusMeta, trace: CorpusTrace): string[] {
  const text = String(meta.profiles[trace.profile]?.["PK"] ?? "");
  return text
    .replace(/[{}\s]/g, "")
    .split(",")
    .filter(Boolean);
}
