/**
 * The own-writes state table (own-writes-state-table.md), one case per row.
 *
 * Every row drives the real `StreamSyncWriter` and reads through the writer's
 * own overlay source, so the plan the reader reads is the one the writer
 * publishes with. For every row:
 *
 * - the owner's records (payload included), completeness and withheld runs,
 *   before the writer publishes and after it publishes until stable and the
 *   reader imports the result;
 * - what a grant reads at the same two points: published data only, no
 *   marker; the owner never reads fewer records than a grant;
 * - the plan's predicted head after each step equals the head the writer
 *   registers, pass after pass, until no pass changes anything, and every
 *   registry publication holds the lines the plan predicted for its step;
 * The mixed legacy-file/overlay HTTP response is retired; these cases retain
 * the writer/fold oracle independently of HTTP account-mode routing.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  compareStamp,
  SEED_OBSERVED_AT,
  SEED_RUN_ID,
  type Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { PlanHead, PlanStep } from "../stream-sync/publish-plan.js";
import { planHeadOf } from "./fold.js";
import type { ReadDecision } from "./service.js";
import {
  CONNECTOR,
  Rig,
  type RunSpec,
  type SeedRows,
  type StreamSpec,
} from "./writer-rig.js";

type Rec = Record<string, unknown>;

const run = (spec: Partial<RunSpec> & { runId: string }): RunSpec => ({
  key: "id",
  version: "1.0.0",
  rows: [],
  full: false,
  ...spec,
});

const A = { id: "a", v: 1 };
const B = { id: "b", v: 1 };
const C = { id: "c", v: 1 };
const D = { id: "d", v: 1 };
const X = { id: "x", v: 1 };
const Z = { id: "z", v: 1 };
const A2 = { id: "a", v: 2 };
const U1 = { uid: "u1" };
const SEED = { id: "seed" };

const baseRun = (over: Partial<RunSpec> = {}): RunSpec =>
  run({ runId: "base", full: true, rows: [A, B], ...over });
const AB = [A, B];

const CUR = "connector_update_required";

/** One read: records (null = no view body), completeness, withheld `runId:reason`. */
interface Read {
  readonly rows: readonly Rec[] | null;
  /** Response completeness: a view is complete; null when no view serves. */
  readonly complete: boolean | null;
  readonly withheld: readonly string[];
}

interface Row {
  readonly id: string;
  readonly title: string;
  readonly connector?: string;
  readonly scope?: string;
  readonly seed?: SeedRows;
  /** Published and imported before the case starts. */
  readonly base: readonly RunSpec[];
  readonly runs: readonly RunSpec[];
  /** The writer publishes the runs once before the owner reads; the reader has not imported them. */
  readonly published?: boolean;
  readonly expect: {
    readonly before: Read;
    /** After one publish pass, before the reader imports anything. */
    readonly published?: Read;
    /** After the writer publishes until stable and the reader imports. */
    readonly after: Read;
    /** What a grant reads, before and after. */
    readonly grant: readonly [readonly Rec[] | null, readonly Rec[] | null];
    /** Distinct unpublished runs; the pending marker when the legacy body answers. */
    readonly pending: number;
    /** The registered head of the read's stream at the end. */
    readonly head?: {
      readonly key: string;
      readonly version: string;
      readonly complete: boolean;
    };
  };
}

const read = (
  rows: readonly Rec[] | null,
  complete: boolean | null,
  withheld: readonly string[] = [],
): Read => ({ rows, complete, withheld });

const ROWS: readonly Row[] = [
  {
    id: "S1",
    title: "same key, a new row",
    base: [baseRun()],
    runs: [run({ runId: "r1", rows: [C] })],
    expect: {
      before: read([A, B, C], true),
      after: read([A, B, C], true),
      grant: [AB, [A, B, C]],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "S2",
    title: "a run with no record and the same profile: a no-op",
    base: [baseRun()],
    runs: [run({ runId: "r1" })],
    expect: {
      before: read(AB, true),
      after: read(AB, true),
      grant: [AB, AB],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "S3",
    title: "a newer connector changes the key, full run",
    base: [baseRun()],
    runs: [
      run({
        runId: "r1",
        key: "uid",
        version: "2.0.0",
        full: true,
        rows: [U1],
      }),
    ],
    expect: {
      before: read(AB, false, ["r1:key_reset_pending"]),
      after: read([U1], true),
      grant: [AB, [U1]],
      pending: 1,
      head: { key: "uid", version: "2.0.0", complete: true },
    },
  },
  {
    id: "S4",
    title: "a newer connector changes the key, partial run",
    base: [baseRun()],
    runs: [run({ runId: "r1", key: "uid", version: "2.0.0", rows: [U1] })],
    expect: {
      before: read(AB, false, ["r1:key_reset_pending"]),
      // The imported head is incomplete: a grant has no view; the owner keeps
      // reading its rows after the run is acknowledged and retired.
      after: read([U1], false),
      grant: [AB, null],
      pending: 1,
      head: { key: "uid", version: "2.0.0", complete: false },
    },
  },
  {
    id: "S5",
    title: "a run resumed from another namespace's checkpoint",
    base: [baseRun()],
    runs: [run({ runId: "r1", otherNamespace: true, rows: [C] })],
    expect: {
      before: read([A, B, C], false),
      after: read([A, B, C], false),
      grant: [AB, null],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: false },
    },
  },
  {
    id: "S6",
    title: "an older connector meets a changed key: the writer refuses",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({
        runId: "r1",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [U1],
      }),
    ],
    expect: {
      before: read(AB, true, [`r1:${CUR}`]),
      after: read(AB, true, [`r1:${CUR}`]),
      grant: [AB, AB],
      pending: 1,
      head: { key: "id", version: "2.0.0", complete: true },
    },
  },
  {
    id: "S7",
    title: "A merges, B changes the key at the floor, C merges",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({ runId: "rA", version: "2.0.0", rows: [X] }),
      run({
        runId: "rB",
        key: "uid",
        version: "2.0.0",
        full: true,
        rows: [U1],
      }),
      run({ runId: "rC", version: "2.0.0", full: true, rows: [Z] }),
    ],
    expect: {
      // The floor stays 2.0.0, so B is refused; once C commits, B is older
      // than the newest commit and can never commit.
      before: read([A, B, X, Z], true, [`rB:${CUR}`]),
      after: read([A, B, X, Z], true, ["rB:out_of_order"]),
      grant: [AB, [A, B, X, Z]],
      pending: 3,
      head: { key: "id", version: "2.0.0", complete: true },
    },
  },
  {
    id: "S8",
    title: "the key changes and changes back",
    base: [baseRun()],
    runs: [
      run({
        runId: "r1",
        key: "uid",
        version: "2.0.0",
        full: true,
        rows: [U1],
      }),
      run({ runId: "r2", version: "3.0.0", full: true, rows: [C] }),
    ],
    expect: {
      before: read(AB, false, [
        "r1:key_reset_pending",
        "r2:earlier_run_pending",
      ]),
      after: read([C], true),
      grant: [AB, [C]],
      pending: 2,
      head: { key: "id", version: "3.0.0", complete: true },
    },
  },
  {
    id: "S9",
    title: "an older empty run is refused, then an older changed key",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({ runId: "r1", version: "1.0.0" }),
      run({
        runId: "r2",
        key: "uid",
        version: "1.5.0",
        full: true,
        rows: [U1],
      }),
    ],
    expect: {
      before: read(AB, true, [`r1:${CUR}`, `r2:${CUR}`]),
      after: read(AB, true, [`r1:${CUR}`, `r2:${CUR}`]),
      grant: [AB, AB],
      pending: 2,
      head: { key: "id", version: "2.0.0", complete: true },
    },
  },
  {
    id: "S10",
    title: "a newer empty run raises the floor above a later changed key",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({ runId: "r1", version: "3.0.0" }),
      run({
        runId: "r2",
        key: "uid",
        version: "2.5.0",
        full: true,
        rows: [U1],
      }),
    ],
    expect: {
      before: read(AB, true, [`r2:${CUR}`]),
      after: read(AB, true, [`r2:${CUR}`]),
      grant: [AB, AB],
      pending: 2,
      head: { key: "id", version: "3.0.0", complete: true },
    },
  },
  {
    id: "S11",
    title: "a run with a row, then a changed key above the floor",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({ runId: "r1", version: "3.0.0", rows: [C] }),
      run({
        runId: "r2",
        key: "uid",
        version: "3.5.0",
        full: true,
        rows: [U1],
      }),
    ],
    expect: {
      before: read([A, B, C], false, ["r2:key_reset_pending"]),
      after: read([U1], true),
      grant: [AB, [U1]],
      pending: 2,
      head: { key: "uid", version: "3.5.0", complete: true },
    },
  },
  {
    id: "S12",
    title: "a run from another namespace's checkpoint updates a base row",
    base: [baseRun()],
    runs: [run({ runId: "r1", otherNamespace: true, rows: [A2] })],
    expect: {
      before: read([A2, B], false),
      after: read([A2, B], false),
      grant: [AB, null],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: false },
    },
  },
  {
    id: "S13",
    title: "an ordinary incremental run from a newer connector",
    base: [baseRun()],
    runs: [run({ runId: "r1", version: "2.0.0", rows: [C] })],
    expect: {
      before: read([A, B, C], true),
      after: read([A, B, C], true),
      grant: [AB, [A, B, C]],
      pending: 1,
      head: { key: "id", version: "2.0.0", complete: true },
    },
  },
  {
    id: "S14",
    title: "an incomplete imported base and a refused full run",
    base: [baseRun({ version: "2.0.0", full: false, otherNamespace: true })],
    runs: [
      run({
        runId: "r1",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [U1],
      }),
    ],
    expect: {
      before: read(AB, false, [`r1:${CUR}`]),
      after: read(AB, false, [`r1:${CUR}`]),
      grant: [null, null],
      pending: 1,
      head: { key: "id", version: "2.0.0", complete: false },
    },
  },
  {
    id: "S15",
    title: "a seed merged at the first publish",
    base: [],
    seed: { key: "id", version: "1.0.0", rows: [SEED] },
    runs: [run({ runId: "r1", rows: [C] })],
    expect: {
      before: read(null, null, ["r1:seed_unresolved"]),
      after: read([C, SEED], true),
      grant: [null, [C, SEED]],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "A2",
    title: "A empty at the floor, B changes the key at it, C merges a row",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({ runId: "rA", version: "2.0.0" }),
      run({
        runId: "rB",
        key: "uid",
        version: "2.0.0",
        full: true,
        rows: [U1],
      }),
      run({ runId: "rC", version: "2.0.0", full: true, rows: [Z] }),
    ],
    expect: {
      before: read([A, B, Z], true, [`rB:${CUR}`]),
      after: read([A, B, Z], true, ["rB:out_of_order"]),
      grant: [AB, [A, B, Z]],
      pending: 3,
      head: { key: "id", version: "2.0.0", complete: true },
    },
  },
  {
    id: "A3",
    title: "as A2, C empty too",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({ runId: "rA", version: "2.0.0" }),
      run({
        runId: "rB",
        key: "uid",
        version: "2.0.0",
        full: true,
        rows: [U1],
      }),
      run({ runId: "rC", version: "2.0.0", full: true }),
    ],
    expect: {
      before: read(AB, true, [`rB:${CUR}`]),
      after: read(AB, true, ["rB:out_of_order"]),
      grant: [AB, AB],
      pending: 3,
      head: { key: "id", version: "2.0.0", complete: true },
    },
  },
  {
    id: "B2",
    title: "the key changes, then changes back at an equal version",
    base: [baseRun({ version: "2.0.0" })],
    runs: [
      run({
        runId: "rX",
        key: "uid",
        version: "3.0.0",
        full: true,
        rows: [U1],
      }),
      run({ runId: "rY", version: "3.0.0", full: true, rows: [C] }),
    ],
    expect: {
      before: read(AB, false, ["rX:key_reset_pending", `rY:${CUR}`]),
      after: read([U1], true, [`rY:${CUR}`]),
      grant: [AB, [U1]],
      pending: 2,
      head: { key: "uid", version: "3.0.0", complete: true },
    },
  },
  {
    id: "C3",
    title: "a full stream read from another namespace's checkpoint",
    base: [baseRun()],
    runs: [
      run({
        runId: "rX",
        otherNamespace: true,
        fullStream: true,
        rows: [C],
      }),
    ],
    expect: {
      before: read([A, B, C], false),
      after: read([A, B, C], false),
      grant: [AB, null],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: false },
    },
  },
  {
    id: "D2",
    title: "an empty same-key run from another namespace's checkpoint",
    base: [baseRun()],
    runs: [run({ runId: "rX", otherNamespace: true })],
    expect: {
      before: read(AB, false),
      after: read(AB, false),
      grant: [AB, null],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: false },
    },
  },
  {
    id: "D3",
    title: "an empty full run from a newer connector with a changed key",
    base: [baseRun()],
    runs: [run({ runId: "rX", key: "uid", version: "2.0.0", full: true })],
    expect: {
      before: read(AB, false, ["rX:key_reset_pending"]),
      after: read([], true),
      grant: [AB, []],
      pending: 1,
      head: { key: "uid", version: "2.0.0", complete: true },
    },
  },
  {
    id: "D4",
    title: "an empty full run from an older connector with a changed key",
    base: [baseRun({ version: "2.0.0" })],
    runs: [run({ runId: "rX", key: "uid", version: "1.0.0", full: true })],
    expect: {
      before: read(AB, true, [`rX:${CUR}`]),
      after: read(AB, true, [`rX:${CUR}`]),
      grant: [AB, AB],
      pending: 1,
      head: { key: "id", version: "2.0.0", complete: true },
    },
  },
  {
    id: "D5",
    title: "an empty full run completes an incomplete base",
    base: [baseRun({ full: false })],
    runs: [run({ runId: "rX", full: true })],
    expect: {
      before: read(AB, true),
      after: read(AB, true),
      grant: [null, AB],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "N1",
    title: "no imported base, a full run",
    base: [],
    runs: [run({ runId: "r1", full: true, rows: [C] })],
    expect: {
      before: read([C], true),
      after: read([C], true),
      grant: [null, [C]],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "D6",
    title: "a run whose every row loses to a newer head from another device",
    base: [baseRun({ otherDevice: true, at: 5000 })],
    runs: [run({ runId: "rX", at: 500, rows: [{ id: "a", v: 0 }] })],
    expect: {
      // The plan predicts the head that stays; the writer records a no-op.
      before: read(AB, true),
      after: read(AB, true),
      grant: [AB, AB],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "P2",
    title: "a published no-op the reader has not imported",
    // Another device's incomplete head: after an incomplete commit of its
    // own, this writer accepts only full runs (needsFull, §2.4).
    base: [baseRun({ full: false, otherDevice: true })],
    runs: [run({ runId: "rP" })],
    published: true,
    expect: {
      before: read(AB, false),
      after: read(AB, false),
      grant: [null, null],
      pending: 0,
      head: { key: "id", version: "1.0.0", complete: false },
    },
  },
  {
    id: "E2",
    title: "no intake record, and a seed merged at the first publish",
    base: [],
    seed: { key: "id", version: "1.0.0", rows: [SEED] },
    runs: [run({ runId: "rE" })],
    expect: {
      before: read(null, null, ["rE:seed_unresolved"]),
      after: read([SEED], true),
      grant: [null, [SEED]],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "E3",
    title: "a seed-only stream the first publish adds",
    base: [],
    seed: { key: "id", version: "1.0.0", rows: [SEED] },
    runs: [run({ runId: "rE", stream: "other", rows: [C] })],
    expect: {
      // The overlay does not list a seed-only stream: no rows, no marker
      // before publish (a contract boundary, not a lost row).
      before: read(null, null),
      after: read([SEED], true),
      grant: [null, [SEED]],
      pending: 0,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "E4",
    title:
      "a seed-only stream the first publish adds, then a run that changes its key at the seed's version",
    base: [],
    seed: { key: "uid", version: "3.0.0", rows: [{ uid: "s1" }] },
    runs: [
      run({ runId: "rA", stream: "other", version: "3.0.0", rows: [C] }),
      run({
        runId: "rB",
        version: "3.0.0",
        full: true,
        rows: [D],
      }),
    ],
    expect: {
      before: read(null, null, ["rB:seed_unresolved"]),
      // A's publish committed the seed on `items` (key uid, 3.0.0); the
      // writer now refuses B. The reader has not imported that head: the
      // seed rows are not shown, and neither is B.
      published: read(null, null, ["rA:seed_pending", `rB:${CUR}`]),
      after: read([{ uid: "s1" }], true, [`rB:${CUR}`]),
      grant: [null, [{ uid: "s1" }]],
      pending: 1,
      head: { key: "uid", version: "3.0.0", complete: true },
    },
  },
  {
    id: "F1",
    title: "a same-key full run without a base row keeps it",
    base: [baseRun()],
    runs: [run({ runId: "rX", full: true, rows: [A2] })],
    expect: {
      before: read([A2, B], true),
      after: read([A2, B], true),
      grant: [AB, [A2, B]],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "V1",
    title: "the floor is the highest version registered, not the last head's",
    base: [baseRun()],
    runs: [
      run({ runId: "r1", version: "3.0.0", rows: [C] }),
      run({ runId: "r2", version: "2.0.0", rows: [D] }),
      run({
        runId: "r3",
        key: "uid",
        version: "2.5.0",
        full: true,
        rows: [U1],
      }),
    ],
    expect: {
      // r2 is older than the floor 3.0.0 r1 raised: refused, its row unpublished.
      before: read([A, B, C], true, [`r2:${CUR}`, `r3:${CUR}`]),
      after: read([A, B, C], true, [`r2:${CUR}`, `r3:${CUR}`]),
      grant: [AB, [A, B, C]],
      pending: 3,
      head: { key: "id", version: "3.0.0", complete: true },
    },
  },
  {
    id: "O1",
    title: "a run older than the stream's newest commit never commits",
    base: [baseRun()],
    runs: [run({ runId: "r1", at: 500, rows: [C] })],
    expect: {
      before: read(AB, true, ["r1:out_of_order"]),
      after: read(AB, true, ["r1:out_of_order"]),
      grant: [AB, AB],
      pending: 1,
      head: { key: "id", version: "1.0.0", complete: true },
    },
  },
  {
    id: "R1",
    title: "an empty run with a new profile re-projects the head",
    base: [baseRun()],
    runs: [run({ runId: "r1", version: "1.1.0" })],
    expect: {
      before: read(AB, true),
      after: read(AB, true),
      grant: [AB, AB],
      pending: 1,
      head: { key: "id", version: "1.1.0", complete: true },
    },
  },
  {
    id: "S16",
    title: "two streams of a legacy name: one has no run, one is refused",
    connector: "meta",
    scope: "instagram.posts",
    base: [
      baseRun({
        stream: "posts",
        runId: "basePosts",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
      baseRun({
        stream: "post_likes",
        runId: "baseLikes",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
    ],
    runs: [
      run({
        runId: "r1",
        stream: "post_likes",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [U1],
      }),
    ],
    expect: {
      before: read(null, null, [`r1:${CUR}`]),
      after: read(null, null, [`r1:${CUR}`]),
      grant: [null, null],
      pending: 1,
    },
  },
  {
    id: "S17",
    title: "two streams of a legacy name, both refused: both are reported",
    connector: "meta",
    scope: "instagram.posts",
    base: [
      baseRun({
        stream: "posts",
        runId: "basePosts",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
      baseRun({
        stream: "post_likes",
        runId: "baseLikes",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
    ],
    runs: [
      run({
        runId: "r1",
        stream: "posts",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [U1],
      }),
      run({
        runId: "r2",
        stream: "post_likes",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [{ uid: "u2" }],
      }),
    ],
    expect: {
      before: read(null, null, [`r1:${CUR}`, `r2:${CUR}`]),
      after: read(null, null, [`r1:${CUR}`, `r2:${CUR}`]),
      grant: [null, null],
      pending: 2,
    },
  },
  {
    id: "M1",
    title: "one run withheld on both streams of a legacy name",
    connector: "meta",
    scope: "instagram.posts",
    base: [
      baseRun({
        stream: "posts",
        runId: "basePosts",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
      baseRun({
        stream: "post_likes",
        runId: "baseLikes",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
    ],
    runs: [
      run({
        runId: "r1",
        stream: "posts",
        key: "uid",
        version: "1.0.0",
        full: true,
        rows: [U1],
        also: [
          {
            stream: "post_likes",
            key: "uid",
            version: "1.0.0",
            rows: [{ uid: "u2" }],
          },
        ],
      }),
    ],
    expect: {
      before: read(null, null, [`r1:${CUR}`, `r1:${CUR}`]),
      after: read(null, null, [`r1:${CUR}`, `r1:${CUR}`]),
      grant: [null, null],
      pending: 1,
    },
  },
  {
    id: "M2",
    title:
      "one run published on one stream of a legacy name, refused on the other",
    connector: "meta",
    scope: "instagram.posts",
    base: [
      baseRun({
        stream: "posts",
        runId: "basePosts",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
      baseRun({
        stream: "post_likes",
        runId: "baseLikes",
        version: "2.0.0",
        full: false,
        otherNamespace: true,
      }),
    ],
    runs: [
      run({
        runId: "r1",
        stream: "posts",
        version: "2.0.0",
        full: true,
        rows: [C],
        also: [
          {
            stream: "post_likes",
            key: "uid",
            version: "1.0.0",
            rows: [{ uid: "u2" }],
          },
        ],
      }),
    ],
    published: true,
    expect: {
      before: read(null, null, [`r1:${CUR}`, "r1:projection_unavailable"]),
      after: read(null, null, [`r1:${CUR}`]),
      grant: [null, null],
      pending: 1,
    },
  },
];

function rowScope(row: Row): string {
  return row.scope ?? `pdpp.${row.connector ?? CONNECTOR}.items`;
}

function rowStreams(row: Row): string[] {
  const names = new Set<string>();
  for (const spec of row.runs) {
    for (const s of [spec, ...(spec.also ?? [])] as StreamSpec[]) {
      names.add(s.stream ?? "items");
    }
  }
  // A seed-only stream is not in the overlay (E3): the plan does not cover it.
  return [...names].sort();
}

/** A model to break on purpose: it rewrites the lines the oracle predicts. */
interface Options {
  readonly distort?: (
    kind: "prepublished" | "seed" | "base-only",
    lines: Line[],
    stream: string,
  ) => Line[];
}

/** How many registry stream publications existed when the case started. */
const initialPublications = new WeakMap<Rig, number>();

async function open(row: Row, options: Options = {}): Promise<Rig> {
  const rig = new Rig(row.seed, row.connector);
  await rig.open();
  if (row.base.length > 0) {
    for (const spec of row.base) await rig.collect(spec);
    await rig.publish();
    await rig.sync();
  }
  // The publications of the connector's streams only: control posts are not.
  initialPublications.set(rig, (await rig.publications()).length);
  for (const spec of row.runs) await rig.collect(spec);
  if (row.published) await checkedPass(rig, row, options, "prepublished");
  return rig;
}

const canon = (records: readonly Rec[] | null): string[] | null =>
  records ? records.map((r) => JSON.stringify(r)).sort() : null;

async function records(decision: ReadDecision): Promise<Rec[] | null> {
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return null;
  }
  const envelope = JSON.parse(await new Response(decision.body).text()) as {
    data: { records: Rec[] };
  };
  return envelope.data.records;
}

function withheldOf(decision: ReadDecision): string[] {
  const notes = decision as {
    withheld?: readonly { runId: string; reason: string }[];
  };
  return (notes.withheld ?? []).map((w) => `${w.runId}:${w.reason}`).sort();
}

function resolve(
  rig: Rig,
  row: Row,
  input: {
    owner: boolean;
    legacyFile?: boolean;
    connection?: string;
    cursor?: string;
  },
) {
  return rig.service.resolve({
    scope: rowScope(row),
    connection: input.connection ?? null,
    cursor: input.cursor ?? null,
    legacyFile: input.legacyFile ?? false,
    isOwnerView: input.owner,
  });
}

interface Observed {
  readonly read: Read;
  readonly kind: ReadDecision["kind"];
  readonly grant: readonly Rec[] | null;
}

async function observe(rig: Rig, row: Row): Promise<Observed> {
  const owner = await resolve(rig, row, { owner: true });
  const grant = await resolve(rig, row, { owner: false });
  expect(withheldOf(grant)).toEqual([]);
  expect((grant as { pending?: unknown }).pending ?? null).toBeNull();
  return {
    kind: owner.kind,
    read: {
      rows: await records(owner),
      complete:
        owner.kind === "view"
          ? true
          : owner.kind === "local_pending"
            ? owner.complete
            : null,
      withheld: withheldOf(owner),
    },
    grant: await records(grant),
  };
}

const keyOf = (r: Rec): string => String(r["id"] ?? r["uid"]);

/**
 * The owner never reads fewer records than a grant of the same stream: every
 * key a grant reads, the owner reads (its payload may be newer).
 */
function expectOwnerCoversGrant(seen: Observed): void {
  const owner = new Set((seen.read.rows ?? []).map(keyOf));
  for (const r of seen.grant ?? []) expect(owner).toContain(keyOf(r));
}

function expectRead(seen: Observed, want: Read): void {
  expect(canon(seen.read.rows)).toEqual(canon(want.rows));
  expect(seen.read.complete).toBe(want.complete);
  expect(seen.read.withheld).toEqual([...want.withheld].sort());
}

const sameAs = (predicted: PlanHead, registered: PlanHead): PlanHead =>
  predicted.generation === null
    ? { ...predicted, generation: registered.generation }
    : predicted;

async function plans(
  rig: Rig,
  row: Row,
  heads: Map<string, PlanHead | null>,
): Promise<Map<string, PlanStep[]>> {
  const snapshot = await rig.overlay.snapshot(row.connector ?? CONNECTOR);
  try {
    const out = new Map<string, PlanStep[]>();
    for (const stream of modelStreams(row)) {
      const ids = snapshot.runs
        .filter((r) => r.streams.some((s) => s.name === stream))
        .map((r) => r.runId);
      out.set(
        stream,
        snapshot.plan(rig.ns, stream, heads.get(stream) ?? null, ids),
      );
    }
    return out;
  } finally {
    snapshot.release();
  }
}

async function registered(rig: Rig, stream: string): Promise<PlanHead | null> {
  const head = await rig.registeredHead(stream);
  return head && planHeadOf(head);
}

// ---------------------------------------------------------------------------
// The differential oracle: what the registry holds after every publication,
// predicted from the plan and the collected rows alone.

/** Every stream the case touches: the runs', the base's and the seed's. */
function modelStreams(row: Row): string[] {
  const base = row.base.flatMap((spec) =>
    ([spec, ...(spec.also ?? [])] as StreamSpec[]).map(
      (s) => s.stream ?? "items",
    ),
  );
  return [
    ...new Set([
      ...rowStreams(row),
      ...base,
      ...(row.seed ? [row.seed.stream ?? "items"] : []),
    ]),
  ].sort();
}

const sameLines = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

const lineKey = (l: Line): string => JSON.stringify([l.o, l.r, l.v]);
const canonLines = (lines: readonly Line[]): string[] =>
  lines.map(lineKey).sort();

/** The greatest (o, r) per primary key wins; the later line wins a tie. */
function reduceLines(
  lines: readonly Line[],
  primaryKey: readonly string[],
): Line[] {
  const winners = new Map<string, Line>();
  for (const line of lines) {
    const key = JSON.stringify(primaryKey.map((f) => line.v[f]));
    const held = winners.get(key);
    if (!held || compareStamp(line, held) >= 0) winners.set(key, line);
  }
  return [...winners.values()];
}

/** The lines the newest publication of `stream` holds in the first `count` posts. */
async function publishedLines(
  rig: Rig,
  stream: string,
  count = Infinity,
): Promise<Line[]> {
  const pubs = (await rig.publications()).slice(0, count);
  return pubs.filter((p) => p.stream === stream).at(-1)?.lines ?? [];
}

/** The collected rows of `runId` on `stream`, stamped as the writer stamps them. */
function runLines(rig: Rig, row: Row, runId: string, stream: string): Line[] {
  const spec = [...row.base, ...row.runs].find((r) => r.runId === runId);
  if (!spec) return [];
  const streams = [spec, ...(spec.also ?? [])] as StreamSpec[];
  return streams
    .filter((s) => (s.stream ?? "items") === stream)
    .flatMap((s) =>
      s.rows.map((v) => ({ o: rig.observedAt(runId), r: runId, v }) as Line),
    );
}

/**
 * The lines a plan step leaves: the head the plan started from (when it
 * keeps it), the seed (when a publish merged it) and each run's rows.
 */
function modelLines(
  rig: Rig,
  row: Row,
  stream: string,
  step: PlanStep,
  start: readonly Line[],
): Line[] {
  const lines: Line[] = [];
  if (step.rows.fromHead) lines.push(...start);
  if (step.rows.seed && row.seed && (row.seed.stream ?? "items") === stream) {
    for (const v of row.seed.rows) {
      lines.push({ o: SEED_OBSERVED_AT, r: SEED_RUN_ID, v } as Line);
    }
  }
  for (const runId of step.rows.runs) {
    lines.push(...runLines(rig, row, runId, stream));
  }
  return reduceLines(lines, step.head!.primaryKey);
}

/** One publication the oracle predicts: its head and the lines it holds. */
interface Expected {
  readonly head: PlanHead;
  readonly lines: string[];
}

const distorted = (
  options: Options,
  kind: "prepublished" | "seed" | "base-only",
  lines: Line[],
  stream: string,
): Line[] => options.distort?.(kind, lines, stream) ?? lines;

const sameHeadFields = (a: PlanHead, b: PlanHead): boolean =>
  a.generation === b.generation &&
  a.complete === b.complete &&
  a.profile.key === b.profile.key &&
  a.profile.version === b.profile.version &&
  a.primaryKey.join("\n") === b.primaryKey.join("\n");

/** The run and stream spec a collected run's stream came from. */
function specOf(
  row: Row,
  runId: string,
  stream: string,
): { run: RunSpec; s: StreamSpec } | undefined {
  const run = [...row.base, ...row.runs].find((r) => r.runId === runId);
  const s = run
    ? ([run, ...(run.also ?? [])] as StreamSpec[]).find(
        (x) => (x.stream ?? "items") === stream,
      )
    : undefined;
  return run && s ? { run, s } : undefined;
}

/**
 * The explicit seed-admission input (§2.9): the first publish of a stream
 * the seed fills, with no head, holds the seed's rows and the rows of the
 * runs that share its key and version, under the seed's own head. It is a
 * model input, stated before the POST; it is not read from the plan the
 * writer holds after it executes.
 */
function seedAdmission(
  rig: Rig,
  row: Row,
  stream: string,
  runIds: readonly string[],
): { head: Omit<PlanHead, "generation">; lines: Line[] } | null {
  const seed = row.seed;
  if (!seed || (seed.stream ?? "items") !== stream) return null;
  const lines: Line[] = seed.rows.map(
    (v) => ({ o: SEED_OBSERVED_AT, r: SEED_RUN_ID, v }) as Line,
  );
  for (const runId of runIds) {
    const spec = specOf(row, runId, stream);
    if (spec && spec.s.key === seed.key && spec.s.version === seed.version) {
      lines.push(...runLines(rig, row, runId, stream));
    }
  }
  return {
    head: {
      primaryKey: [seed.key],
      profile: { key: null, version: seed.version },
      complete: true,
    },
    lines: reduceLines(lines, [seed.key]),
  };
}

/**
 * A run whose seed is unresolved on a stream the seed does not fill is
 * admitted with no seed: over no head it publishes its own head and rows.
 */
function plainAdmission(
  rig: Rig,
  row: Row,
  stream: string,
  runId: string,
  generation: number | null,
): Expected | null {
  const spec = specOf(row, runId, stream);
  if (!spec) return null;
  return {
    head: {
      generation,
      primaryKey: [spec.s.key],
      profile: { key: spec.s.profileKey ?? null, version: spec.s.version },
      complete: spec.run.full && !spec.run.otherNamespace,
    },
    lines: canonLines(
      reduceLines(runLines(rig, row, runId, stream), [spec.s.key]),
    ),
  };
}

/**
 * Once the writer is stable, the newest publication of every stream holds
 * exactly the lines the plan, from the head the case started with, predicts:
 * the streams the runs name, the streams only the seed fills, the streams
 * only the base published, and the runs published before the case began.
 */
async function expectRegistryMatchesPlan(
  rig: Rig,
  row: Row,
  options: Options,
): Promise<void> {
  const initial = initialPublications.get(rig) ?? 0;
  const snapshot = await rig.overlay.snapshot(row.connector ?? CONNECTOR);
  try {
    const publications = await rig.publications();
    for (const stream of modelStreams(row)) {
      const label = `${row.id} ${stream} registry`;
      const before = publications
        .slice(0, initial)
        .filter((p) => p.stream === stream);
      const start = before.at(-1)?.lines ?? [];
      const startHead = before.at(-1)?.head ?? null;
      const ids = snapshot.runs
        .filter((r) => r.streams.some((s) => s.name === stream))
        .map((r) => r.runId);
      const steps = snapshot.plan(
        rig.ns,
        stream,
        startHead && planHeadOf(startHead),
        ids,
      );
      const last = steps
        .filter(
          (s) => s.decision.kind === "publish" || s.decision.kind === "noop",
        )
        .at(-1);
      const want = last
        ? modelLines(rig, row, stream, last, start)
        : distorted(options, "base-only", start, stream);
      const got = await publishedLines(rig, stream);
      expect(canonLines(got), label).toEqual(canonLines(want));
      // The head the registry holds is the last step's, or the base's.
      const held = await registered(rig, stream);
      const wantHead = last ? last.head : startHead && planHeadOf(startHead);
      expect(
        held && wantHead && sameAs(wantHead, held),
        `${label} head`,
      ).toEqual(held);
    }
  } finally {
    snapshot.release();
  }
}

/**
 * One publish pass, checked. Before it, the plan predicts every step from the
 * registered head, and a seed admission is predicted from its explicit input.
 * After it, every step the plan said publishes or is a no-op has run: it is
 * executed with the predicted head, or (a no-op) its run is reclaimed. Every
 * refused step carries the writer's problem. Every publication the pass
 * posted holds the head fields and the lines of one predicted step, in order,
 * and the registry holds the head of the last one. Returns whether the pass
 * changed anything.
 */
async function checkedPass(
  rig: Rig,
  row: Row,
  options: Options,
  phase: "prepublished" | "pass" = "pass",
  pass = 1,
): Promise<boolean> {
  const streams = modelStreams(row);
  const heads = new Map<string, PlanHead | null>();
  const starts = new Map<string, Line[]>();
  for (const stream of streams) {
    heads.set(stream, await registered(rig, stream));
    starts.set(stream, await publishedLines(rig, stream));
  }
  const predicted = await plans(rig, row, heads);
  const pubsBefore = (await rig.publications()).length;
  const statuses = await rig.publish();
  const executed = await plans(rig, row, heads);
  const posted = (await rig.publications()).slice(pubsBefore);
  let progressed = false;
  for (const stream of streams) {
    const label = `${row.id} ${phase} ${pass} ${stream}`;
    const after = executed.get(stream)!;
    const now = await registered(rig, stream);
    const steps = predicted.get(stream)!.filter((st) => !st.executed);
    const expected: Expected[] = [];
    let want: PlanHead | null = heads.get(stream) ?? null;
    const unresolved = steps.some(
      (st) =>
        st.decision.kind === "deferred" &&
        st.decision.reason === "seed_unresolved",
    );
    // The seed fills a stream no run names (E3) at the first admission.
    const admitting =
      steps.length === 0 &&
      [...predicted.values()].some((all) => all.some((st) => !st.executed));
    const seeded =
      want === null && (unresolved || admitting)
        ? seedAdmission(
            rig,
            row,
            stream,
            steps.map((st) => st.runId),
          )
        : null;
    if (seeded) {
      // The writer resolves the seed at admission: one publication holds it
      // and every later step is planned again from that head.
      const head = { ...seeded.head, generation: now?.generation ?? null };
      expected.push({
        head,
        lines: canonLines(distorted(options, "seed", seeded.lines, stream)),
      });
      want = head;
      progressed = true;
    } else {
      for (const step of steps) {
        const done = after.find((s) => s.runId === step.runId);
        const { decision } = step;
        if (decision.kind === "publish" || decision.kind === "noop") {
          const head = sameAs(step.head!, now ?? step.head!);
          if (done) {
            expect(done.executed, `${label} ${step.runId} executed`).toBe(true);
            expect(done.head, `${label} ${step.runId} head`).toEqual(head);
          } else {
            // Reclaimed at once: only a no-op leaves nothing to import.
            expect(statuses.find((s) => s.runId === step.runId)?.phase).toBe(
              "done",
            );
          }
          if (decision.kind === "publish") {
            const lines = modelLines(
              rig,
              row,
              stream,
              step,
              starts.get(stream)!,
            );
            expected.push({
              head,
              lines: canonLines(
                phase === "prepublished"
                  ? distorted(options, "prepublished", lines, stream)
                  : lines,
              ),
            });
          }
          want = head;
          progressed = true;
        } else if (decision.kind === "refused") {
          const status = statuses.find((s) => s.runId === step.runId);
          expect(
            status?.streams[stream]?.problem,
            `${label} ${step.runId} refused`,
          ).toBe(decision.reason);
        } else if (
          decision.reason === "seed_unresolved" &&
          want === null &&
          plainAdmission(rig, row, stream, step.runId, now?.generation ?? null)
        ) {
          const plain = plainAdmission(
            rig,
            row,
            stream,
            step.runId,
            now?.generation ?? null,
          )!;
          expected.push(plain);
          want = plain.head;
          progressed = true;
        } else {
          throw new Error(
            `${label} ${step.runId} is deferred (${decision.reason}) and no model input says how it resolves`,
          );
        }
      }
    }
    expect(now, `${label} registered head`).toEqual(want);
    // Each publication this pass posted holds one predicted step's head
    // fields and lines, in order. A step may become a no-op and post nothing.
    let from = 0;
    for (const p of posted.filter((q) => q.stream === stream)) {
      const lines = canonLines(p.lines);
      const head = planHeadOf(p.head);
      const at = expected.findIndex(
        (e, i) =>
          i >= from &&
          sameLines(e.lines, lines) &&
          sameHeadFields(e.head, head),
      );
      expect(
        at,
        `${label} a publication matches no predicted step (lines or head fields)`,
      ).toBeGreaterThanOrEqual(0);
      from = at + 1;
    }
  }
  return progressed;
}

/** Publish pass after pass until a pass executes nothing. */
async function publishUntilStable(
  rig: Rig,
  row: Row,
  options: Options = {},
): Promise<number> {
  for (let pass = 1; pass <= 6; pass += 1) {
    if (!(await checkedPass(rig, row, options, "pass", pass))) {
      await expectRegistryMatchesPlan(rig, row, options);
      return pass;
    }
  }
  throw new Error(`${row.id}: the writer did not reach a stable state`);
}

describe("own-writes state table", () => {
  for (const row of ROWS) {
    const { expect: want } = row;
    describe(`${row.id} ${row.title}`, () => {
      it("owner and grant read what the table says, before and after the writer publishes", async () => {
        const rig = await open(row);
        const before = await observe(rig, row);
        expectRead(before, want.before);
        expect(canon(before.grant)).toEqual(canon(want.grant[0]));
        expectOwnerCoversGrant(before);

        if (want.published) {
          await checkedPass(rig, row, {});
          const mid = await observe(rig, row);
          expectRead(mid, want.published);
          expectOwnerCoversGrant(mid);
        }
        await publishUntilStable(rig, row);
        await rig.sync();

        const after = await observe(rig, row);
        expectRead(after, want.after);
        expect(canon(after.grant)).toEqual(canon(want.grant[1]));
        expectOwnerCoversGrant(after);
        if (want.head) {
          const head = await rig.registeredHead("items");
          expect({
            key: head?.primaryKey.join(","),
            version: head?.profile.version,
            complete: head?.complete,
          }).toEqual(want.head);
        }
      });
    });
  }
});

describe("the oracle catches a deliberately broken model", () => {
  type Distort = NonNullable<Options["distort"]>;
  const dropFirst =
    (only: Parameters<Distort>[0], stream: string): Distort =>
    (kind, lines, name) =>
      kind === only && name === stream ? lines.slice(1) : lines;

  for (const [id, kind, stream, failure] of [
    ["M2", "prepublished", "posts", /prepublished 1 posts a publication/],
    ["E2", "seed", "items", /pass 1 items a publication matches no/],
    ["S16", "base-only", "posts", /S16 posts registry/],
  ] as const) {
    it(`${id}: a model that loses a ${kind} line fails the case`, async () => {
      const row = ROWS.find((r) => r.id === id)!;
      const distort = dropFirst(kind, stream);
      await expect(
        (async () => {
          const rig = await open(row, { distort });
          await publishUntilStable(rig, row, { distort });
        })(),
      ).rejects.toThrow(failure);
    });
  }
});

describe("a pending view's cursor pins the head it was built on", () => {
  it("is stale once another device's incomplete head with a new profile is imported", async () => {
    const row: Row = ROWS.find((r) => r.id === "S14")!;
    const rig = new Rig();
    await rig.open();
    // Another device's incomplete head; this device then reads a partial
    // view of it with its own pending run.
    await rig.collect(
      baseRun({
        version: "2.0.0",
        full: false,
        otherNamespace: true,
        otherDevice: true,
      }),
    );
    await rig.sync();
    await rig.collect(run({ runId: "r1", version: "2.0.0", rows: [C] }));
    const first = await resolve(rig, row, { owner: true });
    expect(first.kind).toBe("local_pending");
    const cursor = (first as { cursor: string }).cursor;
    expect(canon(await records(first))).toEqual(canon([A, B, C]));

    // That device publishes again with another profile (a full run: its
    // last commit was incomplete).
    await rig.collect(
      run({
        runId: "o1",
        version: "3.0.0",
        otherDevice: true,
        full: true,
        at: 9000,
        rows: [D],
      }),
    );
    await rig.sync();
    expect((await rig.registeredHead())?.profile.version).toBe("3.0.0");

    const replay = await resolve(rig, row, { owner: true, cursor });
    expect(replay.kind).toBe("cursor_stale");
    const fresh = await resolve(rig, row, { owner: true });
    expect(canon(await records(fresh))).toEqual(canon([A, B, D]));
  });
});

describe("an incomplete head's acknowledgment keeps the owner's rows", () => {
  it("the owner reads the imported rows after the run is retired, not pass", async () => {
    const row = ROWS.find((r) => r.id === "S5")!;
    const rig = await open(row);
    await publishUntilStable(rig, row);
    await rig.sync();
    const snapshot = await rig.overlay.snapshot(CONNECTOR);
    expect(snapshot.runs).toEqual([]);
    snapshot.release();
    const after = await resolve(rig, row, { owner: true });
    expect(after.kind).toBe("local_pending");
    expect((after as { complete: boolean }).complete).toBe(false);
    expect(canon(await records(after))).toEqual(canon([A, B, C]));
    // A grant has no view of an incomplete head.
    expect(await records(await resolve(rig, row, { owner: false }))).toBeNull();
  });
});

// ---------------------------------------------------------------------------

const label = (r: Rec): string => {
  const id = String(r["id"] ?? r["uid"]);
  return r["v"] !== undefined && r["v"] !== 1 ? `${id}@${String(r["v"])}` : id;
};

const rowsCell = (rows: readonly Rec[] | null): string =>
  rows === null
    ? "—"
    : rows.length === 0
      ? "∅"
      : `\`${rows.map(label).sort().join(" ")}\``;

const completeCell = (c: boolean | null): string =>
  c === null ? "—" : c ? "yes" : "no";

const withheldCell = (w: readonly string[]): string =>
  w.length === 0
    ? "none"
    : [...w]
        .sort()
        .map((x) => `\`${x}\``)
        .join(" ");

/** The table's semantic columns for `row`, as the document writes them. */
function cells(row: Row): string[] {
  const w = row.expect;
  return [
    rowsCell(w.before.rows),
    completeCell(w.before.complete),
    withheldCell(w.before.withheld),
    rowsCell(w.after.rows),
    completeCell(w.after.complete),
    withheldCell(w.after.withheld),
    rowsCell(w.grant[0]),
    rowsCell(w.grant[1]),
    String(w.pending),
  ];
}

describe("own-writes-state-table.md", () => {
  it("states every row's outcome as the test does", () => {
    const doc = readFileSync(
      new URL("./own-writes-state-table.md", import.meta.url),
      "utf8",
    );
    for (const row of ROWS) {
      const line = doc
        .split("\n")
        .find((l) => new RegExp(`^\\| ${row.id}\\s+\\|`).test(l));
      expect(line, `${row.id} has a row`).toBeDefined();
      const columns = line!
        .split("|")
        .slice(1, -1)
        .map((c) => c.trim());
      // Row | Setup | Writer does | then the semantic columns.
      expect(columns.slice(3), row.id).toEqual(cells(row));
    }
  });
});
