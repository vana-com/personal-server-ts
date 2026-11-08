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
 *   registers, pass after pass, until no pass changes anything;
 * - every API path carries the owner's markers, and none of a grant's does.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "../api/index.js";
import type { PersonalServerDataApiDeps } from "../api/index.js";
import type { PlanHead, PlanStep } from "../stream-sync/publish-plan.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
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
      before: read(null, null, [`r1:${CUR}`]),
      after: read(null, null, [`r1:${CUR}`]),
      grant: [null, null],
      pending: 1,
    },
  },
];

// ---------------------------------------------------------------------------

const BUILDER = "0x000000000000000000000000000000000000bEEF";

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

async function open(row: Row): Promise<Rig> {
  const rig = new Rig(row.seed, row.connector);
  await rig.open();
  if (row.base.length > 0) {
    for (const spec of row.base) await rig.collect(spec);
    await rig.publish();
    await rig.sync();
  }
  for (const spec of row.runs) await rig.collect(spec);
  if (row.published) await rig.publish();
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
    for (const stream of rowStreams(row)) {
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

/**
 * Publish pass after pass until a pass executes nothing. Before each pass the
 * plan predicts every step from the registered head. After it, every step the
 * plan said publishes or is a no-op has run: it is executed with the
 * predicted head, or (a no-op) its run is reclaimed. Every refused step
 * carries the writer's problem, and the registry holds the head of the last
 * step the plan predicted.
 */
async function publishUntilStable(rig: Rig, row: Row): Promise<number> {
  for (let pass = 1; pass <= 6; pass += 1) {
    const heads = new Map<string, PlanHead | null>();
    for (const stream of rowStreams(row)) {
      heads.set(stream, await registered(rig, stream));
    }
    const predicted = await plans(rig, row, heads);
    const statuses = await rig.publish();
    const executed = await plans(rig, row, heads);
    let progressed = false;
    for (const stream of rowStreams(row)) {
      const label = `${row.id} pass ${pass} ${stream}`;
      const after = executed.get(stream)!;
      const now = await registered(rig, stream);
      let want: PlanHead | null = heads.get(stream) ?? null;
      let unpredicted = false;
      for (const step of predicted.get(stream)!) {
        if (step.executed) continue;
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
          want = head;
          progressed = true;
        } else if (decision.kind === "refused") {
          const status = statuses.find((s) => s.runId === step.runId);
          expect(
            status?.streams[stream]?.problem,
            `${label} ${step.runId} refused`,
          ).toBe(decision.reason);
        } else if (done?.executed || !done) {
          // A deferred step the writer resolved in this pass (admission
          // decides the seed); the next pass's plan carries it.
          unpredicted = true;
          progressed = true;
        }
      }
      if (unpredicted) {
        const last = after.filter((s) => s.executed).at(-1);
        if (last) want = last.head;
      }
      expect(now, `${label} registered head`).toEqual(want);
    }
    if (!progressed) return pass;
  }
  throw new Error(`${row.id}: the writer did not reach a stable state`);
}

interface Api {
  readonly status: number;
  readonly source: string | null;
  readonly withheld: string | null;
  readonly complete: string | null;
  readonly pending: string | null;
  readonly bodyWithheld: string[] | null;
  readonly records: Rec[] | null;
}

async function api(
  rig: Rig,
  row: Row,
  input: { builder: boolean; file: boolean; connection?: boolean },
): Promise<Api> {
  const storage = createMemoryDataStorage();
  if (input.file) {
    const envelope = {
      version: "1.0" as const,
      scope: rowScope(row),
      collectedAt: "2026-10-01T00:00:00.000Z",
      data: { records: [{ id: "stored" }] },
    };
    const written = await storage.writeEnvelope(envelope);
    storage.insertEntry({
      fileId: null,
      path: written.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: written.sizeBytes,
    } as never);
  }
  const deps: PersonalServerDataApiDeps = {
    storage,
    streamSyncRead: rig.service,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async ({ request }: { request: Request }) =>
        request.headers.get("x-test-builder")
          ? { builder: BUILDER, grantId: "grant-1" }
          : { builder: BUILDER, grantId: "owner" },
      ),
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
  };
  const query = input.connection ? "?connection=" : "";
  const response = await handlePersonalServerDataRequest(
    new Request(`https://ps.example.com/${rowScope(row)}${query}`, {
      headers: input.builder ? { "x-test-builder": "1" } : {},
    }),
    deps,
  );
  const body = (await response.json().catch(() => null)) as {
    withheld?: { runId: string; reason: string }[];
    data?: { records?: Rec[] };
  } | null;
  return {
    status: response.status,
    source: response.headers.get("x-vana-data-source"),
    withheld: response.headers.get("x-stream-sync-withheld"),
    complete: response.headers.get("x-stream-sync-complete"),
    pending: response.headers.get("x-stream-sync-pending"),
    bodyWithheld: body?.withheld
      ? body.withheld.map((w) => `${w.runId}:${w.reason}`).sort()
      : null,
    records: body?.data?.records ?? null,
  };
}

function reasonsHeader(withheld: readonly string[]): string | null {
  if (withheld.length === 0) return null;
  return [...new Set(withheld.map((w) => w.slice(w.indexOf(":") + 1)))]
    .sort()
    .join(",");
}

const sortedHeader = (h: string | null) =>
  h === null ? null : h.split(",").sort().join(",");

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

      it("every owner response carries the markers; a grant's carries none", async () => {
        const rig = await open(row);
        const grantView = want.grant[0] !== null;
        const header = reasonsHeader(want.before.withheld);
        const plain = await api(rig, row, { builder: false, file: false });
        const filed = await api(rig, row, { builder: false, file: true });
        const named = await api(rig, row, {
          builder: false,
          file: false,
          connection: true,
        });
        for (const read of [plain, filed, named]) {
          expect(sortedHeader(read.withheld)).toBe(header);
          expect(read.bodyWithheld).toEqual(
            header === null ? null : [...want.before.withheld].sort(),
          );
        }
        if (want.before.rows === null) {
          // No view: no file is a missing body, a named connection without a
          // view is a refusal.
          expect(plain.status).toBe(404);
          expect(named.status).toBe(404);
        } else {
          expect(plain.status).toBe(200);
          expect(canon(plain.records)).toEqual(canon(want.before.rows));
          const partial = want.before.complete !== true;
          expect(plain.complete).toBe(
            partial ? String(want.before.complete) : plain.complete,
          );
        }
        if (grantView || want.before.complete === true) {
          // A grant reads the published view, not the stored body, so the
          // owner does too, whatever is pending (no legacy body over a
          // pending key reset). A complete owner view also wins (D5).
          expect(filed.source).toBe("stream-sync");
          expect(canon(filed.records)).toEqual(canon(want.before.rows));
          expect(filed.pending).toBeNull();
        } else {
          // A grant reads the stored body: so does the owner, told how many
          // runs are not published.
          expect(filed.source).toBe("legacy");
          expect(filed.records).toEqual([{ id: "stored" }]);
          expect(filed.pending).toBe(
            want.pending > 0 ? String(want.pending) : null,
          );
        }

        for (const file of [false, true]) {
          for (const connection of [false, true]) {
            const g = await api(rig, row, { builder: true, file, connection });
            expect(g.withheld).toBeNull();
            expect(g.bodyWithheld).toBeNull();
            expect(g.pending).toBeNull();
            expect(g.complete).toBeNull();
            if (file && !connection) {
              if (grantView) {
                expect(canon(g.records)).toEqual(canon(want.grant[0]));
              } else {
                expect(g.records).toEqual([{ id: "stored" }]);
              }
            }
          }
        }
      });
    });
  }
});

// ---------------------------------------------------------------------------
// Cases that need more than one read.

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

describe("a stored body never answers the owner over a pending key reset", () => {
  it("the owner reads the published base the grant reads, marked incomplete", async () => {
    const row = ROWS.find((r) => r.id === "S4")!;
    const rig = await open(row);
    const owner = await api(rig, row, { builder: false, file: true });
    expect(owner.source).toBe("stream-sync");
    expect(canon(owner.records)).toEqual(canon(AB));
    expect(owner.complete).toBe("false");
    expect(owner.withheld).toBe("key_reset_pending");
    const grant = await api(rig, row, { builder: true, file: true });
    expect(canon(grant.records)).toEqual(canon(AB));
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
