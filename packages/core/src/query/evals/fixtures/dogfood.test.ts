import { describe, expect, it } from "vitest";

import { generateCorpus, SCOPES } from "./generate.js";
import { MemoryFixtureSink } from "./sink.js";
import { DEFAULT_SEED, PROFILES } from "./profiles.js";
import { Q5_RESTAURANT, Q8_CONFLICT_MARKER } from "./planted.js";
import { sleepTrap, branchTrap } from "../reference/compute.js";
import {
  arcReference,
  focusWeekReference,
  intentionReference,
  morningPersonReference,
  nutritionReference,
  personBriefReference,
} from "../reference/semantic.js";

async function build(profile: "small" | "dogfood" | "lite") {
  const sink = new MemoryFixtureSink();
  const manifest = await generateCorpus(sink, { profile });
  return { sink, manifest };
}

async function concat(sink: MemoryFixtureSink): Promise<string> {
  const parts: string[] = [];
  for (const f of await sink.list()) parts.push(await sink.read(f));
  return parts.join("\n");
}

describe("profile isolation", () => {
  /*
   * The load-bearing test in this file.
   *
   * `small` and `full` carry the committed trap numbers — the Oura nap error,
   * the ChatGPT phantom rate, Q14's total. Every one is an expectation
   * somewhere, and the dogfood work adds rows to shared sources. If a single
   * extra rng draw leaked into a non-dogfood profile, those numbers would move
   * and the regression would surface as an unrelated case failing weeks later.
   */
  it("adding the dogfood profile does not perturb `small`", async () => {
    const { sink } = await build("small");
    const sleep = await sleepTrap(sink, null);
    const branches = await branchTrap(sink);

    // Captured from the pre-dogfood generator at seed 20260828.
    expect(sleep.correctHours).toBeCloseTo(6.521692286947141, 10);
    expect(sleep.naiveHours).toBeCloseTo(5.93435346075876, 10);
    expect(sleep.errorPct).toBeCloseTo(-9.005926688137567, 10);
    expect(sleep.nights).toBe(1030);
    expect(branches.correctMessages).toBe(4449);
    expect(branches.naiveMessages).toBe(5114);
    expect(branches.phantomPct).toBeCloseTo(14.947179141380085, 10);
  });

  it("emits no semantic content into non-dogfood profiles", async () => {
    for (const name of ["small", "lite"] as const) {
      const { sink, manifest } = await build(name);
      const arcs = await arcReference(sink);
      expect(
        arcs.every((a) => a.mentions === 0),
        `${name} leaked arc lines`,
      ).toBe(true);
      const scopes = manifest.scopes.map((s) => s.scope);
      expect(scopes).not.toContain(SCOPES.nutrition);
      expect(scopes).not.toContain(SCOPES.commits);
    }
  });

  it("semantic references degrade to zero rather than throwing", async () => {
    // A case must be able to tell "the model missed it" from "the corpus never
    // contained it". Throwing here would make the two indistinguishable.
    const { sink } = await build("small");
    expect((await nutritionReference(sink)).daysLogged).toBe(0);
    expect((await morningPersonReference(sink)).conflict).toBe(false);
    expect((await focusWeekReference(sink)).realCommits).toBe(0);
  });
});

describe("dogfood determinism", () => {
  it("is byte-identical across runs at the same seed", async () => {
    const a = await build("dogfood");
    const b = await build("dogfood");
    expect(await concat(a.sink)).toBe(await concat(b.sink));
  });

  it("differs at a different seed", async () => {
    const sinkA = new MemoryFixtureSink();
    const sinkB = new MemoryFixtureSink();
    await generateCorpus(sinkA, { profile: "dogfood", seed: DEFAULT_SEED });
    await generateCorpus(sinkB, { profile: "dogfood", seed: DEFAULT_SEED + 1 });
    expect(await concat(sinkA)).not.toBe(await concat(sinkB));
  });
});

describe("dogfood planted facts survive the denser prose", () => {
  it("keeps the Q5 needle unique and the Q8 marker absent", async () => {
    const { sink } = await build("dogfood");
    const all = await concat(sink);
    expect(all.split(Q5_RESTAURANT).length - 1).toBe(1);
    expect(all).not.toContain(Q8_CONFLICT_MARKER);
  });
});

describe("Q9 / Q10 — topic arcs", () => {
  it("both arcs are present with a datable first mention", async () => {
    const { sink } = await build("dogfood");
    const arcs = await arcReference(sink);
    expect(arcs).toHaveLength(2);
    for (const arc of arcs) {
      expect(arc.mentions, `${arc.arcId} has no mentions`).toBeGreaterThan(20);
      expect(arc.firstMentionDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      // The earliest mention must belong to the earliest stage, or "first
      // mention" is reporting something other than the start of the arc.
      expect(arc.firstMentionStage).toBe(
        arc.arcId === "job-departure" ? "oblique" : "speculative",
      );
    }
  });

  it("both halves of the investing arc are sampleable", async () => {
    // Q10 asks for a contrast. If one half were empty a summary of the other
    // would pass, which is the failure design §3 Q10 names.
    const { sink } = await build("dogfood");
    const investing = (await arcReference(sink)).find(
      (a) => a.arcId === "investing-views",
    );
    expect(investing!.mentionsFirstHalf).toBeGreaterThan(10);
    expect(investing!.mentionsSecondHalf).toBeGreaterThan(10);
  });
});

describe("Q2 — the loud source is deliberately wrong", () => {
  it("Slack volume points at the wrong topic while other sources point right", async () => {
    const { sink } = await build("dogfood");
    const focus = await focusWeekReference(sink);
    // The trap must be armed: more Slack noise than signal.
    expect(focus.loudSlackMessages).toBeGreaterThan(focus.realSlackMessages);
    expect(focus.loudToRealSlackRatio).toBeGreaterThan(2);
    // And the defensible evidence must exist and point the other way.
    expect(focus.realCalendarEvents).toBeGreaterThan(0);
    expect(focus.realCommits).toBeGreaterThan(0);
    expect(focus.loudCalendarEvents).toBe(0);
  });
});

describe("Q15 — intent versus follow-through", () => {
  it("abandoned intentions are stated repeatedly and have no evidence", async () => {
    const { sink } = await build("dogfood");
    const intentions = await intentionReference(sink);
    const abandoned = intentions.filter((i) => !i.followedThrough);
    const kept = intentions.filter((i) => i.followedThrough);

    expect(abandoned.length).toBeGreaterThan(0);
    expect(kept.length).toBeGreaterThan(0);
    for (const i of abandoned) {
      expect(i.statedMentions, `${i.anchor} never stated`).toBeGreaterThan(0);
      expect(i.evidenceEvents, `${i.anchor} has phantom evidence`).toBe(0);
    }
    for (const i of kept) {
      expect(i.evidenceEvents, `${i.anchor} lacks evidence`).toBeGreaterThan(0);
    }
  });
});

describe("Q16 — stated versus measured", () => {
  it("the corpus genuinely disagrees with itself", async () => {
    const { sink } = await build("dogfood");
    const m = await morningPersonReference(sink);
    expect(m.statedClaims).toBeGreaterThan(0);
    expect(m.commits).toBeGreaterThan(0);
    // Measured in LOCAL time. Reading the UTC hour off a -08:00 timestamp
    // inverts this and reports a night owl.
    expect(m.shareBefore9).toBeGreaterThan(0.5);
    expect(m.medianCommitHour).toBeLessThan(9);
    expect(m.conflict).toBe(true);
  });
});

describe("Q17 — entity gather has substance", () => {
  it("has facts for the right Sarah and different ones for the other", async () => {
    const { sink } = await build("dogfood");
    const p = await personBriefReference(sink);
    expect(p.factAnchors.length).toBeGreaterThan(2);
    expect(p.factMentions).toBeGreaterThan(10);
    expect(p.confusableFactAnchors.length).toBeGreaterThan(0);
    // Disjoint, or a wrong-person briefing would be indistinguishable.
    for (const a of p.confusableFactAnchors) {
      expect(p.factAnchors).not.toContain(a);
    }
  });
});

describe("Q18 — a real intake source", () => {
  it("nutrition is partial, joins to workouts, and differs from expenditure", async () => {
    const { sink } = await build("dogfood");
    const n = await nutritionReference(sink);

    expect(n.daysLogged).toBeGreaterThan(0);
    expect(n.daysLogged).toBeLessThan(PROFILES.dogfood.sleepDays);
    // Partial logging is the point: the denominator is not the run-day count.
    expect(n.runDaysWithoutLog).toBeGreaterThan(0);
    expect(n.matchedDays).toBeGreaterThan(20);

    // There must be a real signal, or the case grades noise.
    expect(n.meanKcalOnRunDays).toBeGreaterThan(n.meanKcalOtherDays);

    // And the old expenditure proxy must be visibly a different number, which
    // is why it was the wrong source to answer an intake question from.
    expect(
      Math.abs(n.meanActivityCaloriesOnRunDays - n.meanKcalOnRunDays),
    ).toBeGreaterThan(100);
  });
});

describe("dogfood shape", () => {
  it("stays in the size band it is meant for", async () => {
    const { sink, manifest } = await build("dogfood");
    let bytes = 0;
    for (const f of await sink.list()) bytes += await sink.size(f);
    // Semantic exercise, not scale testing: big enough for the arcs to be
    // sparse, small enough to regenerate in a test.
    expect(bytes).toBeGreaterThan(5_000_000);
    expect(bytes).toBeLessThan(60_000_000);
    expect(manifest.scopes.length).toBeGreaterThan(15);
  });

  it("ships an FX rate the script can actually read", async () => {
    /*
     * Before this existed the corpus contained no rate anywhere and the
     * sandbox has no network, so Q14's constant was known only to the grader.
     * A model could apply the FX rule perfectly and still fail by ~$12 for
     * using 149.0 instead of 149.5 — a test of clairvoyance, not reasoning.
     */
    const { sink, manifest } = await build("dogfood");
    expect(manifest.scopes.map((s) => s.scope)).toContain(SCOPES.fx);

    const rates = JSON.parse(await sink.read("fx_rates.json")) as {
      date: string;
      base: string;
      quote: string;
      jpy_per_usd: number;
    }[];
    expect(rates.length).toBeGreaterThan(1000);
    expect(rates[0]!.base).toBe("USD");
    expect(rates[0]!.quote).toBe("JPY");
    // Plausible band: a wrong-way inversion would land near 0.0067.
    for (const r of rates) {
      expect(r.jpy_per_usd).toBeGreaterThan(120);
      expect(r.jpy_per_usd).toBeLessThan(180);
    }
    // Dogfood drifts, which is what "FX at transaction date" requires.
    expect(new Set(rates.map((r) => r.jpy_per_usd)).size).toBeGreaterThan(50);
  });

  it("keeps the older profiles' rate flat so their Q14 total is unmoved", async () => {
    const { sink } = await build("small");
    const rates = JSON.parse(await sink.read("fx_rates.json")) as {
      jpy_per_usd: number;
    }[];
    expect(new Set(rates.map((r) => r.jpy_per_usd)).size).toBe(1);
  });

  it("email is threaded and can carry several recipients", async () => {
    // Without threading, every conversation-shaped question is unanswerable;
    // without arrays there is no group mail or Cc to ask about at all.
    const { sink } = await build("dogfood");
    const mail = JSON.parse(await sink.read("email.json")) as {
      to: string[];
      cc: string[];
      thread_id: string;
      subject: string;
      in_reply_to: string | null;
    }[];
    expect(mail.every((m) => Array.isArray(m.to) && m.to.length > 0)).toBe(
      true,
    );
    expect(mail.some((m) => m.to.length > 1)).toBe(true);
    expect(mail.some((m) => m.cc.length > 0)).toBe(true);
    expect(mail.some((m) => m.in_reply_to !== null)).toBe(true);
    expect(mail.some((m) => m.subject.startsWith("Re: "))).toBe(true);
    // Threads must actually group: more messages than distinct threads.
    const threads = new Set(mail.map((m) => m.thread_id));
    expect(threads.size).toBeLessThan(mail.length);
  });

  it("calendar events vary in duration and group size", async () => {
    // Identical one-hour two-person events make "calendar hours" the same
    // number as "event count", which is what Q2's weighting turns on.
    const { sink } = await build("dogfood");
    const events = JSON.parse(await sink.read("calendar.json")) as {
      duration_minutes: number;
      attendees: string[];
    }[];
    expect(new Set(events.map((e) => e.duration_minutes)).size).toBeGreaterThan(
      3,
    );
    expect(events.some((e) => e.attendees.length > 2)).toBe(true);
    expect(events.some((e) => e.attendees.length === 1)).toBe(true);
  });

  it("bank rows carry an explicit currency", async () => {
    const { sink } = await build("dogfood");
    const rows = JSON.parse(await sink.read("bank_transactions.json")) as {
      currency: string;
    }[];
    expect(rows.every((r) => typeof r.currency === "string")).toBe(true);
    const currencies = new Set(rows.map((r) => r.currency));
    // Q14 needs FX to be unavoidable, so more than one currency must appear.
    expect(currencies.size).toBeGreaterThan(1);
    expect(currencies).toContain("JPY");
  });
});
