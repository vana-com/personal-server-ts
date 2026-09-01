import { describe, expect, it } from "vitest";

import { createRng } from "./prng.js";
import { Q5_RESTAURANT, Q8_CONFLICT_MARKER } from "./planted.js";
import {
  ALL_ARC_ANCHORS,
  INTENTIONS,
  INVESTING_ARC,
  JOB_ARC,
  MORNING_CLAIMS,
  TOPIC_ARCS,
  arcLineForDay,
  proseParagraph,
  proseSentence,
  stageForDay,
} from "./prose.js";
import { CORPUS_DAYS } from "./time.js";

describe("topic arcs", () => {
  it("stages tile the arc without gaps or overlaps", () => {
    for (const arc of TOPIC_ARCS) {
      const stages = [...arc.stages].sort((a, b) => a.fromDay - b.fromDay);
      expect(stages[0]!.fromDay, `${arc.id} starts at firstMentionDay`).toBe(
        arc.firstMentionDay,
      );
      for (let i = 1; i < stages.length; i++) {
        expect(
          stages[i]!.fromDay,
          `${arc.id}: ${stages[i]!.id} must start the day after ${stages[i - 1]!.id} ends`,
        ).toBe(stages[i - 1]!.toDay + 1);
      }
      expect(stages.at(-1)!.toDay).toBeLessThan(CORPUS_DAYS);
    }
  });

  it("has no line before the arc begins", () => {
    // This is what makes "first mention" a fact rather than an artifact of
    // sampling: the corpus cannot contain the topic before its start day.
    const rng = createRng(1);
    for (const arc of TOPIC_ARCS) {
      expect(arcLineForDay(rng, arc, arc.firstMentionDay - 1)).toBeUndefined();
      expect(arcLineForDay(rng, arc, 0)).toBeUndefined();
      expect(arcLineForDay(rng, arc, arc.firstMentionDay)).toBeDefined();
    }
  });

  it("returns a line from the stage covering the day", () => {
    const rng = createRng(7);
    for (const arc of TOPIC_ARCS) {
      for (const stage of arc.stages) {
        const day = Math.floor((stage.fromDay + stage.toDay) / 2);
        expect(stageForDay(arc, day)?.id).toBe(stage.id);
        const line = arcLineForDay(rng, arc, day);
        expect(stage.lines).toContain(line);
      }
    }
  });

  it("the job arc opens obliquely — no keyword a naive search would catch", () => {
    // Design §3 Q9: the earliest instance is oblique, which is why ordering by
    // relevance buries it. If the opening stage ever mentions quitting outright
    // the question has quietly become easy.
    const opening = JOB_ARC.stages[0]!;
    for (const line of opening.lines) {
      const l = line.toLowerCase();
      expect(l, `oblique stage leaked a keyword: ${line}`).not.toMatch(
        /\bquit|\bresign|\bnew job|\bleaving\b/,
      );
    }
  });

  it("the investing arc reverses rather than drifts", () => {
    // Q10 asks what *changed*. If both ends said the same thing there would be
    // no contrast to find and the case would pass on a summary.
    expect(INVESTING_ARC.earlyPosition).not.toBe(INVESTING_ARC.latePosition);
    expect(INVESTING_ARC.stages[0]!.lines.join(" ")).toMatch(/Index funds/);
    expect(INVESTING_ARC.stages.at(-1)!.lines.join(" ")).toMatch(
      /index funds/i,
    );
  });
});

describe("intentions", () => {
  it("has both kept and abandoned, or Q15 is unanswerable", () => {
    expect(INTENTIONS.some((i) => i.followedThrough)).toBe(true);
    expect(INTENTIONS.some((i) => !i.followedThrough)).toBe(true);
  });

  it("every intention states itself more than once", () => {
    // "What do I keep saying I'll do" — a thing said once is not a pattern.
    for (const i of INTENTIONS) {
      expect(i.stated.length, `${i.id} stated only once`).toBeGreaterThan(1);
    }
  });

  it("kept intentions declare their evidence", () => {
    for (const i of INTENTIONS.filter((x) => x.followedThrough)) {
      expect(
        i.evidence,
        `${i.id} claims follow-through with no evidence`,
      ).toBeTruthy();
    }
  });
});

describe("planted-token safety", () => {
  const everything = [
    ...TOPIC_ARCS.flatMap((a) => a.stages.flatMap((s) => s.lines)),
    ...MORNING_CLAIMS,
    ...INTENTIONS.flatMap((i) => i.stated),
  ].join("\n");

  it("never leaks the Q5 needle", () => {
    // The needle must occur exactly once in the whole corpus. Prose that could
    // emit it would make Q5 pass for the wrong reason.
    expect(everything).not.toContain(Q5_RESTAURANT);
  });

  it("never leaks the Q8 conflict marker", () => {
    // Q8's honest answer is "none found". Prose containing the marker would
    // make the correct answer wrong.
    expect(everything).not.toContain(Q8_CONFLICT_MARKER);
  });

  it("background prose cannot emit an arc anchor", () => {
    const rng = createRng(99);
    let generated = "";
    for (let i = 0; i < 4000; i++) generated += proseSentence(rng) + " ";
    for (const anchor of ALL_ARC_ANCHORS) {
      expect(
        generated.toLowerCase(),
        `filler produced the arc anchor "${anchor}", which would create false positives`,
      ).not.toContain(anchor.toLowerCase());
    }
  });

  it("background prose cannot emit the needle or the conflict marker", () => {
    const rng = createRng(1234);
    let generated = "";
    for (let i = 0; i < 3000; i++) generated += proseParagraph(rng, 3) + " ";
    expect(generated).not.toContain(Q5_RESTAURANT);
    expect(generated).not.toContain(Q8_CONFLICT_MARKER);
  });
});

describe("prose determinism", () => {
  it("is a pure function of the seed", () => {
    const a = createRng(42);
    const b = createRng(42);
    for (let i = 0; i < 200; i++) {
      expect(proseParagraph(a, 4)).toBe(proseParagraph(b, 4));
    }
  });

  it("differs across seeds", () => {
    const a = createRng(1);
    const b = createRng(2);
    const left = Array.from({ length: 40 }, () => proseSentence(a)).join("");
    const right = Array.from({ length: 40 }, () => proseSentence(b)).join("");
    expect(left).not.toBe(right);
  });

  it("is not one repeated sentence shape", () => {
    // Grammatical word salad is still word salad: a model summarising it would
    // describe the template rather than the content.
    const rng = createRng(5);
    const shapes = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const s = proseSentence(rng);
      shapes.add(s.slice(0, 12));
    }
    expect(shapes.size).toBeGreaterThan(8);
  });
});
