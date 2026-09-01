/**
 * Seeded filler prose and the identity graph the corpus is built around.
 *
 * The prose is deliberately low-entropy. Design §18.5 is explicit that scan
 * timings off this corpus are realistic but *semantic quality* on it proves
 * nothing — only the graded set does. What the filler has to guarantee is that
 * it never accidentally contains a planted needle token.
 */

import type { Rng } from "./prng.js";

export const FILLER_WORDS =
  "project deadline sleep training kiln pottery invoice runway roadmap migration latency schema onboarding retro standup budget mortgage refactor benchmark vendor contract equity vesting travel kyoto osaka ramen espresso deadlift taper hrv insomnia melatonin therapist landlord sublet visa reimbursement quarterly forecast churn cohort retention".split(
    " ",
  );

/**
 * One person, many handles. Q6 (distinct people) and Q17 (brief me on X) are
 * unanswerable without collapsing these, and Q5 turns on the question naming
 * "Sarah" while the record carries `sarahj`.
 */
export interface Person {
  id: string;
  display: string;
  aliases: string[];
}

export const PEOPLE: readonly Person[] = [
  {
    id: "sarah-johnson",
    display: "Sarah Johnson",
    aliases: ["Sarah Johnson", "sarahj", "sarah@work.com", "Sarah 🌸"],
  },
  {
    id: "sarah-nguyen",
    display: "Sarah Nguyen",
    aliases: ["Sarah Nguyen", "snguyen", "sarah.nguyen@partner.io"],
  },
  {
    id: "miguel-ortiz",
    display: "Miguel Ortiz",
    aliases: ["Miguel Ortiz", "mortiz", "miguel@work.com"],
  },
  {
    id: "priya-raman",
    display: "Priya Raman",
    aliases: ["Priya Raman", "priya.raman@gmail.com", "praman"],
  },
  {
    id: "tom-becker",
    display: "Tom Becker",
    aliases: ["Tom Becker", "tbecker", "tom.becker@work.com"],
  },
  {
    id: "yuki-tanaka",
    display: "Yuki Tanaka",
    aliases: ["Yuki Tanaka", "ytanaka", "yuki@work.com"],
  },
];

/** Every alias, flattened — what a naive row-counting answer would count. */
export const ALL_ALIASES: readonly string[] = PEOPLE.flatMap((p) => p.aliases);

/** The ground-truth identity count Q6 must arrive at. */
export const DISTINCT_PEOPLE = PEOPLE.length;

export function sentence(rng: Rng): string {
  const n = 8 + rng.int(14);
  const words: string[] = [];
  for (let i = 0; i < n; i++) words.push(rng.pick(FILLER_WORDS));
  return words.join(" ") + ".";
}

export function paragraph(rng: Rng, sentences: number): string {
  const out: string[] = [];
  for (let i = 0; i < sentences; i++) out.push(sentence(rng));
  return out.join(" ");
}
