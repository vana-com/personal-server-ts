/**
 * Prose a model can actually reason over.
 *
 * `text.ts` emits random words from a 40-word vocabulary. That is the right
 * choice for the `small`/`full` profiles — it is fast, it is incapable of
 * accidentally containing a planted needle, and design §18.5 is explicit that
 * scan timings off it are realistic while *semantic quality* on it proves
 * nothing.
 *
 * The consequence is that seven of the eighteen questions (Q2, Q3, Q9, Q10,
 * Q15, Q16, Q17) are structurally present but semantically vacuous: there is no
 * topic to identify, no position to contrast, no intention to follow up on. This
 * module supplies the missing substance for the `dogfood` profile.
 *
 * Three rules it holds to:
 *
 *  1. **Deterministic.** Templated composition over seeded draws. No LLM, no
 *     `Math.random()`. A seed reproduces the corpus byte for byte, which is
 *     what lets an expected value stay valid.
 *  2. **Ground truth is declared, not inferred.** Every arc names its own first
 *     mention, its before/after position and its anchors, so the reference path
 *     can compute an expectation instead of a human eyeballing it.
 *  3. **Never leaks a needle.** The Q5 restaurant token and the Q8 conflict
 *     marker must not appear here; `prose.test.ts` asserts it.
 */

import type { Rng } from "./prng.js";

/* ------------------------------------------------------------------ */
/* Topic arcs — the spine of Q9 and Q10                                */
/* ------------------------------------------------------------------ */

/**
 * One stage of an evolving view. `fromDay`/`toDay` are indices into the 1100-day
 * corpus window; a stage's lines are only emitted inside its own span, which is
 * what makes "earliest mention" and "before vs after" computable rather than
 * hoped for.
 */
export interface ArcStage {
  id: string;
  fromDay: number;
  toDay: number;
  /** Sentences a message in this stage can be built from. */
  lines: readonly string[];
}

export interface TopicArc {
  id: string;
  /** Human-readable subject, used in rubrics and reference facts. */
  subject: string;
  /**
   * The day the topic first appears at all. The earliest stage's `fromDay`;
   * carried separately so the reference path can assert the two agree.
   */
  firstMentionDay: number;
  /** How the view reads at the start and at the end — Q10's contrast. */
  earlyPosition: string;
  latePosition: string;
  /**
   * Tokens that identify the topic. Distinctive enough that a scan can find
   * them and that filler cannot produce them.
   */
  anchors: readonly string[];
  stages: readonly ArcStage[];
}

/**
 * Q9 — "when did I first start thinking about leaving my job?"
 *
 * The first mention is deliberately oblique: a question about tenure, with no
 * keyword a naive search for "quit"/"resign"/"leaving" would catch. That is the
 * failure mode design §3 Q9 names — the earliest instance is the one that
 * ranking-by-relevance buries, so the answer requires ordering by time over
 * semantic matches rather than taking the top hit.
 */
export const JOB_ARC: TopicArc = {
  id: "job-departure",
  subject: "leaving my job",
  firstMentionDay: 214,
  earlyPosition:
    "vague restlessness framed as a question about tenure, with no intent to leave",
  latePosition:
    "an explicit decision to interview, with a timeline and people told",
  anchors: ["four years", "tenure", "interviewing", "resignation"],
  stages: [
    {
      id: "oblique",
      fromDay: 214,
      toDay: 380,
      lines: [
        "Is four years a long time to be at one company? Genuinely asking, I have no calibration for this.",
        "Everyone I started with has left. I keep telling myself that means nothing.",
        "Had the tenure conversation with myself again on the walk home. Still no conclusion.",
        "I notice I describe my job in the past tense sometimes and then correct myself.",
        "Nothing is wrong. That is sort of the problem — nothing is wrong and I still feel like this.",
      ],
    },
    {
      id: "questioning",
      fromDay: 381,
      toDay: 700,
      lines: [
        "Sat in the roadmap review today and felt like I was watching someone else's plan for someone else's year.",
        "If I am honest the interesting problems here were solved eighteen months ago.",
        "Asked myself what I would miss and the honest list was three people and the coffee machine.",
        "Started reading job postings the way you read a menu when you are not hungry yet.",
        "The tenure question came back. Four years is starting to sound like an answer rather than a question.",
      ],
    },
    {
      id: "explicit",
      fromDay: 701,
      toDay: 940,
      lines: [
        "Updated my resume tonight. Did not send it anywhere. Felt significant anyway.",
        "Two recruiters in one week. I replied to both, which is new.",
        "I am going to start interviewing. Writing it down so it is real.",
        "Made a list of what the next thing has to have. It is short and none of it is money.",
        "Told myself I would give it until the end of the quarter. I do not think I will make it that long.",
      ],
    },
    {
      id: "decisive",
      fromDay: 941,
      toDay: 1099,
      lines: [
        "Told Priya I am interviewing. She was not surprised, which tells me something.",
        "Two onsites scheduled. The resignation conversation is now a matter of timing, not decision.",
        "Drafted the resignation note. Not sending it yet, but it exists.",
        "The four years question finally has an answer and the answer is that it was about one year too many.",
      ],
    },
  ],
};

/**
 * Q10 — "what changed in how I think about X over the last two years?"
 *
 * A genuine reversal, not a drift: concentrated speculation early, boring
 * diversification late, with the drawdown that caused it in the middle. Doubles
 * as the evidence base for Q3 (risk appetite), where the honest answer has to
 * notice that the early and late halves disagree rather than averaging them.
 */
export const INVESTING_ARC: TopicArc = {
  id: "investing-views",
  subject: "how I invest",
  firstMentionDay: 40,
  earlyPosition:
    "concentrated and speculative — index funds dismissed as giving up, position sizing driven by conviction",
  latePosition:
    "diversified and boring by choice — indexed core, speculation ring-fenced to a small explicit budget",
  anchors: ["index funds", "position sizing", "drawdown", "conviction"],
  stages: [
    {
      id: "speculative",
      fromDay: 40,
      toDay: 340,
      lines: [
        "Index funds are what you buy when you have given up on having an opinion. I have opinions.",
        "Put another chunk into the same position today. If I am right once it does not matter how often I am wrong.",
        "Position sizing advice always comes from people who have never been right about anything.",
        "The whole portfolio is three names and I sleep fine.",
        "Someone told me to diversify and I genuinely could not tell if they were being serious.",
      ],
    },
    {
      id: "drawdown",
      fromDay: 341,
      toDay: 620,
      lines: [
        "Down forty percent on the concentrated position. Writing that sentence is the first honest thing I have done about it.",
        "I did not sell. I want to be clear with myself that this was not conviction, it was that selling would make it real.",
        "Ran the numbers on what indexing the same money would have done. I do not like the answer.",
        "The drawdown is not the lesson. The lesson is that I had no plan for the drawdown.",
        "Starting to think conviction is just position sizing with better marketing.",
      ],
    },
    {
      id: "reformed",
      fromDay: 621,
      toDay: 1099,
      lines: [
        "Moved the core of it into index funds. Two years ago I would have found that embarrassing.",
        "New rule: speculation gets a fixed budget and the budget is small enough that losing all of it changes nothing.",
        "Boring is a strategy. It took a forty percent drawdown to teach me a thing I had been told for free.",
        "Rebalanced today, which is a sentence I could not have written before.",
        "I still have opinions. I just no longer think my opinions deserve most of my money.",
      ],
    },
  ],
};

export const TOPIC_ARCS: readonly TopicArc[] = [JOB_ARC, INVESTING_ARC];

/* ------------------------------------------------------------------ */
/* Q16 — the stated/measured conflict                                  */
/* ------------------------------------------------------------------ */

/**
 * Q16 ("am I a morning person?") is graded on noticing a disagreement, so the
 * corpus has to contain one. These are the *stated* claims; the measured side is
 * the commit stream, which the dogfood generator weights to early morning.
 *
 * A system that retrieves only text answers "no". A system that only aggregates
 * answers "yes". The design's point is that the honest answer reports both.
 */
export const MORNING_CLAIMS: readonly string[] = [
  "I am definitely not a morning person, never have been.",
  "Anyone who schedules a meeting before ten is my enemy.",
  "I do my best work at night. Always have.",
  "Mornings are for people with something to prove.",
  "I told them I am not a morning person and they laughed, which I did not appreciate.",
];

/** Hour of day the dogfood commit stream clusters around — the measured rebuttal. */
export const MORNING_COMMIT_PEAK_HOUR = 6;
export const MORNING_COMMIT_SHARE = 0.62;

/* ------------------------------------------------------------------ */
/* Q15 — stated intentions, kept and abandoned                         */
/* ------------------------------------------------------------------ */

/**
 * Q15 ("what do I keep saying I'll do but never do?") needs both halves:
 * intentions stated in text, and evidence of follow-through that exists for some
 * and provably does not for others. `followedThrough` is the ground truth; the
 * generator emits calendar events and commits only for the true ones.
 */
export interface Intention {
  id: string;
  /** How the intention is stated, in the user's voice. */
  stated: readonly string[];
  /** Distinctive token tying evidence back to the intention. */
  anchor: string;
  followedThrough: boolean;
  /** Only meaningful when followedThrough — what the evidence looks like. */
  evidence?: string;
}

export const INTENTIONS: readonly Intention[] = [
  {
    id: "spanish",
    anchor: "Spanish",
    stated: [
      "This is the year I actually learn Spanish.",
      "Booked nothing, told no one, but I am going to get serious about Spanish.",
      "Reinstalled the Spanish app. Third time.",
    ],
    followedThrough: false,
  },
  {
    id: "half-marathon",
    anchor: "half marathon",
    stated: [
      "Signing up for a half marathon in the spring.",
      "The half marathon plan starts Monday. It always starts Monday.",
    ],
    followedThrough: true,
    evidence:
      "training runs appear in the workout log and the race is on the calendar",
  },
  {
    id: "pottery",
    anchor: "pottery class",
    stated: [
      "I keep saying I will take a pottery class and I keep not doing it.",
      "Looked up pottery classes again. Closed the tab again.",
      "Pottery class. This time for real.",
    ],
    followedThrough: false,
  },
  {
    id: "dentist",
    anchor: "dentist",
    stated: [
      "I need to book the dentist. I have needed to book the dentist for a while.",
      "Still have not booked the dentist.",
    ],
    followedThrough: true,
    evidence: "a dentist appointment appears on the calendar",
  },
  {
    id: "writing",
    anchor: "write something long",
    stated: [
      "I want to write something long this year instead of only notes to myself.",
      "The long piece is still an outline. It has been an outline for months.",
      "Going to write something long. Blocking out Sundays for it.",
    ],
    followedThrough: false,
  },
];

export const ABANDONED_INTENTIONS = INTENTIONS.filter(
  (i) => !i.followedThrough,
);
export const KEPT_INTENTIONS = INTENTIONS.filter((i) => i.followedThrough);

/* ------------------------------------------------------------------ */
/* Q17 — a person with real presence                                   */
/* ------------------------------------------------------------------ */

/**
 * Q17 ("summarize everything I know about Sarah Johnson") is currently graded on
 * alias resolution alone, because there is nothing to summarize. These give the
 * gather actual substance — facts a briefing would contain — attached to the
 * `sarah-johnson` identity across several sources.
 *
 * The confusable second Sarah gets her own, clearly different, facts so that a
 * failure to resolve identity produces a visibly wrong briefing rather than a
 * slightly thin one.
 */
export interface PersonFact {
  personId: string;
  anchor: string;
  text: string;
}

export const SARAH_JOHNSON_FACTS: readonly PersonFact[] = [
  {
    personId: "sarah-johnson",
    anchor: "Helsinki",
    text: "Sarah is in Helsinki now — the timezone is why our syncs moved to her morning.",
  },
  {
    personId: "sarah-johnson",
    anchor: "migration",
    text: "Sarah owned the storage migration end to end and is the only person who understands the rollback path.",
  },
  {
    personId: "sarah-johnson",
    anchor: "pottery",
    text: "Sarah is the one who keeps sending me pottery studios, which is how that whole idea started.",
  },
  {
    personId: "sarah-johnson",
    anchor: "promotion",
    text: "Sarah was promoted to staff engineer in the spring cycle; she was matter-of-fact about it.",
  },
  {
    personId: "sarah-johnson",
    anchor: "boat noodles",
    text: "Sarah's food recommendations have never once been wrong, which is why I still take them seriously.",
  },
];

export const SARAH_NGUYEN_FACTS: readonly PersonFact[] = [
  {
    personId: "sarah-nguyen",
    anchor: "procurement",
    text: "Sarah Nguyen is on the partner side and handles procurement; we have never worked directly.",
  },
  {
    personId: "sarah-nguyen",
    anchor: "contract",
    text: "Sarah Nguyen sent the redlines on the partner contract. That is the extent of our contact.",
  },
];

/* ------------------------------------------------------------------ */
/* Q2 — main focus, with the loud source deliberately wrong            */
/* ------------------------------------------------------------------ */

/**
 * Design §3 Q2 names the failure mode precisely: "2000 Slack messages drowning
 * out the 3 documents that were the actual week". So the final week is built to
 * punish exactly that — a high-volume, low-substance Slack topic sits on top of
 * the small number of calendar hours, documents and commits that are what the
 * week was actually about.
 *
 * A volume-weighted answer returns `LOUD`. The defensible answer returns `REAL`
 * and can say why (calendar hours and deep work, not message count).
 */
export const FOCUS_WEEK_DAYS = 7;

export const FOCUS_REAL_TOPIC = {
  id: "storage-migration-cutover",
  label: "the storage migration cutover",
  anchor: "migration cutover",
  lines: [
    "Cutover plan for the storage migration, third revision. This is the whole week.",
    "Spent the day on the migration cutover runbook. Nothing else got touched.",
    "Migration cutover rehearsal went long. Found two ordering bugs in the rollback.",
    "The cutover is the only thing that matters this week. Everything else is noise.",
  ],
} as const;

export const FOCUS_LOUD_TOPIC = {
  id: "office-move",
  label: "the office move thread",
  anchor: "office move",
  lines: [
    "anyone know if the new desks are the sit-stand ones",
    "office move thread is at 200 messages and counting",
    "can someone confirm the move date, I have heard three different ones",
    "re: office move — is the old fridge coming with us or not",
    "office move: do we need to label the monitors",
    "genuinely how is the office move still being discussed",
  ],
} as const;

/* ------------------------------------------------------------------ */
/* Filler with actual structure                                        */
/* ------------------------------------------------------------------ */

/**
 * Background prose for the dogfood corpus.
 *
 * Still synthetic and still templated, but composed from clause fragments rather
 * than shuffled single words, so a model reading it sees ordinary sentences
 * about plausible subjects. Its job is to be *unremarkable* — the arcs above
 * have to stand out against it, and a scan of it must not accidentally produce a
 * planted anchor.
 */
const SUBJECTS = [
  "the standup",
  "the deploy",
  "the invoice from the vendor",
  "the quarterly forecast",
  "the onboarding doc",
  "the flaky test",
  "the design review",
  "the landlord",
  "the sublet paperwork",
  "the reimbursement",
  "the retro",
  "the schema change",
  "the latency graph",
  "the on-call rotation",
  "the budget spreadsheet",
];

const PREDICATES = [
  "took longer than it should have",
  "is still blocked on someone else",
  "went fine, which was a surprise",
  "got pushed to next week again",
  "is now someone else's problem",
  "turned out to be a configuration issue",
  "needs a decision I do not want to make",
  "was resolved in about ten minutes once I actually looked",
  "is fine and I should stop thinking about it",
  "came back after I thought it was done",
];

const OPENERS = [
  "Short one today.",
  "Note to self.",
  "Nothing much to report.",
  "Quick update.",
  "Mostly admin today.",
  "Long day.",
];

const CLOSERS = [
  "Moving on.",
  "Will pick it up tomorrow.",
  "Not worth more time than it already took.",
  "Fine.",
  "Leaving it there.",
];

/**
 * Sentence frames, so background prose is not one grammatical shape repeated.
 *
 * A corpus where every sentence reads "The X did Y." is still word salad — just
 * grammatical word salad, and a model summarising it produces a summary of the
 * template rather than of the content. Four frames is enough to break the
 * pattern without pretending this is literature.
 */
const FRAMES: readonly ((s: string, p: string) => string)[] = [
  (s, p) => `${capitalize(s)} ${p}.`,
  (s, p) => `Spent longer than I meant to on ${s}, which ${p}.`,
  (s, p) => `${capitalize(s)}: ${p}.`,
  (s, p) => `Reminder that ${s} ${p}.`,
];

/** One ordinary sentence about an ordinary thing. */
export function proseSentence(rng: Rng): string {
  return rng.pick(FRAMES)(rng.pick(SUBJECTS), rng.pick(PREDICATES));
}

/** A short passage of background prose. */
export function proseParagraph(rng: Rng, sentences: number): string {
  const out: string[] = [];
  if (rng.chance(0.4)) out.push(rng.pick(OPENERS));
  for (let i = 0; i < sentences; i++) out.push(proseSentence(rng));
  if (rng.chance(0.35)) out.push(rng.pick(CLOSERS));
  return out.join(" ");
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/* ------------------------------------------------------------------ */
/* Arc sampling                                                        */
/* ------------------------------------------------------------------ */

/** The stage covering `dayIndex`, or undefined if the arc has not started. */
export function stageForDay(
  arc: TopicArc,
  dayIndex: number,
): ArcStage | undefined {
  return arc.stages.find((s) => dayIndex >= s.fromDay && dayIndex <= s.toDay);
}

/**
 * A line from whichever stage covers this day, or undefined.
 *
 * Callers decide *how often* to reach for an arc line; this only decides what a
 * line would say if they did. Keeping the two apart is what lets the arcs be
 * sparse — a topic that appears in every message is not a topic, it is a theme
 * park.
 */
export function arcLineForDay(
  rng: Rng,
  arc: TopicArc,
  dayIndex: number,
): string | undefined {
  const stage = stageForDay(arc, dayIndex);
  if (!stage) return undefined;
  return rng.pick(stage.lines as string[]);
}

/** Every token the reference path expects to be findable, for leak assertions. */
export const ALL_ARC_ANCHORS: readonly string[] = TOPIC_ARCS.flatMap(
  (a) => a.anchors,
);
