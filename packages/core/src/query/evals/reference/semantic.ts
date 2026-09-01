/**
 * Ground truth for the seven questions that need meaning, not arithmetic.
 *
 * Sibling to `compute.ts` and bound by the same rule: everything here re-reads
 * the **serialized** corpus through a `FixtureSource` and recomputes from
 * scratch, sharing no state with the generator. An expectation that came from
 * the generator's own bookkeeping would only prove the generator agrees with
 * itself.
 *
 * What these return is **anchors and counts, not prose judgements**. "Did it
 * identify the right topic" cannot be asserted against a paragraph; it can be
 * asserted against a date that must be found, a token that must appear, and a
 * token that must not. A `judged` case still needs a model to grade the
 * wording — it now has something to grade the wording against.
 *
 * Every function here returns zeroes on a corpus generated without
 * `semanticProse`, which is what lets a case distinguish "the model missed it"
 * from "the corpus never contained it".
 */

import type { FixtureSource } from "../fixtures/sink.js";
import { PEOPLE } from "../fixtures/text.js";
import { CORPUS_DAYS, dayStartMs } from "../fixtures/time.js";
import {
  FOCUS_LOUD_TOPIC,
  FOCUS_REAL_TOPIC,
  FOCUS_WEEK_DAYS,
  INTENTIONS,
  MORNING_CLAIMS,
  SARAH_JOHNSON_FACTS,
  SARAH_NGUYEN_FACTS,
  TOPIC_ARCS,
} from "../fixtures/prose.js";

async function readJson<T>(source: FixtureSource, file: string): Promise<T> {
  return JSON.parse(await source.read(file)) as T;
}

/* ------------------------------------------------------------------ */
/* The text index every semantic question is computed from             */
/* ------------------------------------------------------------------ */

export interface TextRecord {
  text: string;
  /** ISO instant. */
  at: string;
  source: string;
}

interface ChatMessage {
  author?: { role?: string };
  create_time?: number | null;
  content?: { parts?: unknown };
}

interface ChatConversation {
  current_node: string;
  mapping: Record<
    string,
    { id: string; parent: string | null; message: ChatMessage | null }
  >;
}

/**
 * The messages actually on the conversation's current path, oldest first.
 *
 * Design §12.3: edits and regenerations are sibling children, so
 * `Object.values(mapping)` includes branches the user abandoned. Treating those
 * as evidence of what someone thinks is wrong twice over — they were never
 * sent, and they can carry text that contradicts the path that was.
 */
function currentPath(conv: ChatConversation): ChatMessage[] {
  const out: ChatMessage[] = [];
  let cursor: string | null = conv.current_node;
  const seen = new Set<string>();
  while (cursor && cursor !== "root" && !seen.has(cursor)) {
    seen.add(cursor);
    const node: ChatConversation["mapping"][string] | undefined =
      conv.mapping[cursor];
    if (!node) break;
    if (node.message) out.push(node.message);
    cursor = node.parent;
  }
  return out.reverse();
}

/**
 * Every free-text record in the corpus with a comparable timestamp.
 *
 * Q9 asks for the earliest mention *across sources*, so notes, Slack, email and
 * chat have to land in one time-ordered pool. Anything undateable is dropped
 * rather than defaulted: a null `create_time` coerced to 0 becomes 1970 and
 * would win "earliest" against every real record in the corpus.
 */
export async function allText(source: FixtureSource): Promise<TextRecord[]> {
  const out: TextRecord[] = [];

  for (const n of await readJson<
    { created: string; title: string; body: string }[]
  >(source, "notes.json")) {
    out.push({ text: `${n.title} ${n.body}`, at: n.created, source: "notes" });
  }

  for (const m of await readJson<{ ts: string; text: string }[]>(
    source,
    "slack_messages.json",
  )) {
    out.push({
      text: m.text,
      at: new Date(Number(m.ts) * 1000).toISOString(),
      source: "slack",
    });
  }

  for (const e of await readJson<
    { date: string; subject: string; body: string }[]
  >(source, "email.json")) {
    out.push({ text: `${e.subject} ${e.body}`, at: e.date, source: "email" });
  }

  for (const conv of await readJson<ChatConversation[]>(
    source,
    "conversations.json",
  )) {
    for (const msg of currentPath(conv)) {
      if (msg.author?.role !== "user") continue;
      if (msg.create_time == null) continue;
      const parts = msg.content?.parts;
      if (!Array.isArray(parts)) continue;
      const text = parts.filter((p) => typeof p === "string").join(" ");
      if (!text) continue;
      out.push({
        text,
        at: new Date(msg.create_time * 1000).toISOString(),
        source: "chatgpt",
      });
    }
  }

  return out;
}

/* ------------------------------------------------------------------ */
/* Q9 / Q10 — topic arcs                                               */
/* ------------------------------------------------------------------ */

export interface ArcReference {
  arcId: string;
  subject: string;
  /** Earliest instant any line of the arc appears, across every source. */
  firstMentionAt: string | null;
  firstMentionDate: string | null;
  firstMentionSource: string | null;
  /** Which stage that first mention belongs to. Should be the earliest stage. */
  firstMentionStage: string | null;
  mentions: number;
  mentionsFirstHalf: number;
  mentionsSecondHalf: number;
  earlyPosition: string;
  latePosition: string;
  anchors: string[];
}

/**
 * Q9 wants the *earliest* mention — the one relevance ranking buries — so this
 * orders by time and never by match quality. Q10 wants a contrast, so the
 * early/late split is reported separately: an answer that summarises the recent
 * half and calls it a change has not answered the question.
 */
export async function arcReference(
  source: FixtureSource,
): Promise<ArcReference[]> {
  const records = await allText(source);
  const midpoint = dayStartMs(Math.floor(CORPUS_DAYS / 2));

  return TOPIC_ARCS.map((arc) => {
    const lines = arc.stages.flatMap((s) =>
      s.lines.map((l) => ({ line: l, stage: s.id })),
    );
    let firstAt = Infinity;
    let firstSource: string | null = null;
    let firstStage: string | null = null;
    let mentions = 0;
    let early = 0;
    let late = 0;

    for (const rec of records) {
      const hit = lines.find((l) => rec.text.includes(l.line));
      if (!hit) continue;
      mentions++;
      const t = Date.parse(rec.at);
      if (t < midpoint) early++;
      else late++;
      if (t < firstAt) {
        firstAt = t;
        firstSource = rec.source;
        firstStage = hit.stage;
      }
    }

    return {
      arcId: arc.id,
      subject: arc.subject,
      firstMentionAt: mentions ? new Date(firstAt).toISOString() : null,
      firstMentionDate: mentions
        ? new Date(firstAt).toISOString().slice(0, 10)
        : null,
      firstMentionSource: firstSource,
      firstMentionStage: firstStage,
      mentions,
      mentionsFirstHalf: early,
      mentionsSecondHalf: late,
      earlyPosition: arc.earlyPosition,
      latePosition: arc.latePosition,
      anchors: [...arc.anchors],
    };
  });
}

/* ------------------------------------------------------------------ */
/* Q2 — main focus, with the loud source deliberately wrong            */
/* ------------------------------------------------------------------ */

export interface FocusWeekReference {
  windowDays: number;
  from: string;
  to: string;
  realTopic: string;
  realAnchor: string;
  realSlackMessages: number;
  realCalendarEvents: number;
  realNotes: number;
  realCommits: number;
  loudTopic: string;
  loudAnchor: string;
  loudSlackMessages: number;
  loudCalendarEvents: number;
  loudNotes: number;
  /** Above 1 means a message-counting answer picks the wrong topic. */
  loudToRealSlackRatio: number;
}

/**
 * Design §3 Q2 names the failure mode as the loudest source dominating, so the
 * corpus is built to punish it: counting Slack messages returns the wrong
 * topic, while calendar hours, notes and commits return the right one.
 *
 * The ratio is reported so a case can assert the trap is actually armed rather
 * than assume it. If it ever drops to 1 the question has quietly become easy.
 */
export async function focusWeekReference(
  source: FixtureSource,
): Promise<FocusWeekReference> {
  const from = dayStartMs(CORPUS_DAYS - FOCUS_WEEK_DAYS);
  const to = dayStartMs(CORPUS_DAYS);
  const inWindow = (ms: number): boolean => ms >= from && ms < to;
  const real = FOCUS_REAL_TOPIC.anchor;
  const loud = FOCUS_LOUD_TOPIC.anchor;

  let realSlack = 0;
  let loudSlack = 0;
  for (const m of await readJson<{ ts: string; text: string }[]>(
    source,
    "slack_messages.json",
  )) {
    if (!inWindow(Number(m.ts) * 1000)) continue;
    const t = m.text.toLowerCase();
    if (t.includes(loud)) loudSlack++;
    if (t.includes(real)) realSlack++;
  }

  let realCal = 0;
  let loudCal = 0;
  for (const e of await readJson<{ start: string; title: string }[]>(
    source,
    "calendar.json",
  )) {
    if (!inWindow(Date.parse(e.start))) continue;
    const t = e.title.toLowerCase();
    if (t.includes(loud)) loudCal++;
    if (t.includes(real)) realCal++;
  }

  let realNotes = 0;
  let loudNotes = 0;
  for (const n of await readJson<{ created: string; body: string }[]>(
    source,
    "notes.json",
  )) {
    if (!inWindow(Date.parse(n.created))) continue;
    const t = n.body.toLowerCase();
    if (t.includes(loud)) loudNotes++;
    if (t.includes(real)) realNotes++;
  }

  let realCommits = 0;
  if ((await source.list()).includes("git_commits.json")) {
    for (const c of await readJson<{ authored_at: string; message: string }[]>(
      source,
      "git_commits.json",
    )) {
      if (!inWindow(Date.parse(c.authored_at))) continue;
      if (c.message.toLowerCase().includes(real)) realCommits++;
    }
  }

  return {
    windowDays: FOCUS_WEEK_DAYS,
    from: new Date(from).toISOString().slice(0, 10),
    to: new Date(to - 1).toISOString().slice(0, 10),
    realTopic: FOCUS_REAL_TOPIC.label,
    realAnchor: real,
    realSlackMessages: realSlack,
    realCalendarEvents: realCal,
    realNotes,
    realCommits,
    loudTopic: FOCUS_LOUD_TOPIC.label,
    loudAnchor: loud,
    loudSlackMessages: loudSlack,
    loudCalendarEvents: loudCal,
    loudNotes,
    loudToRealSlackRatio: realSlack ? loudSlack / realSlack : Infinity,
  };
}

/* ------------------------------------------------------------------ */
/* Q15 — stated intent vs follow-through                               */
/* ------------------------------------------------------------------ */

export interface IntentionReference {
  anchor: string;
  statedMentions: number;
  followedThrough: boolean;
  /** Calendar events evidencing follow-through. Zero for abandoned ones. */
  evidenceEvents: number;
}

/**
 * The graded property is that abandoned intentions were stated repeatedly *and*
 * have zero follow-through evidence. Listing an intention nobody ever mentioned
 * is wrong; listing a kept one as abandoned is wrong in the more damaging
 * direction, since the user would believe a thing about themselves that is not
 * true.
 */
export async function intentionReference(
  source: FixtureSource,
): Promise<IntentionReference[]> {
  const records = await allText(source);
  const calendar = await readJson<{ title: string }[]>(source, "calendar.json");

  return INTENTIONS.map((intent) => {
    let stated = 0;
    for (const rec of records) {
      if (intent.stated.some((s) => rec.text.includes(s))) stated++;
    }
    return {
      anchor: intent.anchor,
      statedMentions: stated,
      followedThrough: intent.followedThrough,
      evidenceEvents: calendar.filter((e) =>
        e.title.includes(`${intent.anchor} — booked`),
      ).length,
    };
  });
}

/* ------------------------------------------------------------------ */
/* Q16 — stated vs measured                                            */
/* ------------------------------------------------------------------ */

export interface MorningPersonReference {
  /** The "I am not a morning person" side. */
  statedClaims: number;
  commits: number;
  commitsBefore9: number;
  shareBefore9: number;
  medianCommitHour: number;
  /** True when the two sides disagree — which is the entire case. */
  conflict: boolean;
}

/**
 * Q16 is graded on *noticing a disagreement*, so both sides are computed
 * separately and the conflict is reported explicitly. If the two ever stop
 * disagreeing the case is vacuous, and `conflict: false` says so rather than
 * letting it pass quietly.
 */
export async function morningPersonReference(
  source: FixtureSource,
): Promise<MorningPersonReference> {
  const records = await allText(source);
  let claims = 0;
  for (const rec of records) {
    if (MORNING_CLAIMS.some((c) => rec.text.includes(c))) claims++;
  }

  if (!(await source.list()).includes("git_commits.json")) {
    return {
      statedClaims: claims,
      commits: 0,
      commitsBefore9: 0,
      shareBefore9: 0,
      medianCommitHour: 0,
      conflict: false,
    };
  }

  const commits = await readJson<{ authored_at: string }[]>(
    source,
    "git_commits.json",
  );
  // The **local** wall-clock hour is what "morning person" means. Reading the
  // UTC hour off a `-08:00` timestamp answers a different question by 8 hours,
  // and would report this user as a night owl.
  const hours = commits
    .map((c) => Number(c.authored_at.slice(11, 13)))
    .sort((a, b) => a - b);
  const before9 = hours.filter((h) => h < 9).length;

  return {
    statedClaims: claims,
    commits: commits.length,
    commitsBefore9: before9,
    shareBefore9: hours.length ? before9 / hours.length : 0,
    medianCommitHour: hours.length ? hours[Math.floor(hours.length / 2)]! : 0,
    conflict: claims > 0 && hours.length > 0 && before9 / hours.length > 0.5,
  };
}

/* ------------------------------------------------------------------ */
/* Q17 — entity-centric gather                                         */
/* ------------------------------------------------------------------ */

export interface PersonBriefReference {
  personId: string;
  aliases: string[];
  factAnchors: string[];
  factMentions: number;
  /** The confusable other person, whose facts must NOT appear in the brief. */
  confusableAliases: string[];
  confusableFactAnchors: string[];
}

/**
 * Q17 could previously only be graded on alias resolution, because there was
 * nothing to summarise. There are facts now, and the second Sarah has her own
 * distinct ones — so a failure to resolve identity produces a briefing that is
 * visibly about the wrong person rather than one that is merely thin.
 */
export async function personBriefReference(
  source: FixtureSource,
): Promise<PersonBriefReference> {
  const records = await allText(source);
  const present = (
    facts: readonly { anchor: string; text: string }[],
  ): string[] =>
    facts
      .filter((f) => records.some((r) => r.text.includes(f.text)))
      .map((f) => f.anchor);

  const sj = PEOPLE.find((p) => p.id === "sarah-johnson");
  const sn = PEOPLE.find((p) => p.id === "sarah-nguyen");

  let mentions = 0;
  for (const rec of records) {
    if (SARAH_JOHNSON_FACTS.some((f) => rec.text.includes(f.text))) mentions++;
  }

  return {
    personId: "sarah-johnson",
    aliases: sj ? [...sj.aliases] : [],
    factAnchors: present(SARAH_JOHNSON_FACTS),
    factMentions: mentions,
    confusableAliases: sn ? [...sn.aliases] : [],
    confusableFactAnchors: present(SARAH_NGUYEN_FACTS),
  };
}

/* ------------------------------------------------------------------ */
/* Q18 — conditional aggregation against a real intake source          */
/* ------------------------------------------------------------------ */

export interface NutritionReference {
  /** Days with any nutrition record — Q18's real denominator. */
  daysLogged: number;
  daysComplete: number;
  matchedDays: number;
  /** Run days with no nutrition record. The honest answer states this. */
  runDaysWithoutLog: number;
  meanKcalOnRunDays: number;
  meanKcalOtherDays: number;
  /** Complete days only — the more defensible figure. */
  meanKcalOnRunDaysCompleteOnly: number;
  /** What answering from expenditure instead of intake returns. */
  meanActivityCaloriesOnRunDays: number;
}

/**
 * The case previously stood on `oura_activity.total_calories`, which is energy
 * *expenditure*. On a 10km day expenditure rises and intake may not, so the
 * proxy does not add noise — it answers a different question with a similar
 * name. Both figures are returned so the gap is visible rather than assumed.
 */
export async function nutritionReference(
  source: FixtureSource,
  thresholdMetres = 10_000,
): Promise<NutritionReference> {
  if (!(await source.list()).includes("nutrition_log.json")) {
    return {
      daysLogged: 0,
      daysComplete: 0,
      matchedDays: 0,
      runDaysWithoutLog: 0,
      meanKcalOnRunDays: 0,
      meanKcalOtherDays: 0,
      meanKcalOnRunDaysCompleteOnly: 0,
      meanActivityCaloriesOnRunDays: 0,
    };
  }

  const nutrition = await readJson<
    { day: string; total_kcal: number; complete: boolean }[]
  >(source, "nutrition_log.json");
  const workouts = await readJson<
    { day: string; distance: number; source: string }[]
  >(source, "oura_workout.json");
  const activity = await readJson<{ day: string; total_calories: number }[]>(
    source,
    "oura_activity.json",
  );

  // Same dedup rule as `conditionalReference`: `manual` and `autodetected` can
  // describe one session, and double-counting changes which days qualify.
  const byDay = new Map<string, { day: string; distance: number }>();
  for (const w of workouts) {
    const existing = byDay.get(w.day);
    if (!existing || w.source === "autodetected") byDay.set(w.day, w);
  }
  const runDays = new Set(
    [...byDay.values()]
      .filter((w) => w.distance > thresholdMetres)
      .map((w) => w.day),
  );

  const nutByDay = new Map(nutrition.map((n) => [n.day, n]));
  const onRun: number[] = [];
  const onRunComplete: number[] = [];
  const other: number[] = [];
  let runDaysWithoutLog = 0;

  for (const day of runDays) {
    const row = nutByDay.get(day);
    if (!row) {
      runDaysWithoutLog++;
      continue;
    }
    onRun.push(row.total_kcal);
    if (row.complete) onRunComplete.push(row.total_kcal);
  }
  for (const n of nutrition) {
    if (!runDays.has(n.day)) other.push(n.total_kcal);
  }

  const mean = (xs: number[]): number =>
    xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;

  return {
    daysLogged: nutrition.length,
    daysComplete: nutrition.filter((n) => n.complete).length,
    matchedDays: onRun.length,
    runDaysWithoutLog,
    meanKcalOnRunDays: mean(onRun),
    meanKcalOtherDays: mean(other),
    meanKcalOnRunDaysCompleteOnly: mean(onRunComplete),
    meanActivityCaloriesOnRunDays: mean(
      activity.filter((a) => runDays.has(a.day)).map((a) => a.total_calories),
    ),
  };
}
