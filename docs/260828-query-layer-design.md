# Query layer for the Personal Server: problem framing and use cases

Status: **draft**. Part I (problem + question corpus) is settled and is what we
grade any design against. Part II is the solution space after an OSS prior-art
sweep: it proposes a shape, not an implementation plan.

## 1. Problem

A Personal Server holds a user's raw data: ChatGPT and Claude exports, Slack
and email archives, bank and brokerage statements, wearable and health
timeseries, calendar, photos metadata, browser history, purchase receipts,
PDFs. The volume is large (GBs), the shape is heterogeneous (dense numeric
timeseries next to 400MB of unstructured conversation JSON), and the schema is
whatever the exporting app happened to emit.

An external consumer — an app holding a read grant, or the user's own client —
asks a natural-language question and expects an answer that is **correct**,
**fast**, **attributable**, and **inside the grant boundary**.

Today nothing in the server answers questions. `packages/core/src/mcp/search`
is a MiniSearch lexical index over block text; `storage/index` is a per-scope
version ledger; `derivatives/compute.ts` stuffs the newest `maxSourceItems`
(default 50) items per source scope into a single LLM prompt and truncates at
200k characters. Those are the building blocks we have, not an answer layer.

## 2. What we have tried

| Approach                                                                        | Works for                                                              | Fails at                                                                                                                                                                                                              |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Raw data + coding agent** (Claude/Codex/Gemini CLI turned loose on the files) | Almost anything, given time. Can write its own aggregation on the fly. | Latency (minutes), cost, nondeterminism — two runs give two answers. Not a thing you put behind a request/response API.                                                                                               |
| **RAG over embeddings**                                                         | "What did I say about X", topical recall, fuzzy semantic lookup.       | Anything requiring completeness or arithmetic. Top-k retrieval structurally cannot answer "average over the last month" — it returns 8 chunks out of 30 nights and averages those. Silently wrong, not visibly wrong. |
| **Raw data straight to an LLM**                                                 | Small scopes, recent windows.                                          | Context window. Also degrades before it overflows: recall of a single fact inside a 500k-token dump is unreliable, and the truncation heuristic ("newest 50 items") decides the answer more than the model does.      |

The shared failure: **each approach has one retrieval strategy and applies it
to every question**, while the questions differ in what "correct" even means.
An average needs _every_ row. A theme needs _representative_ rows. A trait
inference needs _enough_ rows. A needle lookup needs _the one_ row.

## 3. The question corpus

Every entry: the question as a user would type it, the data it touches, what
makes it hard, and what an accurate answer would actually require. The last
column is the one that matters — it is the requirement, not the design.

---

### Q1. "How much did I sleep on average over the last month?"

- **Data:** Oura / Apple Health / Whoop sleep records. Dense numeric timeseries, one row per night, well-typed.
- **Class:** Exact aggregation over a bounded window.
- **Hard because:** trivially easy _if_ the data is parsed into rows and _if_ the window is complete. Neither is guaranteed: the export may have gaps, may span timezone changes, may double-count naps versus main sleep, and may have two devices reporting the same night.
- **Accurate answer requires:** a complete row set for the window, a stated denominator ("28 of 31 nights had data"), an explicit definition (total sleep time vs time in bed), and deduplication across overlapping sources. The number must be reproducible — same question, same data, same answer, byte for byte.

### Q2. "What was my main focus this week?"

- **Data:** Slack, email, ChatGPT conversations, calendar, git activity. Unstructured text across 5 sources.
- **Class:** Multi-source thematic synthesis over a bounded window.
- **Hard because:** there is no field called "focus". The answer is a clustering-and-ranking judgement over hundreds of small artifacts, weighted by something (volume? time spent? who else was involved?) that the user never specified.
- **Accurate answer requires:** coverage of the window across all granted sources (not top-k from one), a defensible weighting the answer can state ("most of your calendar hours and 60% of your Slack messages were about X"), and citations back to specific artifacts. Failure mode to design against: the loudest source dominating — 2000 Slack messages drowning out the 3 documents that were the actual week.

### Q3. "What is my financial risk appetite?"

- **Data:** bank statements, brokerage trades, Polymarket/betting activity, crypto wallets, ChatGPT conversations where the user talks about money, purchase history.
- **Class:** Latent trait inference. No record in the corpus states the answer.
- **Hard because:** it requires composing several intermediate quantities the user never asked for — volatility of holdings, position sizing relative to income, drawdown behavior (did they sell at the bottom?), frequency of speculative bets, stated vs revealed preference. Each is itself a Q1-style aggregation. Then those get synthesized into a judgement.
- **Accurate answer requires:** the ability to _decompose_ the question into computable sub-questions, compute each exactly, and reason only over the results. It also requires calibrated uncertainty: "moderate-to-high, based on 14 months of brokerage data; no data on retirement accounts or income, so this may be unrepresentative."

### Q4. "Did my sleep affect my productivity last quarter?"

- **Data:** sleep timeseries × git commits / calendar / Linear tickets / typing activity.
- **Class:** Cross-source correlation on a shared time axis.
- **Hard because:** joining a nightly record to a "productivity" proxy requires (a) picking the proxy, (b) aligning to the same day boundary and timezone, (c) enough n to say anything, and (d) resisting the urge to state a correlation as a cause.
- **Accurate answer requires:** an explicit join key, an explicit proxy definition surfaced to the user, a real statistic with n and spread, and a refusal to over-claim. Nothing about this is retrievable — it must be _computed_.

### Q5. "What was the name of that Thai restaurant Sarah recommended?"

- **Data:** iMessage/WhatsApp/Slack DMs, email, possibly a ChatGPT thread where the user asked about it later.
- **Class:** Needle in a haystack. Single fact, exact recall.
- **Hard because:** the fact appears once, possibly years ago, in one message, possibly misspelled, possibly as a link with no name in the text. Semantic search may retrieve the right _conversation_ and still miss the message. Recency-truncation guarantees a miss.
- **Accurate answer requires:** unbounded-time exhaustive search over the granted text, entity resolution ("Sarah" → one of four Sarahs), and an honest "not found" rather than a plausible hallucinated restaurant. This is the question where a wrong answer is indistinguishable from a right one to the user.

### Q6. "How many distinct people did I talk to last month, and who were the top 10?"

- **Data:** email, Slack, calendar attendees, phone/messages, contacts.
- **Class:** Cardinality + ranking with entity resolution.
- **Hard because:** the same human is `sarah@work.com`, `sarahj@gmail.com`, `@sjohnson` in Slack, "Sarah Johnson" in calendar, and "Sarah 🌸" in contacts. Counting rows gives a wildly wrong number. Also: does a mailing list count? A calendar invite you declined?
- **Accurate answer requires:** a cross-source identity graph, a stated inclusion rule, and exact counting over the resolved set.

### Q7. "What are my recurring monthly expenses, and which ones have crept up?"

- **Data:** bank statements, card transactions, receipt emails, App Store/subscription confirmations.
- **Class:** Pattern detection + grouping + period-over-period comparison.
- **Hard because:** "recurring" is inferred (same-ish merchant, same-ish amount, ~30-day cadence), merchant strings are dirty (`SQ *BLUE BOTTLE 9821`), amounts drift, and annual subscriptions look like noise at monthly granularity. Currency conversion if the user travels.
- **Accurate answer requires:** normalization of merchant identity, cadence detection over the full history (not a window), exact arithmetic on the grouped set, and a diff against a prior period with the comparison basis stated.

### Q8. "Have I ever agreed to anything that conflicts with this contract?"

- **Data:** email, signed PDFs, Slack, DocuSign confirmations, calendar.
- **Class:** Absence/exhaustiveness question ("have I ever…", "is there any…").
- **Hard because:** a confident "no" is only valid if the search was _complete_. Any sampling, truncation, or top-k retrieval makes "no" unjustifiable. Also spans binary documents (PDF, scans) that may not be text-extracted at all.
- **Accurate answer requires:** either an exhaustive pass over the granted corpus, or an answer that explicitly scopes its own confidence ("no match across 12k emails and 340 PDFs; 22 scanned documents could not be read"). The system must know what it did **not** look at.

### Q9. "When did I first start thinking about leaving my job?"

- **Data:** ChatGPT/Claude conversations, journal entries, Slack DMs, search history, calendar (recruiter calls).
- **Class:** Temporal first-occurrence over a fuzzy concept.
- **Hard because:** the concept has no keyword. Early instances are oblique ("is 4 years a long time to be somewhere?"). The answer is a date, but finding it requires semantic judgement over the full timeline, and the _earliest_ match matters — exactly the one that ranking-by-relevance buries.
- **Accurate answer requires:** semantic matching combined with ordering by time rather than score, and evidence for the specific earliest artifact.

### Q10. "What changed in how I think about X over the last two years?"

- **Data:** long-form conversations, notes, published writing, saved articles.
- **Class:** Diachronic comparison — same topic, two time slices, contrast.
- **Hard because:** requires representative sampling from _both_ ends of the period and a comparison, not a summary. Naive retrieval returns the most relevant chunks regardless of date, which are usually all recent.
- **Accurate answer requires:** time-stratified retrieval (guaranteed coverage per period), then contrast. Also needs to distinguish "my view changed" from "the topic changed".

### Q11. "Was my resting heart rate unusual last week?"

- **Data:** wearable timeseries.
- **Class:** Anomaly detection against a personal baseline.
- **Hard because:** "unusual" is relative to _this user's_ distribution, which requires the full history, not the window in question. Seasonality (training blocks, illness, alcohol) matters.
- **Accurate answer requires:** a baseline computed over a long history, a stated threshold, and the arithmetic to be exact. Cheap to compute, impossible to retrieve.

### Q12. "Which of my data has app X seen, and what could it infer from it?"

- **Data:** the server's own grant records, access logs (`packages/core/src/mcp/activity.ts`), lineage graph.
- **Class:** Introspection over metadata, not content.
- **Hard because:** it is a question about the server itself, and the second half ("what could it infer") is a reasoning question over the _shape_ of the released data. Also the one question where the answer must never be served to the app itself.
- **Accurate answer requires:** exact enumeration from the grant/access ledger, plus lineage traversal (a derivative released to an app implies exposure of what it was computed from, in aggregate).

### Q13. "Plan my week around my energy levels."

- **Data:** calendar (future), sleep/HRV history (past), task list, historical patterns of when the user did good work.
- **Class:** Forward-looking synthesis mixing historical aggregation with future-state data.
- **Hard because:** it joins a _predicted_ quantity derived from history against records that do not exist yet, and the output is a plan, not a fact. Freshness matters — a calendar read from an hour-old snapshot is wrong.
- **Accurate answer requires:** a real aggregation over history, live-enough future data, and clear separation in the answer between what is measured and what is projected.

### Q14. "How much did I spend on my Japan trip?"

- **Data:** transactions, photos metadata (geo), calendar, flight/hotel confirmations, currency rates.
- **Class:** Aggregation over an implicitly-defined set.
- **Hard because:** the _set membership_ is the hard part, not the sum. "The Japan trip" is a date range the user never stated, inferred from flights or photo geodata; then transactions must be attributed to it (including a pre-paid hotel charged two months earlier, and the flight itself). Multi-currency.
- **Accurate answer requires:** a two-stage answer — resolve the entity ("Japan trip = Mar 3–17"), state that resolution to the user, then aggregate exactly over the resolved set with FX applied at transaction date.

### Q15. "What do I keep saying I'll do but never do?"

- **Data:** task lists, notes, chat messages, calendar.
- **Class:** Cross-referencing intent against outcome; requires negative evidence.
- **Hard because:** it needs to find stated intentions (scattered, phrased a hundred ways) _and then prove absence_ of follow-through — an exhaustiveness problem (Q8) run once per candidate intention.
- **Accurate answer requires:** high-recall extraction of intent statements, then a completeness-guaranteed check for each. Expensive by construction; the interesting question is how to bound it.

### Q16. "Am I a morning person?"

- **Data:** sleep timing, commit timestamps, message timestamps, calendar acceptance patterns, self-descriptions in conversations.
- **Class:** Measured behavior vs self-report, potentially in conflict.
- **Hard because:** the corpus contains both a stated answer ("I'm not a morning person" said in a ChatGPT thread) and a measured answer (median first commit at 07:12). A good answer notices the conflict rather than picking whichever source it retrieved.
- **Accurate answer requires:** treating stated claims and behavioral aggregates as distinct evidence types and reporting disagreement.

### Q17. "Summarize everything I know about [person] before my meeting with them."

- **Data:** email threads, meeting notes, Slack, CRM, shared docs, calendar history.
- **Class:** Entity-centric gather across all sources.
- **Hard because:** the unit of retrieval is an entity, not a query string. Requires the identity graph from Q6, plus recency weighting, plus knowing when to stop (500 emails with this person over 6 years).
- **Accurate answer requires:** entity resolution, coverage across all granted sources, and a principled compression — recent + important, with importance derived from something, not vibes.

### Q18. "How many calories do I typically eat on days I run more than 10km?"

- **Data:** nutrition log × workout timeseries.
- **Class:** Conditional aggregation — a filter on one source driving an aggregate on another.
- **Hard because:** it is a `GROUP BY` across two independently-shaped datasets with a day-boundary join and a sparse left side (nutrition logging is partial). Sampling either side breaks it.
- **Accurate answer requires:** an exact join, honest handling of days where one side is missing, and the n reported.

---

## 4. What the corpus tells us

### 4.1 Question classes

Grouping Q1–Q18 by what "correct" means:

| Class                        | Examples              | Correctness criterion                                                                                                               |
| ---------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Exact aggregation**        | Q1, Q7, Q11, Q14, Q18 | Every qualifying row included; arithmetic exact; denominator stated. Sampling is a bug.                                             |
| **Exhaustive / absence**     | Q5, Q8, Q15           | Full-corpus coverage, or an explicit statement of what was not searched. A confident wrong "no" is the worst failure in the system. |
| **Representative synthesis** | Q2, Q10, Q17          | Coverage-balanced sampling; no single loud source dominating; citations.                                                            |
| **Latent inference**         | Q3, Q16               | Decomposition into computable sub-facts, then bounded reasoning over the results, with calibrated confidence.                       |
| **Relational / join**        | Q4, Q6, Q18           | Correct join keys and entity resolution before any aggregation happens.                                                             |
| **Entity resolution**        | Q5, Q6, Q14, Q17      | The set must be resolved and _stated_ before it is used.                                                                            |
| **Introspection**            | Q12                   | Answered from server metadata, never from content; must not be answerable by the party it is about.                                 |

The load-bearing observation: **these classes need different retrieval
guarantees, and the class is a property of the question, not of the data.**
The same sleep scope serves Q1 (needs all rows), Q11 (needs all history for
baseline, one week for the test) and Q4 (needs a join).

### 4.2 Data-shape taxonomy

| Shape                                  | Examples                                     | What it affords                                                                              |
| -------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Dense numeric timeseries               | sleep, HR, steps, weight                     | Exact aggregation, baselines, joins on a time axis. Cheap if parsed once.                    |
| Transactional / semi-structured events | bank, purchases, commits, calendar           | Grouping, cadence detection, but needs normalization (merchant strings, currency, timezone). |
| Long-form conversational text          | ChatGPT/Claude exports, Slack, email         | Semantic recall, theme extraction. No arithmetic. Huge. Mostly worthless per token.          |
| Documents / binary                     | PDFs, scans, images                          | Often not text at all. Silent coverage gaps (Q8).                                            |
| Relational / graph                     | contacts, org charts, attendee lists         | Identity resolution, entity-centric gather.                                                  |
| Server metadata                        | grants, access logs, lineage, index versions | Introspection; also the substrate for "what did I not look at".                              |

The same _scope_ can hold several shapes (a ChatGPT export is text, but it is
also an event stream with timestamps that supports Q9 and Q16).

### 4.3 Cross-cutting requirements the corpus forces

1. **The system must know what it did not read.** Half the questions can only be answered honestly with a coverage statement. Any layer that cannot report its own coverage cannot answer Q1, Q8 or Q15 correctly.
2. **Determinism where determinism is possible.** Q1, Q7, Q14, Q18 must return the same number twice. An LLM in the arithmetic path forfeits this.
3. **Grant boundaries are part of correctness, not a wrapper.** A consumer holding a grant on `oura.sleep` asking Q4 must not get an answer computed from `github.commits`. Any index that spans scopes must be able to answer _within_ a subset without leaking. Derivatives already carry this rule (a grant on a derived scope confers nothing on its sources, and vice versa) — the query layer inherits it.
4. **Entity resolution is a prerequisite, not a feature.** Q5, Q6, Q14, Q17 are unanswerable without it, and it is shared infrastructure across all of them.
5. **Freshness varies by question.** Q13 needs live calendar; Q3 is fine on week-old data; Q11 needs a long-history baseline that changes slowly. One staleness policy will be wrong for most questions.
6. **Cost must be bounded before execution, not discovered during it.** Q15 is unbounded by construction. The system needs to know the cost class of a question before running it, and to be able to say "this is a 40-second question".
7. **Answers need attribution.** Citations to specific records are what makes the difference between an answer and a guess — and lineage already gives us the vocabulary for it.
8. **Honest failure beats a plausible answer.** Especially Q5 and Q8. "I searched X and found nothing" must be a first-class result.

## 5. Open questions carried into Part II

- Which classes must be exact and which may be approximate — and does the _consumer_ get to choose, or the server?
- Do we pre-compute per shape (parse timeseries into rows at ingest) or on first question? What is the trigger, and who pays?
- Is the answer unit a derivative record (durable, lineage-carrying, cacheable, re-servable) or a transient response? The `derivatives` module already makes the first one possible.
- How does a consumer express a question class, or do we classify server-side?
- How does the query layer report coverage in a way an external app can act on?
- What is the acceptable latency envelope per class — and what does the consumer see while a slow question runs?
- Where does entity resolution live, and is the identity graph itself a scope (and therefore grantable)?

---

# Part II — Solution space

Sourced from a six-track OSS prior-art sweep (agent memory; NL→SQL and semantic
layers; GraphRAG and entity resolution; personal-KB and company-brain systems;
routing and agentic retrieval; the embedded Node stack). Raw notes live in the
scratchpad research files; only conclusions are here.

## 6. What the prior art settles

**6.1 Nobody has built this.** Every OSS personal "second brain" (Khoj, Reor,
Obsidian Smart Connections, Karakeep, screenpipe) is the same pipeline: chunk →
embed → top-k → LLM. All are single-user with no permission model, and none can
answer Q1. Company-brain systems (Onyx, Glean, R2R, Morphik, Airweave) add
hybrid retrieval and connector-synced ACLs but share the same aggregation blind
spot. Agent-memory systems (Mem0, Zep/Graphiti, Letta, Cognee, Memobase) are
benchmarked exclusively on QA-over-narrative-text; exact aggregation over
structured records is unbenchmarked territory industry-wide.

The two systems that _do_ answer Q1-class questions reject RAG entirely:
karlicoss's **HPI** (exports → typed objects → pandas) and Simon Willison's
**Dogsheep/Datasette** (exports → SQLite → SQL). Neither has an NL interface or
a permission model. Airweave is our closest architectural sibling (connectors →
normalization → embed → unified retrieval over MCP) and still only produces
embeddings, not computable records.

So: exact aggregation + grant-scoped answering + open-ended NL over personal
data is genuinely unsolved. We reuse components, not a system.

**6.2 The split is the finding.** Independently, four of six tracks converged on
the same rule: **normalize structured data into a relational substrate and
compute exactly over it; use embeddings only for descriptive text.** Top-k
retrieval has no "return ALL matching rows" guarantee, so no amount of RAG
tuning fixes Q1/Q7/Q18. This is the load-bearing decision in the design.

The honest caveat: this argument is about _retrieval_. An agent that writes and
runs code over raw files is a third option with a different failure profile,
evaluated on its own terms in §15.

**6.3 A knowledge graph is not worth its cost.** Microsoft GraphRAG indexes a
corpus for $200–$33,000; their own 2025 follow-up (LazyGraphRAG) drops
index-time summarization, matches global-query quality and cuts query cost
~700x. SlimRAG (a flat entity→chunk table, no graph) beats graph baselines on a
fraction of the index tokens. We should not build a KG. Two narrow patterns are
still worth stealing:

- **Bi-temporal facts** (Graphiti): every extracted fact carries valid-time and
  transaction-time, and superseded facts are invalidated rather than deleted.
  This is the only prior art that directly answers Q9 and Q10.
- **Flat entity/alias table** (SlimRAG): `person_id → aliases`,
  `person_id → chunk_ids`. Answers Q6/Q17 with no graph engine.

**6.4 The semantic layer, not the model, drives NL→SQL accuracy.** BIRD (real
DBs, 93% human ceiling): ~82% execution accuracy. Spider 2.0 (messy,
1000+-column schemas): ~55–58% — which is where raw auto-inferred tables from
personal exports would land. The dominant error is schema linking, not SQL
syntax. Cube's paired benchmark shows +17–23pp from a ~4KB markdown
"measures and disambiguation" doc, with model choice statistically
insignificant. A curated per-connector semantic layer is therefore mandatory,
not a nicety — and it is authored once per connector by us, never by the user.

**6.5 Permissions bind early.** Elastic/OpenSearch DLS, Onyx and Glean all
compile the ACL predicate into the retrieval query as a mandatory filter, never
a post-hoc filter the model could reason around. Our grant scopes must enter
the same way.

**6.6 Vendor benchmark numbers are unreliable.** The Mem0-vs-Zep LoCoMo dispute
spans 58%–92% for the same pair depending on who ran it; an independent eval
found Mem0's OSS SDK at 32.4% on LongMemEval against a self-reported 93.4%.
Nothing in this document should be adopted on a vendor's self-reported score.

## 7. The transformations we need

Each is a **derivative**: a derived scope carrying `$lineage` back to its
sources, written through the existing write path, invalidated by the existing
`derivatives/scheduler.ts` when a source changes. That gives us incremental
reindexing, provenance and grant isolation for free, and makes every index a
first-class, inspectable, deletable piece of user data rather than hidden
server state.

| #   | Transformation                                                                                                                                                                                                                                                                                    | Produces                  | Serves                    | Cost                                                           |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ------------------------- | -------------------------------------------------------------- |
| T1  | **Parse → typed rows.** Per-connector parsers into relational tables (Dogsheep's proven shape). DuckDB `read_json_auto` assists inference for unknown exports, but the schema is **frozen and versioned**, never re-inferred per batch.                                                           | `derived.<source>.tables` | Q1, Q4, Q7, Q11, Q14, Q18 | Cheap, deterministic, no LLM                                   |
| T2  | **Semantic layer.** Per-connector metric/dimension definitions + disambiguation notes, authored by us, shipped with the connector.                                                                                                                                                                | static, versioned         | every T1 question         | One-time authoring                                             |
| T3  | **Chunk + hybrid index.** Block-level chunks (the `storage/blocks` manifest already does this) into FTS5 + vectors, RRF-fused. Anthropic's contextual-retrieval prefix (an LLM-written blurb per chunk) cuts retrieval failure 49% / 67% with reranking — worth it only where recall is critical. | `derived.<source>.index`  | Q2, Q5, Q9, Q10, Q17      | Embedding pass: tens of minutes to hours, one-time, background |
| T4  | **Entity/alias table.** Deterministic canonicalization → probabilistic match → LLM judge on the ambiguous residual only.                                                                                                                                                                          | `derived.identity`        | Q5, Q6, Q14, Q17          | Moderate, mostly non-LLM                                       |
| T5  | **Bi-temporal fact extraction.** Only over conversational/journal text, only for questions that need it.                                                                                                                                                                                          | `derived.facts`           | Q9, Q10, Q16              | Expensive per chunk — make it lazy and narrow                  |
| T6  | **Enrichment columns.** LLM-derived columns materialized back onto T1 rows (merchant normalization, trip clustering, expense category) — Datasette's enrichment pattern. Schema inference can never produce these.                                                                                | columns on T1             | Q7, Q14                   | Bounded, batched, one pass per new row                         |

Not doing: GraphRAG community summarization (6.3), a general KG, per-user
hand-authored models.

## 8. Answering shape

**Classify, then dispatch.** A cheap classifier maps the question to a class
from §4.1 and dispatches to a strategy, rather than handing one agent every
primitive and hoping. Evidence: Copilot's 40→13 tool cut bought +2–5pp accuracy
and −400ms, and their winning selector was a cheap embedding pre-filter (94.5%
coverage) over raw LLM judgment (87.5%); using a frontier model for trivial
classification costs 10–15x more for worse results. Our tool count is small, so
this is about _routing quality_, not tool-count collapse.

Per class:

- **Exact aggregation** → generated SQL over T1+T2. Deterministic, and the
  arithmetic never touches an LLM.
- **Exhaustive/absence** → deterministic full scan over an enumerable scope
  (FTS5/SQL), never top-k. Completeness comes from the scan being total over a
  known corpus, not from a retrieval model's statistics. Return coverage
  metadata (rows scanned, scopes, unreadable items) with the negative.
- **Representative synthesis** → time-stratified and source-balanced sampling
  over T3, so one loud source cannot dominate.
- **Latent inference** → decompose into computable sub-questions, run each as
  above, reason only over results. Decomposition measurably beats one-shot
  retrieval on multi-hop (IRCoT).
- **Relational/join** → T4 resolves entities first, then T1 SQL.
- **Introspection** → grants/access log/lineage only, never content.

**Answers are derivatives.** A computed answer is written back as a derived
record with lineage, which makes it cacheable, re-servable, auditable, and
subject to the same grant isolation. The existing question-registration +
staleness scheduler already implements this loop; the query layer replaces
`compute.ts`'s "newest 50 items, 200k chars, one prompt" with real retrieval.

**Grants compile into the query** (6.5): the scope predicate is a WHERE clause
and an index filter, not a post-filter.

## 9. MCP surface

Consensus across Copilot/AWS/Speakeasy/Arcade: neither one opaque `ask()` nor
raw primitives (`sql()`, `vector_search()`), but a handful of workflow-scoped
tools with rich descriptions. We already ship `list_granted_scopes`,
`read_scope`, `list_scope_blocks`, `search_personal_context`, `get_scope_file`
— primitives with no compute. The gap is one tool per question class, e.g.
`query_structured`, `search_exhaustive` (returns coverage), `search_thematic`,
`investigate`. Anthropic's code-execution-with-MCP pattern (model writes code
against tools instead of passing raw results through context) is the right
escape hatch for the long tail — see §16.

## 10. Stack

`better-sqlite3` + FTS5 + `sqlite-vec` is the primary path (FTS5 ships with
better-sqlite3; `node:sqlite` does not reliably support FTS5 or extension
loading yet). sqlite-vec is comfortable to a few million vectors; LanceDB is
the upgrade path. DuckDB is worth its 71MB/platform only as an
ingestion-time schema-inference and bulk-aggregation engine — its VSS extension
is not viable (HNSW must fit in RAM, experimental persistence, non-incremental
rebuilds). Embeddings via transformers.js (bge-small / all-MiniLM class).
PS-Lite takes no native modules: Orama (Apache-2.0, full-text + vector + RRF,
identical in Node and browser) is the one candidate that could unify both
paths, at some quality cost.

## 11. Risks

1. **NL→SQL accuracy is the whole bet on exactness.** If we land at Spider 2.0's
   ~55% rather than BIRD's ~82%, the layer is not trustworthy for financial or
   health arithmetic. Mitigation is T2 quality and a graded question set; this
   must be measured before it ships.
2. **Schema drift.** DuckDB's inference is sample-dependent and degrades past
   ~24 keys on an object. Freeze and version schemas per connector; never
   silently reshape types on incremental sync.
3. **Connector-bound coverage.** T1 only exists for sources we have written
   parsers for. Everything else degrades to T3 text search — and the system
   must say so rather than answer anyway.
4. **First-index cost.** Embedding a heavy export is a background job measured
   in tens of minutes to hours; ~100–300 embeddings/sec is a planning estimate
   only, and needs a real benchmark on our chunk sizes before we commit.
5. **PS-Lite divergence.** No native modules and no local inference means a
   materially weaker answer path; decide deliberately what it degrades to.
6. **Billing and logging.** A sweep across many scopes has per-scope payment and
   access-log consequences that a single `read_scope` did not.

## 12. Worked examples: Oura, Spotify, ChatGPT

Schemas and volumes below are verified against official docs and real export
samples except where marked. The point of this section is that **the
transformation matrix is sparse** — no source gets all six.

|                      | Oura     | Spotify                         | ChatGPT                   |
| -------------------- | -------- | ------------------------------- | ------------------------- |
| Bytes that are prose | ~0%      | ~5%                             | ~100%                     |
| Rows                 | ~10^5    | 227,024 (real 10yr sample)      | ~10^4 messages            |
| T1 parse → rows      | ✅ core  | ✅ core                         | metadata only             |
| T2 semantic layer    | ✅       | ✅                              | thin                      |
| T3 chunk + embed     | ❌ never | ❌ (FTS on track/artist only)   | ✅ core                   |
| T4 entity/alias      | ❌       | artist/track ids, deterministic | ✅ (people named in text) |
| T5 bi-temporal facts | ❌       | ❌                              | on demand only            |
| T6 enrichment        | ❌       | genre/mood, optional            | ❌                        |

### 12.1 Oura — pure T1/T2

API v2 `usercollection/{daily_sleep, sleep, daily_activity, daily_readiness,
heartrate, workout, daily_spo2}`. `sleep` carries `bedtime_start`,
`bedtime_end`, `total_sleep_duration`, `deep_sleep_duration`,
`rem_sleep_duration`, `average_hrv`, `efficiency`, `latency` (durations in
seconds); `daily_activity` has `steps`, `active_calories`, `total_calories`;
`daily_readiness` has `score`, `temperature_deviation`; `heartrate` is
`{bpm, source, timestamp}` at ~5-minute cadence during sleep.

Three years ≈ a few thousand daily rows plus 100k+ heart-rate samples. T1 is
one streaming pass into seven tables; seconds of CPU, no LLM, fully
deterministic. **Q1 becomes `SELECT AVG(total_sleep_duration)/3600 FROM sleep
WHERE day BETWEEN ? AND ?` — with `COUNT(*)` as the denominator the answer must
report.** Q11's baseline is a window function over the same table.

The gotcha is why this needs a written parser and not schema inference: a day
can have **multiple sleep periods** (naps), so `sleep` rows must be grouped by
`day` and are not 1:1 with `daily_sleep`. Get that wrong and every sleep
average is wrong, silently. T2 is where "sleep" is defined as main-period
`total_sleep_duration`, not time in bed, not naps included.

**Corrections, verified 2026-08-28 against the Oura API v2 OpenAPI spec (1.37)
during phase 6a.** The paragraph above understates the trap and gets one detail
wrong:

- **`type` has five values, not two.** Besides `long_sleep` and `late_nap`
  there are `deleted` (user-deleted) and `rest` (falsely detected, rejected by
  the user), which must be excluded from _every_ calculation — nap questions
  included. This is a nastier trap than naps, because filtering
  `type === "long_sleep"` dodges it by luck while `type !== "late_nap"` walks
  straight into it.
- **`daily_sleep` carries no duration field at all** — only `score` and
  `contributors`. "Not 1:1 with `daily_sleep`" above implies you could get a
  duration there. You cannot.
- **`total_sleep_duration` is nullable**, and is not `time_in_bed`.
- **The sleep day changes at 18:00** (stated in the `late_nap` enum
  description). Bucket by the `day` field; never re-derive it from
  `bedtime_start`. `bedtime_*` are localized strings with UTC offsets, so
  `new Date(x).toISOString().slice(0,10)` shifts the date. **This is not a
  timezone edge case:** `day` is the morning the sleep _ends_ while
  `bedtime_start` is the evening before, so re-deriving the date is wrong for
  **~82% of rows** (1043 of 1276 measured in phase 1) regardless of offset.
- **`heartrate.source` ∈ `awake|workout|rest|sleep|live|session`.** An
  unfiltered resting-HR baseline (Q11) is contaminated by workout samples.
- **`workout.distance` is in meters** (Q18's "10km" is `> 10000`), and
  `workout.source` includes both `manual` and `autodetected`, so one session
  can appear twice.
- **`sleep_algorithm_version`** v1/v2 makes multi-year baselines
  non-comparable.
- The collection list above is a subset; the API also serves `daily_stress`,
  `daily_resilience`, `daily_cardiovascular_age`, `vO2_max`, `sleep_time`,
  `session`, `tag`, `enhanced_tag`, `rest_mode_period`, `ring_configuration`
  and `personal_info`.

Embedding any of this would be pure waste — and worse, it would make Q1
unanswerable, since top-k retrieval cannot average.

### 12.2 Spotify — T1/T2, cheap at scale

`Streaming_History_Audio_<years>_<n>.json`, ~12MB chunks. Confirmed fields:
`ts`, `ms_played`, `master_metadata_track_name`,
`master_metadata_album_artist_name`, `spotify_track_uri`, `reason_start`,
`reason_end`, `shuffle`, `skipped`, `offline`, `incognito_mode`. A real
ten-year heavy user: **227,024 records, ~155MB**.

Quarter of a million rows, and it is still the cheap source: one table, ~a
minute of parsing, no LLM. Listening-history questions ("what did I have on
repeat during that project", "did my music change when I started sleeping
badly") are `GROUP BY` and a join to Oura on date — never retrieval.

Gotchas, all of which defeat naive inference: podcast and track rows **share
one schema** with no type flag (discriminate by which field cluster is
non-null); `skipped` alone is unreliable, real parsers use
`skipped OR reason_end IN ('backbtn','unknown','endplay','fwdbtn')`; ~2.6% of
rows have overlapping timestamps and need dedup. Each of these is a T2/parser
decision, made once by us, not by the user and not by a model at query time.

**Corrections, verified 2026-08-28 during phase 6a:**

- **There are two different exports with the same filename, and picking the
  wrong one is a silent decade-to-year error.** The _account data_ package's
  streaming history covers **the past year only**, with `endTime` / `msPlayed`
  / `trackName`. The _extended streaming history_ package is lifetime, with
  `ts` / `ms_played` / `master_metadata_*`. An agent handed the account-data
  file answers a ten-year question with twelve months and nothing indicates a
  problem. This belongs at the top of the Spotify profile, not in a gotcha
  list.
- **Rows are audio, video _and_ podcast** — three field clusters, not the two
  described above.
- The field list above omits `ip_addr`, `user_agent`, `username`,
  `offline_timestamp` and `spotify_episode_uri`. The first three are PII that
  no listening answer needs and must not be carried into a result.
- **`reason_end`'s vocabulary and the 2.6% duplicate rate could not be traced
  to a primary source** and are _not_ verified. The shipped profile therefore
  instructs the agent to enumerate the distinct `reason_end` values actually
  present and to _measure_ the duplicate rate, then state both — which is more
  accurate than either constant and consistent with the host-authored-coverage
  rule in the prompt contract §1.

### 12.3 ChatGPT — the only source that pays for T3

`conversations.json`: an array of conversations, each with a `mapping` dict of
`{id, message, parent, children}` nodes; a message is
`{author:{role}, create_time, content:{content_type, parts}, metadata}`.
Heavy 2–3 year user: **100–200MB**, and the export is a **full snapshot every
time — never incremental**.

The correctness gotcha is structural: edits and regenerations appear as
**sibling children, not overwrites**. Flattening `mapping.values()` by
timestamp double-counts abandoned branches. The only correct reconstruction is
to walk `current_node` back through `parent` to the root and reverse. Any
question that counts, dates, or quotes messages is wrong without this — and no
generic JSON→table inference will discover it.

**Additional traps, verified 2026-08-28 during phase 6a against a maintained
export parser:**

- **`create_time` is nullable on messages.** Coerced to epoch, a null becomes
  the "earliest" record — which silently destroys Q9 ("when did I first…"),
  the one question whose whole answer is a minimum date.
- **`content.parts` is nullable and holds `str | dict`.** `parts.join("")`
  corrupts char counts and can throw.
- **Hidden, system and tool messages** mean even a correct `current_node` walk
  over-counts unless the answer states which roles it included.

T1 here is thin but real: one row per message (id, conversation, role,
create_time, char count) so that Q9/Q16-style questions can order and count
without touching prose. T3 is the expensive part and this is the one source
that earns it.

## 13. Why this is not six passes over the data

**13.1 It is one pass over raw bytes, then a cascade over shrinking inputs.**
T1 streams the raw export once and emits rows. T3 chunks from the
`storage/blocks` manifest that ingest already builds. T4 reads T1's rows, not
the raw file. T5 and T6 read T1/T3 outputs. Each stage's input is smaller than
the last:

```
raw exports        ~355 MB   (Oura + Spotify + ChatGPT)
  → T1 rows         ~50 MB   one streaming pass, no LLM
  → T3 chunks       text only — Oura and Spotify contribute nothing
  → T4 entities     thousands of rows
  → T5 facts        hundreds, and only if asked for
```

The word "six transformations" describes the catalogue, not the work done on
any given byte.

**13.2 Ingest costs zero LLM calls.** T1, T2 and the lexical half of T3 are
deterministic. That matters more than any efficiency argument: it is what makes
Q1 reproducible.

**13.3 Content-addressed chunk ids are the single biggest cost lever.**
Because ChatGPT exports are full snapshots, a naive pipeline re-embeds the
entire corpus on every sync. Keying chunks by message id + content hash means a
re-export embeds only genuinely new messages — a monthly delta of a few
thousand chunks rather than the whole history. Same for Spotify's overlapping
rows and Oura's re-fetched days. Without this, every design in this document is
too expensive; with it, first index is a one-time cost and steady state is
negligible.

**13.4 Deterministic context beats LLM context blurbs here.** Anthropic's
contextual retrieval pays an LLM per chunk because arbitrary documents lack
metadata. A ChatGPT chunk already knows its conversation title, date, thread
position and role — prepend that for free and skip ~10^5 LLM calls. Reserve
LLM-written context for genuinely context-free material (scanned PDFs).

**13.5 T5 and T6 are demand-driven, and run over summaries.** Fact extraction
per message (~10^4–10^5 calls) does not work. Per conversation (~10^3), once,
only when a registered question needs it, does. The existing question
registration + staleness scheduler is exactly the right trigger: an index is
built because something asked for it, and rebuilt when its sources change.

**13.6 Everything is a derivative, so the work is resumable and inspectable.**
Each artifact above is a derived scope with `$lineage` to its sources. Partial
progress survives restart, the user can see and delete any index, and
`dataStatus: "indexing"` already exists in `ScopeSummary` to report a
half-built one instead of silently answering from it.

**Rough first-index budget** for the three sources above: Oura and Spotify are
seconds-to-a-minute of deterministic parsing. ChatGPT is one parse pass plus an
embedding job whose duration follows the throughput estimate in §11.4 — a
background job with progress, never blocking a query. Steady state after that
is a few thousand new chunks per month.

## 14. Two traces

**"How much did I sleep on average last month?"** → classified exact
aggregation → grant check on `oura.sleep` compiles into the WHERE clause →
SQL over T1 with the T2 definition of sleep → returns the number, the
denominator (nights with data), and the definition used. No model in the
arithmetic path. Reproducible.

**"Did my music change when I was sleeping badly?"** → relational/join → T1
Spotify rows joined to T1 Oura rows on date, with the skip-semantics rule from
T2 applied → aggregate per sleep-quality bucket → the model sees only the
result table, never 227,024 rows. If the consumer's grant covers only one of
the two scopes, the join is refused rather than silently half-answered.

## 15. Alternatives that need no transformation

The obvious objection to everything above: skip it, point an agent at the raw
files, let it write code. That deserves evidence, not assertion — and the
evidence changes the design rather than killing it.

### 15.1 Long context alone is not a design point

A 200MB personal corpus is ~40–50M tokens against a ~1M frontier context cap.
A _single_ scope — the ChatGPT export or the Spotify history — exceeds every
provider's maximum window on its own. Reading the whole corpus once is ~50
max-size calls: order $100 per question uncached and minutes of serial latency,
before any reasoning happens.

Worse, aggregation is the first capability to break as context grows. RULER
shows aggregation degrading faster than any other task category; NoLiMa shows
even single-fact retrieval falling >50% relative by 32K once literal keyword
overlap is removed; ClaimDB (aggregation over ~110M tokens with forced tool
use) has the best of 30 models at 82.7% _with_ 93–99% SQL execution success —
the failures are reasoning over correctly-retrieved data. CAG, the explicit
"skip RAG" paper, was validated to 85K tokens on an 8B model and its authors
call it impractical beyond that.

Nothing found supports letting a model eyeball an average over even dozens of
records. In-context aggregation is not a substitute for computing.

### 15.2 An agent with code execution: strong at text, weak at multi-step

This is the serious alternative, and it splits cleanly.

**Text retrieval — it wins.** A 2026 Amazon/AWS paper puts agentic `rga`/
`pdfgrep` search at ~91–95% of vector RAG's faithfulness and answer
correctness, 88% of context recall, and _beating_ RAG on FinanceBench — the
financial-table PDFs closest to our bank statements — 32.7% vs 24.2%. No vector
store, no reindex on write.

**Multi-step computation over messy data — it collapses.** DABStep (450 real
financial-analytics tasks, code-writing agents): **14–16% on hard multi-step
tasks** against 70–80% on its easy tier and a 62% human baseline. KramaBench,
the closest analogue to "point an agent at a raw data lake" (104 tasks, 1,700
files): **55% end-to-end, 62% even with oracle retrieval**, with models drafting
only 20% of sub-tasks correctly. ScienceAgentBench: 32–42%. But single-file
clean-CSV questions (InfiAgent-DABench) run 79–87%.

The failure mode is precise: **multi-file, multi-step chaining over implicit
rules.** "Total listening time cross-referenced with sleep quality in Q3" is
exactly the shape that scores 14–16%.

Compute is not the bottleneck — DuckDB cold-scans an 18GB JSON corpus in ~7s,
so our 355MB is sub-second-to-seconds. The cost is planning and code-generation
tokens (Anthropic's multi-agent research system runs 4–15x the tokens of a
normal turn; DABStep's best accuracy-per-cost model ran ~$0.20/question).

### 15.3 What this actually argues

**T1/T2 is a regime change, not an optimization.** A clean table plus a
semantic layer converts a DABStep-hard question (14–16%) into a BIRD-style
text-to-SQL question (~82%). The transformation's value is not that it is
faster — it is that it moves the question into a regime where models work. It
does this by removing exactly what the benchmarks show agents failing at:
implicit rules and multi-file chaining. Oura's nap grouping, ChatGPT's sibling
branches and Spotify's skip semantics are each an implicit rule that an agent
can derive — but derives correctly only sometimes, and differently each run.

**T3 (embeddings) is demoted.** If agentic keyword search reaches ~91–95% of
RAG on text and beats it on financial documents, embeddings must justify
themselves per source rather than being assumed. Lexical FTS + agentic search
is the default; vectors are an upgrade we prove, not a foundation. This also
removes the reindex-on-write cost that made §13.3 the biggest line item.

**Determinism is the open risk, and it is unmeasured.** Temperature 0 does not
guarantee reproducibility. The closest agent study found stable tool sequences
(0.87) but substantially varying arguments (0.69) — and **no benchmark anywhere
measures whether independently regenerated aggregation code returns the same
number twice on real data.** For a server that answers financial and health
questions, that is the gap that matters most, and it is cheap for us to measure
ourselves.

**Caching the code, not the data, is the underrated option.** Agent Workflow
Memory reports +24.6% and +51.1% relative success from reusing cached workflows
over regenerating them, and Agent Skills productizes the same idea. Replaying literal
generated code is exactly reproducible, which answer-similarity caching
(GPTCache-style) is not — and exactness is the whole point here.

### 15.4 The resulting tier model

Demand-driven, not ingest-driven. Each tier is a derivative with lineage.

| Tier | Artifact                                     | Amortized over     | New/unknown source   | Deterministic |
| ---- | -------------------------------------------- | ------------------ | -------------------- | ------------- |
| 0    | none — agent + code execution over raw files | nothing            | ✅ day one           | ❌            |
| 1    | the answer, as a derivative                  | one question       | ✅                   | ✅ on replay  |
| 2    | **the generated script, as a derivative**    | a question _shape_ | ✅                   | ✅ on replay  |
| 3    | materialized T1/T2 rows                      | a whole source     | ❌ needs a connector | ✅            |

Tier 0 works on day one for any source we have never seen, which is what the
connector-coverage risk (§11.3) needed. Tier 2 is the promotion path: when a
script has been generated, run and verified, keep the code — it is small,
reviewable, diffable, and replays exactly. Tier 3 is for sources where query
traffic justifies materializing, and for the classes where §15.2 says agents
fail: the health and finance arithmetic.

This inverts the build order. We do not need connectors before the system is
useful; we need them where the evidence says agents are unreliable.

## 16. Code execution with MCP

This is not a fourth alternative. It is the implementation of Tiers 0 and 2,
and it is the most important architectural fit in this document.

### 16.1 What it is, and what is actually shipped

Anthropic's pattern: present MCP servers to the model as a filesystem of
TypeScript modules it explores progressively, let it write real code against
them, and keep intermediate results inside the execution environment instead of
passing them through context.

Status matters. **The post is a pattern, not a product**, and its headline
"150k → 2k tokens" is one worked example, not a benchmark — this document
should not lean on it as evidence. What is shipped: the API's **code execution
tool** (server-side sandbox, no network, Python 3.11), **programmatic tool
calling** (code inside the sandbox calls your tools; +11% accuracy and −24%
tokens on BrowseComp/DeepSearchQA), and **Agent Skills / SKILL.md**, which is
the productized form of "save verified code and reuse it" with real three-level
progressive disclosure.

The citable number for the underlying claim that code beats JSON tool-calling
is **CodeAct** (arXiv:2402.01030): up to 20% higher success rate on API-Bank.
Cloudflare's "Code Mode" is the same idea independently built on V8 isolates,
published without benchmarks.

One hard constraint: **Anthropic's hosted MCP connector cannot reach local
stdio servers**, and no official library generates the MCP-as-filesystem view.
Both are ours to build.

### 16.2 Why it fits a Personal Server better than it fits anyone else

The privacy property is stated precisely as: intermediate results stay in the
execution environment; the model sees only what is explicitly returned, with
PII tokenized (`[EMAIL_1]`) before it reaches the model and detokenized at the
client boundary.

For Anthropic's hosted case, that means data does not enter the _context
window_. **For us, running the sandbox locally, it is strictly stronger: the
data never leaves the machine at all.** A question like "did my music change
when I was sleeping badly" scans 227,024 Spotify rows and three years of Oura
records, and the only thing that reaches a model is a small result table.

That converts three separate concerns in this document into one mechanism:

- **§8's exactness requirement** — arithmetic happens in code, not in a model.
- **§9's tool-surface tension** — the MCP surface stays small; expressive power
  comes from composition in code, not from tool count.
- **§6.5's early-binding grants** — the grant predicate becomes an OS-enforced
  read scope on the sandbox, which is a much stronger enforcement point than a
  WHERE clause the model could be argued out of.

And it composes with what the repo already has: the ZDR / `aci_verified`
inference path only ever sees aggregates, and a verified script is exactly the
Tier-2 artifact — small, reviewable, diffable, replayed exactly.

### 16.3 Sandbox choice

Requirements: offline, on a laptop, no network egress, read-only access scoped
to exactly the granted files, resource limits.

The closest existing match is **Claude Code's own sandbox**
(`@anthropic-ai/sandbox-runtime`, npm-distributed): Seatbelt on macOS,
bubblewrap + seccomp on Linux, OS-enforced fine-grained read/write allow-deny
lists where deny wins inside a wider allow, plus network domain allowlisting.
It has no confirmed CPU/memory limits, so pair it with `isolated-vm` or
`quickjs-emscripten` for resource-capped execution of the generated code
itself.

**Superseded for the Node path, 2026-08-28 (phases 4a and 4b).** Neither second
JS engine is needed. Phase 4a confirmed from source that `sandbox-runtime`
enforces access control only — it never spawns the process, so it could not
impose limits even in principle — and covered the gap with `RLIMIT_CPU`,
`RLIMIT_NPROC` and an out-of-process RSS watchdog (macOS rejects `RLIMIT_AS`
outright and silently ignores `RLIMIT_DATA`). Phase 4b then replaced native
execution of generated code with a tree-walking interpreter carrying its own
step budget. Between them the caps are covered without embedding another
engine. `quickjs-emscripten` remains the right answer for PS-Lite.

Ruled out: **vm2** (unsafe for untrusted code per its own README),
**Pyodide-in-Deno** (mcp-run-python's own maintainers state it "was not
designed as a sandbox" and Python can escape to arbitrary JS), and
**Firecracker / E2B / Daytona / Vercel Sandbox** (hosted or KVM-only, both
excluded by the offline-laptop requirement).

### 16.4 Security: what it fixes and what it does not

Code execution **genuinely shrinks the prompt-injection surface** by keeping
raw, instruction-shaped attacker content — a malicious email, a hostile
calendar invite — out of the model's reasoning context. That is a real gain and
it is unusual to get one this cheaply.

It does **not** dissolve the lethal trifecta. The model still authors the code
from a request that may itself be injected, and the sandbox will faithfully
execute code that reads and exfiltrates. It also does nothing about MCP-level
attacks: poisoned tool descriptions and rug pulls simply relocate from context
into files on disk, with the same exposure. The MCP spec's own "Local MCP
Server Compromise" section recommends precisely the OS sandboxing above.

So the safety is not done by the pattern. It is done by:

1. **Zero ambient network egress** at the sandbox boundary, enforced
   independently of anything the model does.
2. **Grant-scoped, OS-enforced read access** to only the files under the
   consumer's grant — this is what actually contains a compromised script.
3. **Pinned tool descriptions**, treated as untrusted data, versioned against
   rug pulls.
4. Not assuming "stayed in the sandbox" means "safe" — results still flow back
   into context, and that is the remaining channel.

### 16.5 The open decision

Who writes the code: the **consumer's agent** (Anthropic's shape — maximum
flexibility, the caller composes) or the **Personal Server's own compute
layer** (the caller supplies only a question; the PS generates, runs and caches
the script)?

Grant enforcement, payment metering, access logging and Tier-2 caching are all
materially easier in the second shape, and it extends `derivatives/compute.ts`
rather than replacing it. The first is more expressive and is what an external
agent ecosystem will expect. This is the largest unresolved design question in
the document, and it is worth deciding before anything is built.

## 17. If the agent writes code, what is left to precompute?

Assume the shape from §16.5 where the Personal Server bundles its own agent and
generates the code itself. Three questions follow, and the third revises §7.

### 17.1 Will it pick the right path?

Mostly — but path errors are silent, which is the problem.

Classifying "average sleep" as arithmetic and "what was my focus" as synthesis
is not hard, and with code execution the agent does not even have to commit:
one script can run a SQL aggregate and a keyword scan in the same pass.
Evidence still favours a cheap pre-classifier over pure model judgement
(Copilot's embedding pre-filter at 94.5% tool-use coverage vs 87.5% for raw LLM
judgement), but with a small surface this is a nudge, not a necessity.

The real failure is not routing, it is **not knowing what it does not know**.
An agent given `sleep` rows has no way to discover that a day can hold multiple
sleep periods, so it writes a defensible 1:1 join and returns a wrong average
with no signal that anything went wrong. This is the DABStep result restated:
14–16% on multi-step questions over messy data, and the errors are implicit
rules, not syntax. Choosing the wrong path for Q8 is worse still — semantic
search instead of an exhaustive scan produces a confident "no" that is
indistinguishable from a correct one.

### 17.2 Analytical _and_ semantic — yes, and better than either alone

Code execution is the only option surveyed that does both in one pass. A script
can `GROUP BY` in DuckDB, `rg` for a phrase, _and_ call an LLM as a function
inside a loop — map-reduce over 3,000 conversations, then aggregate the
classifications exactly.

That last shape is what none of RAG, SQL, or long context can do: **semantic
judgement applied exhaustively, then counted.** It is the honest way to answer
Q2 (main focus this week), Q15 (stated intent vs follow-through) and Q16
(measured vs self-reported), because coverage is total and the arithmetic is
real. It is also the expensive shape — thousands of model calls per question —
which is exactly where precomputation earns its place.

It also settles the completeness problem from §4.3 more convincingly than any
index does. A script that scans every row _knows_ it scanned every row, and can
return the count. Completeness stops being a statistical property of a
retriever and becomes an ordinary post-condition of a loop.

### 17.3 So do we still need indexes and derivatives?

Separate four things that get called "the index":

|                                          | Still needed?                             | Why                                                                                                                                                                                                 |
| ---------------------------------------- | ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Implicit rules / semantic layer (T2)** | **Yes — the most important artifact**     | The agent cannot rederive naps, sibling branches or skip semantics reliably. But this is _documentation the agent reads_, not a materialized structure. Cube's +17–23pp came from ~4KB of markdown. |
| **Parsers (T1)**                         | Yes, but **as code, not tables**          | A verified parse script (Tier 2) captures the rules and replays exactly. Materializing rows is a separate, later decision.                                                                          |
| **Materialized rows / vectors (T3)**     | **Mostly no, at our scale**               | DuckDB cold-scans 18GB of JSON in ~7s; our 355MB is sub-second. There is no performance argument for precomputing what a scan can do per query.                                                     |
| **Derivatives as durable records**       | **Yes — for protocol reasons, not speed** | A builder holding a grant on a derived scope needs that scope to _exist_ as a record with lineage. Auditability, user inspection and deletion, and payment all attach to a record, not to a cache.  |

That yields one decision rule replacing the T1–T6 catalogue's implied "build
them all":

> **Precompute only what is expensive per query _and_ reused across queries —
> or what must exist as a durable record for grant, lineage or payment
> reasons.**

Scanning is cheap and fails the first test: do not precompute it. LLM-derived
semantics (classifying every conversation, extracting facts, normalizing
merchants) is expensive and reused: precompute it, once, as a derivative. This
is the same conclusion §13.5 reached about T5 and T6, generalized — and it
demotes T3 further, since embeddings are a performance structure for a scan
problem we do not have.

**What this deletes from §7:** T1 as materialized tables (becomes a cached
script), T3 as a default (becomes opt-in per source, justified by eval), and
the entire notion of an ingest-time pipeline. **What survives:** T2 as prose
the agent reads, T4/T5/T6 as demand-driven derivatives holding LLM-derived
semantics, and the derivative record itself as the unit of caching, provenance
and sharing.

**What we lose without materialization** is worth stating plainly:
reproducibility. A replayed script is deterministic; a regenerated one is not,
and nobody has measured the variance (§15.3). That is the single measurement
that should gate this whole direction.

## 18. Simulation: cold server, 222MB, no index

Measured, not argued. A synthetic corpus was generated to the shapes verified in
§12 and the question corpus run against it on a laptop (M-series, 16GB, Node
22). Corpus: **222MB across 13 files / ~10 sources, 43% prose, ≈55.4M tokens** —
Oura sleep with naps, 110k heart-rate samples, 228k Spotify streams with
podcast rows, 10.4k ChatGPT conversations with regenerated sibling branches,
Slack, email, notes, bank, calendar, browser history.

Local data is plaintext on disk (encryption applies to synced copies), so scans
do not pay a decryption cost.

### 18.1 What the questions actually cost

| Question                           | Operation                                          | Time                                              |
| ---------------------------------- | -------------------------------------------------- | ------------------------------------------------- |
| Q1 average sleep                   | parse + aggregate Oura sleep                       | **2 ms**                                          |
| Q7 recurring expenses              | normalize + group 9k transactions                  | **6 ms**                                          |
| Q6 distinct people                 | 110k rows across Slack + email + calendar, aliased | **65 ms**                                         |
| Q5 / Q8 exhaustive scan            | literal scan of **all 95MB of prose**              | **71 ms**                                         |
| Q4 sleep × music join              | 228k streams joined to sleep by date               | **238 ms**                                        |
| ChatGPT correct reconstruction     | `current_node` walk over 10.4k conversations       | **229 ms**                                        |
| Q3 / Q15 whole-corpus semantic map | 10,400 LLM calls, 5.5M input tokens                | **~$5.47 (haiku-class) / ~$16.40 (sonnet-class)** |

Materializing does not change the picture: building a SQLite table of all 228k
Spotify rows takes 0.4s and turns a 175ms scan into a 2ms query. Real, but not
a reason to build an ingest pipeline.

**Every non-semantic question in the corpus answers in milliseconds with no
index.** The scan-is-cheap premise holds at this scale, with ~3 orders of
magnitude of headroom before it stops holding.

### 18.2 The two silent-wrongness results

Both implicit rules from §12 were measured, and both change answers materially:

- **Oura naps.** Correct (main sleep only): **6.48h**. Naive (all sleep periods
  averaged): **5.81h**. A **11.5% error**, in the direction of "you sleep less
  than you do", with nothing in the output to indicate a problem.
- **ChatGPT branches.** Correct `current_node` walk: **119,758 messages**.
  Naive `mapping.values()` flatten: **137,736** — **+15.0% phantom messages**
  that the user never sent or received. Every count, date and "first mention"
  built on that is wrong.

**Recomputed 2026-08-28 on the seeded generator (phase 1), seed `20260828`.**
The numbers above came from one unseeded draw and are not reproducible. The
reproducible figures:

| Trap                        | Correct     | Naive       | Error      |
| --------------------------- | ----------- | ----------- | ---------- |
| Sleep, full corpus (n=1030) | **6.52h**   | **5.93h**   | **-9.0%**  |
| Sleep, 31-day window (n=28) | 6.58h       | 5.73h       | -12.8%     |
| ChatGPT messages            | **120,003** | **138,047** | **+15.0%** |

**The ChatGPT trap reproduces exactly at +15.0%** — it follows structurally from
the sibling-branch rate, so it is a property of the data shape rather than of
the draw. **The sleep trap's magnitude is seed and window noise**: it swings
±4pp with how many naps land in the sampled window. Cite the full-corpus figure
(**6.52h vs 5.93h, -9.0%**) as the stable number; the -11.5% above was one
30-day draw. The regression test asserts the full-corpus ratio for exactly this
reason.

The direction and the mechanism are unchanged, and that is what this section
argues. Phase 1 also made four further traps measurable that this section never
had: keeping `rest`/`deleted` rows (6.52h → 5.99h), treating a null
`total_sleep_duration` as zero (6.52h → 6.44h), an unfiltered resting-HR
baseline (55.5 → 70.5 bpm), and undeduped workouts read as kilometres (193 →
301 run days).

Neither is a performance question. This is the entire case for T2, and it is
why "let the agent figure it out" fails quietly rather than loudly.

### 18.3 Where the cost actually is

The measurements invert the usual assumption. Scanning 222MB is free; the
expensive operations are semantic:

```
scan / aggregate / join   2–240 ms      → never worth precomputing
one week of context       ~35k tokens   → fits a single call, no index needed
whole-corpus semantic map $5–16/pass    → precompute once, reuse forever
```

A week-scale synthesis question (Q2) assembles ~35k tokens of prose at realistic
conversation density — one model call, no retrieval machinery. A corpus-scale
semantic question (Q3 financial risk appetite, Q15 stated intent vs
follow-through) needs a judgement over every conversation: 10,400 calls and
5.5M tokens. That is the only thing in the entire corpus expensive enough to
justify materialization — and it is reusable across many questions, which is
exactly the §17.3 rule.

### 18.4 So when does the index get built?

**Never at ingest. Never for scans. On second use for anything semantic.**

1. **Cold start, minute zero.** The agent lists scopes, reads T2 prose where we
   ship it, and answers Q1, Q4, Q5, Q6, Q7, Q8, Q11, Q14, Q18 by writing code.
   No index exists and none is needed. A brand-new source we have never seen
   works on day one at whatever accuracy the agent can manage unaided.
2. **First expensive semantic question.** Q3 arrives. The agent decomposes it,
   discovers it needs a judgement per conversation, and pays $5–16 once. The
   result is written back as a derivative with lineage — a `derived.topics`-style
   scope, small, inspectable, deletable.
3. **Second question that needs the same map.** Q15 and Q16 hit the derivative
   instead of re-paying. Q2 narrows it by date range. This is where the index
   "exists", and it was built because something asked for it.
4. **Source changes.** `derivatives/scheduler.ts` marks it stale and recomputes
   on its own — the machinery is already in the repo.
5. **Materialized tables (T1/T3), if ever.** Only when grading shows an agent
   getting a source's implicit rules wrong repeatedly, or when one source is
   queried often enough that 175ms → 2ms matters. Neither is true at 222MB.

The trigger is a cost comparison, not a pipeline stage: **materialize when
(cost to recompute × expected reuse) exceeds the cost to store, or when the
artifact must exist as a durable record for grant, lineage or payment reasons.**
Scans fail that test by three orders of magnitude. Semantic maps pass it on the
second question.

### 18.5 Where this breaks

Honest limits of the simulation:

- **Warm page cache.** Cold reads add disk time; at NVMe speeds that is a
  fraction of a second for 222MB, but it was not measured.
- **Synthetic prose is low-entropy.** Scan times are realistic; _semantic
  quality_ on this corpus proves nothing. Only the graded question set (§19.1)
  can test that.
- **Scale.** At ~10x (2GB+) the scan numbers move from milliseconds to seconds
  and the calculus changes — that is when T1 materialization starts earning its
  place. The design should assume this arrives, not that it never will.
- **Concurrency and payment.** Ten consumers asking scan-shaped questions
  simultaneously is ten full scans; per-scope access logging and payment
  settlement multiply accordingly. Not modelled here.
- **The determinism gap is still unmeasured** and remains the one result that
  could invalidate this direction (§15.3).

### 18.6 Verdict

The design holds, and it simplifies. At 222MB the honest architecture is: **an
agent that writes code, a sandbox, prose describing each source's implicit
rules, and derivatives used as a cache for semantic work only.** Everything
else in §7 is a scaling contingency, not a v1 requirement.

## 19. The agent harness

An API key is not a harness. §16–18 assume something that plans, writes code,
runs it in a sandbox, reads results, iterates, and persists verified scripts.

### 19.1 The two hard requirements

1. **Arbitrary OpenAI-compatible endpoint.** Inference goes through our relay
   (`inference.phala.com/v1`, `z-ai/glm-5.2`, `aci_verified`/`zdr`); the relay
   holds the key and the privacy properties. A harness bound to its vendor's
   models is unusable, however good.
2. **OS-enforced sandbox**: per-path read scoping to granted files, zero
   network egress, CPU/memory limits.

Nothing surveyed satisfies both. The candidates split cleanly into "embeddable
and model-agnostic" and "actually sandboxed", and the recommendation is to take
one from each column.

### 19.2 The field

|                         | Licence              | Runtime | Arbitrary OpenAI endpoint    | In-process library   | OS sandbox             |
| ----------------------- | -------------------- | ------- | ---------------------------- | -------------------- | ---------------------- |
| **pi** (earendil-works) | MIT                  | TS/Bun  | ✅ first-class `baseUrl`     | ✅ **only true one** | ❌ none, by design     |
| **Codex CLI**           | Apache-2.0           | Rust    | ⚠️ Responses API only        | ❌ subprocess SDK    | ✅ **only real one**   |
| **Qwen Code**           | Apache-2.0           | TS      | ✅ `modelProviders.openai[]` | ❌ subprocess SDK    | ⚠️ opt-in, weak        |
| **dsh** (DeepSeek)      | repo MIT / npm BSD-3 | TS      | ✅ (wraps pi-ai)             | ❌ Cordis framework  | ⚠️ filesystem only     |
| **OpenCode**            | MIT                  | TS      | ✅                           | ✅ official SDK      | ❌ "No Sandbox"        |
| **Goose**               | Apache-2.0           | Rust    | ✅ verified in source        | ❌ ACP client        | ❌ none                |
| **Gemini CLI**          | Apache-2.0           | TS      | ❌ **Google-locked**         | ❌ SDK unpublished   | ⚠️ opt-in, egress open |
| **Crush**               | FSL-1.1-MIT ⚠️       | Go      | ✅                           | ❌                   | ❌ `Setsid` only       |
| **Claude Agent SDK**    | proprietary ❌       | TS      | ❌ Claude only               | ✅                   | via separate pkg       |

Eliminated outright: **Gemini CLI** — `AuthType` has exactly six values, all
Google auth paths; `baseUrl` redirects Google SDK calls without changing the
wire protocol, and its SDK package is not on public npm. **Crush** — FSL-1.1-MIT
forbids "Competing Use" until each release ages two years into MIT.
**Claude Agent SDK** — Claude-only and proprietary (see §19.5).

### 19.3 Only one candidate is a real library

**`@earendil-works/pi-agent-core` + `pi-ai`** are the only genuinely embeddable
in-process packages found: a plain `agentLoop()`/`Agent` class with no TUI
dependency, 1.9MB and 4.1MB unpacked, MIT throughout, with arbitrary
`baseUrl` + model as a first-class documented feature. 98,730 stars, organic,
with identifiable maintainers. DeepSeek's own harness wraps `pi-ai` for its LLM
layer — pi is upstream of a major vendor's agent stack.

Everything else is a CLI. Codex's `@openai/codex-sdk` and Qwen's `@qwen-code/sdk`
are subprocess wrappers around a large native binary; Goose exposes only an ACP
protocol client; dsh is a Cordis plugin composition whose "headless" mode is a
CLI invocation. OpenCode has a real SDK and client/server split, but it is still
a 144MB binary behind an HTTP API.

Two caveats on pi: **no MCP support at all**, an explicit design choice — which
costs us little, since we ship the MCP server and the harness sits behind it
under §16.5. And **no sandboxing whatsoever**, stated plainly in its own docs
as intentional.

### 19.4 Only one candidate is really sandboxed

**Codex CLI** is the only harness with a self-contained, cross-platform,
default-meaningful OS sandbox: bundled `bwrap` + Landlock on Linux (binary
ships in the release, no external dependency), Seatbelt with deny-by-default
`.sbpl` policies on macOS, restricted-token backends on Windows — read-only by
default, network denied unless enabled, with genuine per-path read/write/deny
maps and domain-level network allowlisting. `codex-rs/sandboxing/` and
`codex-rs/linux-sandbox/` are Apache-2.0 and worth studying directly.

But Codex fails requirement 1. Its `wire_api` accepts `"responses"` **only**,
rejecting `"chat"` with a hard deserialization error — verified at source in
`codex-rs/model-provider-info/src/lib.rs` (its own crate now; the older
`codex-rs/core/src/model_provider_info.rs` path 404s). `WireApi` has a single
variant, `Responses` is the default when unset, and a repo-wide search for
`chat/completions` returns zero hits. Removed in PR #10157, first stable in
`rust-v0.95.0`; confirmed against `codex-rs 0.150.1` (2026-08-27).

**Resolved 2026-08-28 (plan phase 3), and the earlier reasoning here was
wrong.** This section assumed Codex was blocked because our relay probably
speaks only Chat Completions. It does not. The question has _two hops_ with
opposite answers:

- **Phala upstream speaks Responses.** `Dstack-TEE/private-ai-gateway`
  registers `.route("/v1/responses", post(responses))`, and the documented
  example uses `z-ai/glm-5.2`. It is a create-only opaque passthrough — the
  gateway does no chat↔Responses translation, so support is per-upstream and
  per-model, not a gateway guarantee.
- **Our own gateway does not expose it.** The Personal Server does not talk to
  Phala directly; it talks to `data-gateway`, which exposes exactly three
  inference routes (`POST /v1/inference/chat/completions` and two attestation
  reads). No Responses route exists on `main` or `dev`, and none is in flight.

So Codex is blocked for two independent reasons, neither of which is the one
originally written here: **(a)** the deployed relay has no Responses route, and
**(b)** E2EE cannot travel on Responses at all — Phala returns a hard
`400 e2ee_unsupported_endpoint`, because `spec/e2ee-v2.md` §5 defines
encryptable field paths only for the `messages[]`/`choices[]` shape and
mandates rejection for any endpoint it does not cover. Adopting Responses means
`inference.e2ee = false`, i.e. plaintext prompts and answers over TLS.

The verdict stands; the reason is different. Note also that
"Responses supported → Codex viable" is a **false implication** wherever it
appears in this document: it needs both the E2EE clause and the PS-Lite clause
(§19.3 — Codex is a subprocess wrapper, so it cannot run in a browser runtime
at all, and would replace the sandbox on Node only).

The others: **dsh** has a real cross-platform filesystem sandbox
(bubblewrap/Landlock, Seatbelt, Windows ACL-restricted token) but it is
filesystem-only by explicit design — "network and process visibility are
outside this vocabulary" — and its CPU/memory rlimits apply only to its Python
code-runtime tool. **Gemini CLI and Qwen Code** can reach real OS enforcement,
but opt-in, off by default, with macOS's default profile _allowing_ network
egress and non-Mac platforms requiring externally installed Docker/Podman.
**OpenCode, Goose and Crush** ship nothing; OpenCode's SECURITY.md says so
under a heading titled "No Sandbox" and tells you to use Docker or a VM.

For egress specifically, the only surveyed option with real network
allowlisting is **Gondolin**, a separate QEMU-backed micro-VM — macOS/Linux
only, requiring QEMU or libkrun and ~200MB+ images. Not viable for an
npm-shipped desktop component. (`OpenShell`, seen referenced alongside pi, is
NVIDIA's separate commercial product, not part of pi.)

### 19.5 Why Anthropic's stack is out, and what survives from it

`ANTHROPIC_BASE_URL` relocates where requests go, not which model answers;
every supported backend serves Claude only, and Anthropic's gateway docs state
they do not support routing to non-Claude models through any gateway. Both
`@anthropic-ai/claude-agent-sdk` and `@anthropic-ai/claude-code` publish
`"license": "SEE LICENSE IN README.md"` — proprietary, governed by Commercial
ToS, requiring an `ANTHROPIC_API_KEY` at runtime with no offline mode. (Licence
reading is summarized, not counsel-reviewed.)

Two pieces survive independently: **`@anthropic-ai/sandbox-runtime`**
(Apache-2.0, standalone-usable, Seatbelt/bubblewrap/Windows, with network
allowlisting via a proxy) and **SKILL.md** (open, at agentskills.io, implemented
by pi, dsh, Goose, OpenCode, Crush, Gemini CLI and Letta).

### 19.6 Recommendation

Take the loop from one column and the sandbox from the other:

1. **Loop — `@earendil-works/pi-agent-core`.** MIT, in-process, provider-agnostic,
   ~2MB, already the LLM layer under DeepSeek's harness. This replaces the
   "write our own ~300 lines" plan from the previous draft: pi _is_ that loop,
   maintained. Writing our own stays the fallback if pi's abstractions fight our
   grant model.
2. **Sandbox — ours, built from a studied reference.** `sandbox-runtime`
   (Apache-2.0, closest to our requirements, but a "Beta Research Preview" —
   pin versions and verify whether it enforces CPU/memory quotas or only access
   control) or Codex's `codex-rs/sandboxing/` as the design to imitate. This is
   unavoidable work: no harness that meets requirement 1 ships a sandbox.
3. **Capability confinement — the `codemode` pattern.** A tree-walking JS
   interpreter with no `eval`, where generated code receives only host-supplied
   authority and can call only host-registered tools, with
   `timeoutMs`/`maxToolCalls`/`maxOutputBytes` budgets. Maps onto grants
   exactly: register only the tools a consumer's grant permits and the code
   cannot name anything else.
4. **Skills — SKILL.md**, as the Tier-2 script-persistence format.
5. **PS-Lite — `quickjs-emscripten`** (MIT, WASM, real memory and interrupt
   limits, pre-1.0), the only primitive that also runs in a browser.

### 19.7 The sandbox is two layers

§16.3 described only OS enforcement. Both are needed:

- **Capability confinement** — what the generated code can _call_. A language
  boundary; a shell escape defeats it.
- **OS enforcement** — what the process can _read and reach_. Per-path read
  allowlist, zero egress, CPU/memory caps. Alone, it still lets in-grant code
  do out-of-scope things.

Corrections to earlier drafts: `isolated-vm` is in maintenance mode with no CPU
limit and only a soft memory limit, and Node's `--permission` is explicitly
documented as _not a security boundary_ against malicious code. Neither is
usable here.

## 20. Next

1. Turn §3 into a graded question set with expected answers and coverage
   assertions — nothing below is decidable without it.
2. **Measure the determinism gap** (§15.3, §17.3): the same aggregation question
   ten times through a code-writing agent over the §18 corpus. This gates how
   much we materialize.
3. **Decide §16.5** — who authors the code. Assume PS-side unless something
   argues otherwise.
4. ~~Check whether our relay speaks the OpenAI Responses API~~ — **done
   2026-08-28, see §19.4.** Phala speaks it; our `data-gateway` does not expose
   it; and E2EE cannot travel on it regardless. §19.6 stands as written. The
   remaining decision — whether giving up E2EE is ever worth Codex's sandbox —
   is open and belongs to a human, not to an implementation agent.
5. Prototype: `pi-agent-core` against the relay, plus both sandbox layers from
   §19.7, graded against the question set.
6. Write T2 prose (schemas, implicit rules, metric definitions) for Oura,
   Spotify and ChatGPT. §18.2 says this is the highest-leverage artifact we can
   produce: it is what stands between 6.48h and 5.81h.
7. Only then, and only where the grading says so, materialize anything.

Facts flagged UNVERIFIED, **updated 2026-08-28 after phase 6a**:

_Resolved:_

- **spo2 nesting** — confirmed: `daily_spo2.spo2_percentage` is a nested
  object, `{average}` required, and the object itself is nullable.
- **Spotify account-data package shape** — resolved as a _correction_, not a
  confirmation. See §12.2.
- **Midnight-crossing day-bucket rule** — partially resolved: the Oura sleep
  day changes at 18:00, which is enough for the actionable rule (bucket by
  `day`). The general edge-case arithmetic remains unspecified.

_Still unverified, and marked as gaps in the shipped profiles rather than
stated as fact:_ daytime heart-rate cadence (`PublicHeartRateRow` has no
interval field, so the profile tells the agent to measure gaps rather than
assume 5-minute samples), Oura Ring CSV headers, the current ChatGPT export
file list (OpenAI's help centre 403s to automated fetches), Spotify's
`reason_end` vocabulary and duplicate rate (§12.2), the Anthropic Commercial
ToS reading (summarized, not counsel-reviewed), and dsh's 201,918-star count
(real per the API, but accrued in 15 days on a repo with Issues disabled — not
a usable maturity signal).
