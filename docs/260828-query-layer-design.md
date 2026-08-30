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

> **MEASURED 2026-08-28 (phase 2).** Gemini 3.7 Flash, N=10 per case, the
> seeded `small` corpus, through the full nested path. **Temperature was not
> pinned** — our provider sends only `model`, `messages` and `max_tokens` — so
> this measures the provider's default sampler as much as the architecture.
> That is the single largest caveat on every number below.
>
> | Case               | identical value     | spread (sd)       | distinct scripts | coverage records |
> | ------------------ | ------------------- | ----------------- | ---------------- | ---------------- |
> | Q1 sleep avg       | 6/9                 | 6.01–7.23 (0.307) | **9/9**          | 9 distinct       |
> | Q11 HR anomaly     | **9/9**             | 69.43 (0.000)     | **9/9**          | 18.7k–62.5k      |
> | Q14 Japan spend    | 4/4 — **all wrong** | 550824 (0.000)    | 5/5              | 5 distinct       |
> | Q7 recurring (set) | n/a                 | —                 | 10/10            | 4 distinct       |
> | Q18 conditional    | no value returned   | —                 | 10/10            | 10 distinct      |
>
> **Script variance is total: 43 runs, 43 distinct scripts**, raw _and_ after
> normalizing whitespace and comments. The model never regenerated the same
> script once, even when the answer was bit-identical. The "stable sequences,
> varying arguments" finding above understates it for code.
>
> **Value determinism is a property of the question, not of the system.** Q11
> is perfect; Q1 put 3 of 9 runs outside tolerance with sd 0.307 on a ~6.6
> quantity. There is no single determinism number to quote.
>
> **Q14 is the result that matters most, and it is not a determinism result.**
> All four completing runs returned exactly `550824` against an expected
> `7727.24` — perfectly reproducible and 71× wrong. The scripts summed raw JPY
> and never applied FX, which §3's Q14 explicitly requires. (The 71.3 ratio is
> a _blend_ across mixed-currency rows, not an exchange rate: solving
> `U + J = 550824` against `U + J/149.5 = 7727.24` gives J ≈ 546,754 JPY and
> U ≈ $4,070.) `bank.transactions` has **no T2 profile**.
>
> So **determinism and correctness are independent axes**, and a measurement of
> the first alone would have graded Q14 a success. This is the strongest
> evidence yet for §18.2's thesis: the fix for Q14 is a currency profile, not a
> cache. It also sets a hard precondition on phase 6b — caching a script that
> was never eval-verified freezes an error forever, deterministically.
>
> **Coverage is unstable, and that bears on Q8 more than the values do.** Q11
> scanned between 18,704 and 62,532 records for the same question — a 3.3×
> swing — across 9 distinct scope sets. A completeness claim is only as good as
> the scan behind it. Separately, `complete` was false in **43/43** runs, so the
> flag currently carries no information and its derivation may be too strict.
>
> Limits: one model, one corpus, one day, N=10, and a thinking model whose
> reasoning tokens are hidden — variance may originate in reasoning the script
> never shows.
>
> **RE-RUN WITH TEMPERATURE PINNED, same day. The variance is not the
> sampler.** 60 runs at `temperature: 0`, plus an independent replication
> batch:
>
> | Axis                | unpinned       | temperature 0  | replication |
> | ------------------- | -------------- | -------------- | ----------- |
> | distinct scripts    | 43/43          | **42/42**      | **18/18**   |
> | Q1 within-tolerance | 6/9            | 5/9            | 6/9         |
> | Q11 identical       | 9/9            | 7/7            | 9/9         |
> | Q14                 | 550824 (wrong) | 550824 (wrong) | —           |
> | `complete` true     | 0/43           | 0/42           | 0/18        |
>
> **Script variance did not move: 60 temperature-0 runs, 60 distinct scripts**,
> raw and normalized. So regeneration is inherently unstable and no sampler
> setting undoes it — the stronger of the two possible outcomes, and it means
> the phase 6b caching argument rests on something no configuration can fix.
> The offline control was 1/10 distinct with sd 0, so the harness measures the
> model rather than itself. Coverage did not stabilise either: Q11 scanned
> 14,428–33,832 records across 9 distinct scope sets for one question.
>
> **Q1's instability is set resolution, not arithmetic.** The eval reads "last
> month" as a trailing 31 days; the model variously chose trailing-30 (6.16),
> calendar-December (6.68) and trailing-31 (6.62) — three defensible readings
> of an ambiguous question. Q11 is stable precisely because "last week" is not
> ambiguous. That sharpens what a cached script would be freezing: not a
> computation but an _interpretation_, which argues the cached artifact must
> record its resolution alongside its code. Prompt rule 5 already requires the
> model to state that resolution; caching should persist it.
>
> `seed` is **rejected** by this endpoint (`400 Unknown name "seed"`), so
> sampler pinning is limited to `temperature` and `top_p`. An earlier probe of
> mine reported it accepted; that probe read Gemini's array-shaped error body
> (`[{error:…}]`) with an object-shaped check and scored a hard 400 as success.
> `scripts/probe-params.ts` now handles both shapes.

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

## 19.8 Measured: the question corpus, end to end

The first end-to-end grading of §3's eighteen questions, run 2026-08-28 through
the full nested path (loop → confined interpreter → OS sandbox → host-authored
coverage) against a real model — Gemini 3.7 Flash at `temperature: 0`, over the
`dogfood` fixture corpus, **N=3 per question**, 54 live runs, 7.17M input /
171.6k output tokens, 1141s.

N=3 is the standard, not a luxury. A prior single-run pass recorded Q1 and Q11
as clean passes; both are 2/3. It also recorded a fix as working off one lucky
draw that was really 1-in-4. **With 60/60 distinct scripts at temperature 0, a
single live run is a sample, not a verification.**

| Class                | Result                                      |
| -------------------- | ------------------------------------------- |
| Exact aggregation    | Q1 2/3, Q11 2/3, Q18 2/3, Q7 0/3, Q14 0/3   |
| Exhaustive / absence | **Q8 3/3**, Q5 0/3, Q15 0/3                 |
| Latent inference     | **Q16 3/3**, Q3 0/3                         |
| Relational / join    | Q6, Q4, Q17 0/3                             |
| Synthesis            | Q2, Q9, Q10, Q13 0/3                        |
| Introspection        | Q12 0/3 — the corpus models no grant ledger |

**Five questions pass at least once, up from two.** Every harness-caused failure
is gone: null-content crashes 17% → **0/54**, budget kills 28% → **0/54**.
Nothing regressed.

**The one-line finding: the arithmetic is reliable; the set resolution is not.**
Q1 (which window is "last month"), Q6 (who counts as a person), Q14 (which
transactions belong to the trip), Q18 (which days count as logged) all compute
correctly over the wrong set. §3 predicted exactly this for Q14 and Q6; it
generalizes further than the document assumed, and it is the single most
valuable thing to attack next.

**T2 profiles work, measurably, and Q14 is the cleanest evidence in the build:**

| Q14 state                  | Answer                                                                                                            |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| No bank profile            | `550824` — raw JPY summed, **71× wrong**, identically on 4/4 runs                                                 |
| Bank profile               | `3790.28` — FX applied, but JPY-only                                                                              |
| Profile + `fx.rates` scope | **`7728.3`** — exactly `inWindowOnlyUsd`; window resolved, all currencies summed, only the pre-trip flight missed |

That final residual is precisely §3's stated Q14 difficulty ("a pre-paid hotel
charged two months earlier, and the flight itself"). The profile converted a
silent arithmetic error into a correct-but-incomplete set — the shift §18.2
predicts, observed.

**Two flaky rows are grading artifacts, not model failures.** Q11's failing run
computed 69.43 correctly _in its answer text_ but left `value` unset, so the
harness's `extractNumber` fallback scraped `29` out of "December 29". Q18's
failing run computed both candidate denominators and headlined the wrong one —
a defensible alternative reading, not an error.

**§18.3's cost model does not describe the system.** It predicts semantic
questions dominate spend through per-item `vana.classify`. Measured:
**`classify` was called in 0 of 54 runs.** Class medians sit within 2.5× of each
other and spend tracks _turn count_, not semantic difficulty. Scanning remains
free as §18.1 says (13.7MB in single-digit seconds). Phase 7's materialization
calculus rests on §18.3's premise and should be re-derived from this.

**`coverage.complete` has never been true — 132 consecutive runs.** Its
derivation (every granted scope streamed end to end) appears too strict to fire
on a multi-scope grant. A flag that is always false is not a safety property.

### 19.9 The set-resolution finding: the questions are ambiguous, not the model

§19.8 concluded that "the arithmetic is reliable; the set resolution is not."
An experiment run to attack that inverted the diagnosis, and the correction
matters more than the original claim.

The model was made to declare its chosen set in a `resolution` field before
computing. It complied **12/12** where it had declared nothing before. And in
**every failing run the number is exactly consistent with the set it declared**
— not approximately, exactly.

Q1 ("how much did I sleep last month") is the clean case. Every defensible
reading, computed off the corpus:

| Reading              | Average     | n   |
| -------------------- | ----------- | --- |
| trailing 28 days     | 6.5769h     | 25  |
| trailing 30 days     | 6.6190h     | 27  |
| **trailing 31 days** | **6.5775h** | 28  |
| calendar Dec 2025    | 6.6817h     | 27  |
| calendar Nov 2025    | 6.8354h     | 30  |

The eval expects trailing-31. The model declared "calendar December 2025" and
returned 6.68 — **correct for the set it named.** Five readings span **0.26h
against a ±0.05 tolerance**, so the eval cannot distinguish a wrong answer from
a different defensible reading, whatever the model does.

The regression is the sharpest evidence: **Q1 went 3/3 → 0/3 when the model was
made to deliberate.** Before, it fell into the eval's reading by luck; asked to
choose deliberately, it chose a different defensible one. Q14 declared "3790.28
JPY plus the 1418.60 pre-booked flight" and returned their exact sum. Q18's two
passing runs declared "108 logged days"; the failing one declared "74 complete
logged days" and returned the number that follows.

**So this is a definition problem, not a reasoning problem**, and it is a
finding about _the eval_, not about the agent. §3 chose these phrasings
deliberately because real users talk like this — which means the ambiguity is a
property of the problem the Personal Server actually has, not an artifact to be
tuned away.

Three ways forward, and none of them is "prompt harder":

1. **Grade the resolution, then the number given that resolution.** A
   defensible resolution plus a consistent number is a pass. The field now
   exists to do it.
2. **Return the resolution to the caller** as part of the answer contract, so
   an app can re-ask with the window pinned. This is arguably the correct
   product behaviour, and §8's two-stage answering already leans that way.
3. **Disambiguate the corpus questions** — but that narrows what the corpus
   tests, and the ambiguity is the realistic part.

What must _not_ happen is tuning the prompt until Q1 lands on trailing-31. That
optimises for an arbitrary choice and hides the finding. The experiment
deliberately dropped a drafted prompt line defining "last month", on the
grounds that it would have been teaching to the test.

### 19.10 Under the generous rule: what survives, and Q14's real failure

The §19.9 grading rule was implemented and the corpus regraded. Defensible
readings are enumerated **from the corpus before any model output is read**; a
run passes only if it declared a resolution, named an enumerated reading, and
returned _that reading's_ value. The rule can fail a run, and does: of 18
ambiguous runs, 7 failed because the number did not match the declared set, and
**two of those were strict passes the new rule demotes.** It moves results both
ways.

| Question  | Strict         | Resolution-aware |
| --------- | -------------- | ---------------- |
| Q1        | 0/6            | **6/6**          |
| Q6        | 0/3            | 0/3              |
| Q14       | 0/6            | 1/6              |
| Q18       | 3/6            | 4/6              |
| **Total** | **3/21 (14%)** | **11/21 (52%)**  |

Fresh runs made _after_ the rule existed reproduced the shift (1/9 → 4/9), so it
is not an artifact of regrading retrospectively. The older 54-run benchmark
**cannot** be regraded — it predates the field, and inferring declarations from
prose misclassified 2 of 9 runs, so the tooling refuses to guess. Ambiguity was
declared for three questions only; Q6 was refused, because the corpus models no
owner identity, so "excluding myself" is an unforced inference about the data
rather than a reading of the question.

**Q14's failure is not what it first appeared, and the distinction decides how
much the `resolution` field is worth.** It was reported as the model declaring
one set and computing another — which would make the field a fluent artifact
rather than a safety mechanism. The raw runs say otherwise:

| Run | Declared                                                           | Returned  | Consistent?                     |
| --- | ------------------------------------------------------------------ | --------- | ------------------------------- |
| 1   | JPY charges `$3,790.28` **plus** the pre-booked flight `$1,418.60` | `5208.88` | **exactly** (3790.28 + 1418.60) |
| 2   | trip window, JPY converted at each date's rate                     | `7728.3`  | yes — `inWindowOnlyUsd`         |

Expected is `9146.9` = `7728.3` (all in-window spend, every currency) + `1418.6`
(the pre-trip flight). **Run 1 got the flight but took only the JPY half of the
window; run 2 got the whole window but no flight. Each applied one of the two
inclusion rules and never both.**

So the failure is **set composition, not misrepresentation**: the model states
its set honestly and computes it exactly, but under-composes, anchoring on one
inclusion rule at a time rather than unioning them. §19.9's central claim
survives, and the field earned its place — this diagnosis was only available
_because_ the model declared its set.

That is narrower and more tractable than "unreliable on sets", and it is
precisely §3's stated Q14 difficulty: the trip is defined by two disjoint rules,
a date window and a semantically-related charge outside it, and the harder half
is knowing you need both.

**Confirmed 2026-08-29, by a route that briefly looked like a refutation.**
The scope restoration was expected to dissolve the under-composition: §19.8's
`fx.rates` run had reached `7728.3`, the whole window in every currency, so
granting it again should have left only the flight to find. It did not. Across
N=3 with `fx.rates` granted, all three runs returned **5208.88** against
`9146.9` — an error of exactly **3938.02**, which is the in-window USD spend.
`5208.88` is `3790.28` (the JPY charges, converted at each date's rate) plus
`1418.60` (the pre-booked flight): the model took the currency-conversion rule
and the outside-the-window rule and dropped the plain in-window dollar charges
between them. **Under-composition survives the scope restoration**, and §19.10's
diagnosis stands as written.

Two details worth keeping. The resolution grader classified two of the three as
`inWindowPlusFlight` on their prose, but each declaration in fact names a
JPY-only set plus the flight — the number is still exactly the set declared, and
the label match is the grader's coarseness, not the model overclaiming. And the
stuffed-context baseline arm reproduces the same composition on all three runs,
returning `5208.88` twice and `5108.88` once, its declared transaction count
wandering 38 / 48 / 54 while the total does not move. **Composition and
computation fail separately**: the baseline gets the same set wrong and, on one
run, additionally gets the arithmetic wrong — so this is not an artifact of the
code-writing path, and fixing the sum would not fix the set.

### 19.11 A stronger model resolves better and scores worse

`gemini-3.1-pro-preview`, same protocol, `temperature: 0`, `dogfood`, N=3. This
was run to separate "this model is weak" from "the architecture is weak". It
settles it, in the direction that matters.

**Pro resolves sets more consistently than Flash and passes no more often.**
On Q1 it returned **6.62 on all three runs**, declaring:

> "Resolved 'last month' as the 30 days ending on the most recent date in the
> dataset (2025-12-05 to 2026-01-04). Filtered to `type === 'long_sleep'`…
> excluded 2 rows with null `total_sleep_duration`."

That is trailing-30 — **6.6190h, n=27** in §19.9's table — computed exactly, with
the profile's nap and null rules both applied. **Its value is inside the ±0.05
tolerance** (off by 0.0425). It fails only the denominator assertion, which
requires the text to contain 28; Pro stated 27, the honest denominator for the
set it chose. **A correct number over a defensible set, failed for stating its
own denominator truthfully.**

Three defensible readings now across two model tiers: Flash-old fell into
trailing-31 by luck (3/3), Flash-new declared calendar-December, Pro declares
trailing-30. Q18 is sharper still — Pro consistently chose the _stricter_
denominator ("only days with a **complete** nutrition log"), which is arguably
the better methodology, and scored 0/3 where Flash's looser choice scored 2/3.
**The more sophisticated set choice diverges further from the eval's arbitrary
pick.**

**Genuine-reasoning failures survive the tier change.** Q17 still conflates the
two Sarahs (0/3) while burning **354k–442k input tokens and 17–20 tool calls** —
~1.7× Flash's tokens and 2× its calls for the same wrong answer. Q2 still
follows the loud source into the wrong topic, exactly as §3 predicted. These are
architectural or prompt-level, not capability-limited.

**Script variance is a property of the architecture, not of one model.** Pro:
**6/6 distinct**, raw and normalized. Flash: 54/54. Two tiers, same 100%
regeneration variance at temperature 0. §15.3's conclusion is now much better
supported than one model could support.

**The cost shape is counter-intuitive.** Pro is ~4.4× _cheaper_ per run on
questions it resolves in few turns (Q1: 15k input tokens and 1 tool call against
Flash's 66.6k and 3), because spend tracks turn count and it needs fewer. It is
dramatically more expensive on hard ones, where it thinks longer and superlinear
turn growth follows. **On this evidence a stronger model buys no additional
passes at any price.**

Caveats: the sweep did not complete all 18 — a full N=3 run was killed at ~50
minutes before writing output, and the Q8/Q16 controls are unrun. Q2 and Q17
compare Pro-on-new-prompt against Flash-on-old-prompt and are confounded, though
both are 0/3 either way. Per-token pricing was not verified; tokens are the
reported unit.

**The conclusion this forces: model capability is not the binding constraint —
the grading contract is.** Until a resolution is graded separately from the
number it produces, a better model cannot appear as a better score, and the
corpus will keep reporting sophistication as failure.

### 19.12 A methodological-disclosure contract, measured on both arms

The largest single failure bucket in the corpus was **one missing sentence**.
Q2 failed on "did not state the weighting used", Q10 on "did not report
per-period coverage", Q13 on "fails to note calendar freshness" — and Q10's own
failure reason quoted the model's correct computed figures, which it then did
not state. All three failed **identically in the stuffed baseline**, Q13 while
seeing 100% of its grant. So this was neither a retrieval failure nor an
architecture failure, and the mechanism to attack it already had a precedent:
§19.9/§19.10 showed the model complies with a contract _field_ 12/12 where it
had previously declared nothing.

Prompt doc §4's rule 3 was therefore replaced. "State your definitions and
denominators" — two lines, aspirational — became a standing obligation to end
every answer with a `Method:` paragraph giving what was measured and how, what
was included and excluded and on what basis, the denominator (per group and per
period where the answer compares them), the recency of the records used, and
what would have changed the answer. **The replacement text was written before
any failing rubric was read**, from §3's "accurate answer requires" column,
and it is question-agnostic: it names no question, no scope and no metric.
Both arms share the rules block, so both got the change.

**One correction to the premise, found while attributing rows.** Q15 was
counted in the missing-sentence bucket and does not belong there. Its recorded
failures are substantive in both arms — it names a kept intention (the dentist)
as abandoned and omits two real ones — not a disclosure omission. The bucket
was three questions, not four.

`gemini-3.7-flash`, `temperature: 0`, `dogfood` @ seed 20260828, N=3, all 18
questions, judged, same `runEval` grader on every cell.

| Arm                    | Before                 | After                      | Δ rows |
| ---------------------- | ---------------------- | -------------------------- | ------ |
| **Agent** (code loop)  | 14/54, strict 11, 6 Qs | **19/54, strict 16, 7 Qs** | **+5** |
| **Baseline** (stuffed) | 9/54, strict 6, 4 Qs   | 6/54, strict 5, 3 Qs       | −3     |

Run-to-run variance between identical-grader sweeps is **~±3 rows**, so the
agent's +5 is an effect and **the baseline's −3 is not distinguishable from
noise** and is not read as one here.

The baseline's "before" was graded under the pre-`a67f352` grader and had to be
made comparable first. `a67f352` changed only two prose rules — set-grading
exoneration and the absence integrity check — and both were checked against the
retained dump: the three set-kind questions (Q5, Q7, Q17) were already 0/9, and
the change only _removes_ exonerations, so they cannot move; Q8's three passes
were re-tested against the new `statesUnreadableCount` rule and all three state
the count beside an unreadable cue inside the retained text. Numeric and judged
grading are untouched by that commit. **The regraded baseline "before" is 9/54,
unchanged**, and directly comparable to the agent's 14/54.

**The agent's +5 is entirely the two questions the change was aimed at.**

| Q       | Before | After | Recorded failure before            |
| ------- | ------ | ----- | ---------------------------------- |
| **Q2**  | 0/3    | 3/3   | "did not state the weighting"      |
| **Q13** | 0/3    | 2/3   | "fails to note calendar freshness" |
| Q18     | 2/3    | 3/3   | — (within noise)                   |
| Q17     | 1/3    | 0/3   | — (within noise)                   |

Q18 and Q17 move one row each in opposite directions and cancel. Q2 and Q13 are
the two whose failure reason _was_ the sentence the new rule requires, and both
moved the moment it was required. Q13's one remaining failure still cites
freshness. **Q10 did not move at all** — 0/3 before and after, on the same
per-period-coverage clause — so the "give the denominator for each group and
period" clause did not land, and Q15 did not move, as its failure was never
disclosure. Q2 and Q13 are model-graded, and a judge is not a measurement: what
raises confidence is that the reason string is identical across all three before
runs and absent from all three after runs, not the count alone.

**The baseline could not comply with the contract, and that is the finding.**

| Arm      | `Method:` present | Median answer chars | Input tokens  |
| -------- | ----------------- | ------------------- | ------------- |
| Agent    | 1/54 → **52/54**  | 836 → **1771**      | 2.48M → 2.64M |
| Baseline | 0/54 → **10/54**  | 347 → **334**       | 36.0M → 40.0M |

The agent arm complied almost universally and roughly doubled its answer
length. The baseline arm's answers did not get longer at all. Asked the same
thing by the same words, it kept returning ~330-character answers — Q2's was
184 characters against a ~881k-token prompt — and its Q2 and Q13 failures come
back verbatim, still "did not state the weighting used" and still "fails to
note calendar freshness". Its three lost rows are all disclosure-adjacent
integrity checks (a denominator not stated, `coverage.complete` false and not
said so), which is suggestive and is _not_ claimed as an effect at −3.

**So the contract was a binding constraint, and it was not the only one.** The
question this run was built to answer was whether the baseline would gain as
much as the agent, which would have shown the architecture was doing nothing.
It gained nothing: **the gap between the arms widened from 5 rows to 13.** The
honest reading is that a disclosure obligation is only worth what the
architecture can afford to spend on satisfying it — an arm that has consumed
its context window on raw records has no room left to explain itself, and
telling it to explain itself more does not create that room. Compliance
capacity, not instruction quality, is what separated the two arms here.

Caveats. The ±3 band is inherited from prior identical-grader sweeps and was
not re-measured for this pair, so the baseline's −3 could be a small real
regression that this design cannot resolve; distinguishing them needs repeats
the corpus did not get. Q2/Q13/Q10/Q15 are model-graded. The contract was
written once and not revised after seeing results, so no second experiment is
folded into these numbers. Nothing here reopens plan §6, and no tolerance,
ground truth, rubric, fixture or grader was changed — the only edit under test
is the rule-3 replacement, applied identically to both arms.

### 19.13 A value-provenance contract: tried, and abandoned

Q11 looked like the clean case for an answer-selection defect. It reports
69.43 against an expected 66.25, and the reading going in was that the script
computes the right series and then the answer headlines a number from a
different table. If that were right it would be the most corrosive failure mode
available — a figure the reader cannot trace to the computation that produced
it, invisible to the grader whenever the untraceable number happens to be
correct.

Rule 1 was therefore extended. "Compute, never estimate" governs how a number
is _produced_ and said nothing about how it reaches the answer, which is the
unguarded half. The addition requires every reported figure to be one the final
script produced, printed and then carried into the answer verbatim rather than
restated from memory or from an earlier turn; requires a number computed by an
earlier run to be recomputed before it is reported; and requires the answer to
name, beside the headline figure, the computation behind it. **The text was
written and saved before any rubric, dump or transcript was opened** (file
mtimes carry the order), and it is question-agnostic: it names no question,
scope, metric or table. Both arms share the rules block, so both got it, the
stuffed arm in the same no-script-API translation as the rest of its rules.

`gemini-3.7-flash`, `temperature: 0`, `dogfood` @ seed 20260828, N=3, all 18
questions, judged. All four cells were graded by the same `runEval` grader —
between `a67f352` and this run only prompt text changed — so unlike §19.12 no
regrade was needed to make before and after comparable.

| Arm                    | Before                 | After                  | Δ rows |
| ---------------------- | ---------------------- | ---------------------- | ------ |
| **Agent** (code loop)  | 19/54, strict 16, 7 Qs | 19/54, strict 17, 8 Qs | **0**  |
| **Baseline** (stuffed) | 6/54, strict 5, 3 Qs   | 7/54, strict 4, 3 Qs   | **+1** |

The noise band is ~±3 rows. **Neither arm moved.** In the agent arm four
questions each moved by exactly one row — Q6 +1 and Q17 +1 against Q2 −1 and
Q13 −1 — which is the signature of variance, not of an effect. The baseline's
single row is Q1 going 2/3 to 3/3. **Q11, the question the change was aimed
at, was 0/3 before and 0/3 after.**

**The contract was complied with, and the compliance is measurable.** A number
copied out of a computation keeps that computation's precision; a number a
writer restates gets rounded. Counting `value` fields carrying more than four
decimal places:

| Arm      | Full-precision `value` | `value` present | Median answer chars | Input tokens  |
| -------- | ---------------------- | --------------- | ------------------- | ------------- |
| Agent    | 0/14 → **11/15**       | 18/54 → 20/54   | 1779 → 1820         | 2.64M → 4.79M |
| Baseline | 0/10 → **2/10**        | 13/54 → 13/54   | 335 → 297           | 40.0M → 38.3M |

Before the change the agent arm reported `6.68`, `61.79`, `2054.7`, `69.43`;
after it reported `6.681697530864197`, `61.78977272727273`,
`2054.703703703704`, `69.42857142857143`. The instruction landed almost
perfectly and changed the score by nothing. The same split as §19.12 appears
again — the agent arm complies, the baseline arm largely cannot — but here
compliance bought nothing, so the split is not worth much.

**The premise was wrong, and re-executing the scripts is what showed it.** The
dump stores each run's script source but not its output, so "is the reported
number the one the final computation produced" is not decidable from the dump.
Replaying every final script that reported a numeric `value` against the same
corpus and the same per-question grant — a fresh sandbox host per script, since
coverage accumulates across `execute()` calls — and collecting every number the
script emitted gives:

| Arm   | `value` found in the final script's own output |
| ----- | ---------------------------------------------- |
| Agent | 13/18 → 16/20 (38 of 38 replays ran)           |

Values were already traceable roughly three times in four, and the change moved
untraceable rows from 5 to 4, which at that denominator is nothing. More
decisively, **Q11's 69.43 is traceable in every run that reported it.** The
final script computes it, at full precision, from the seven nightly
`average_heart_rate` values `[61,77,60,63,76,75,74]` in the sleep records. The
graded-correct 66.25 is the mean of `oura.heartrate` filtered to rest/sleep
over the same window, n=8. So the number is not imported from somewhere else;
it is the honest output of the script the model wrote. **Q11 is a
wrong-series defect inside the script, not an answer-selection defect at the
reporting step**, and a rule about carrying numbers out of a computation cannot
touch it.

Two rows are worth keeping from the replay. One after-run printed both figures
in its own notes — `Last 7 days avg: 69.43 bpm` beside
`oura.heartrate rest/sleep ... recent (last 7d, n=8) mean: 66.25` — and
headlined the wrong one; that single row is a genuine answer-selection defect,
one of six. And one before-run computed 66.25, the correct answer, and then set
no `value` at all, so it was graded ungradeable. The right number was produced
and lost at the contract boundary, which is a `value`-emission problem and not
a provenance one.

**The change also costs.** Agent input tokens went 2.64M to 4.79M, +82%, on
only +4% more scripts (215 to 224). Telling the model to print its figures
makes it print more, and printed output re-enters the context on every
subsequent turn. That is a real price for a zero-row result.

**Verdict: tried and abandoned.** The rule is question-agnostic, was written
before the data was read, was complied with almost perfectly, and produced no
movement in either arm at N=3 — 0 rows and +1 row against a ±3 band — while
raising the agent arm's input cost by 82%. It is not retained. The finding that
justifies the cost of the run is the diagnosis it forced: Q11 does not fail on
provenance, and the answer-selection defect it was thought to exemplify occurs
in about one run in six rather than as a systematic fault. The work worth doing
on Q11 is on series selection — which of two defensible heart-rate sources the
question means — and that belongs to the resolution machinery of §19.9/§19.10,
not to the response contract.

Caveats. The ±3 band is inherited from prior identical-grader sweeps and was
not re-measured here. The traceability denominators are small (18 and 20 rows),
so the 13/18 → 16/20 movement is not resolvable either way. The replay
re-executes the final script only, in a fresh host, so a run whose answer
depended on an earlier turn's output is judged on the last script alone. Q2,
Q13 and Q17 are model-graded. The contract was written once and not revised
after seeing results, so no second experiment is folded into these numbers, and
nothing here reopens plan §6. No tolerance, ground truth, rubric, fixture or
grader was changed; the only edit under test is the rule-1 extension, applied
identically to both arms, and it reverts with
`git checkout becc984 -- docs/260828-query-layer-prompt.md packages/core/src/query/agent/prompt.ts packages/core/src/query/evals/answerers/stuffed-answerer.ts`.

### 19.14 `vana.classify` was never wired up — and wiring it changed nothing

§19.8 recorded that `vana.classify` was called in 0 of 54 runs and read that as
a cost model that did not describe the system. Two further N=3 sweeps put the
count at **0 of 162**, and §19.12's after-sweep added 0 of 54 more. The obvious
hypothesis was prompt suppression: rule 8 said "`vana.classify` is expensive"
and offered nothing on the other side of the scale. That hypothesis is wrong,
and what is true instead is worse.

**The tool has no implementation, and never had one.**

`createVanaApi` throws `CAPABILITY_UNAVAILABLE` when `deps.classify` is absent
(`tools/api.ts`). `deps` is built in exactly one non-test place —
`runner-entry.ts`'s `buildDeps` — and that function returns four members:
`listScopes`, `streamScope`, `readBlocks`, `search`. No `classify`, and no
`introspect` either. The only two `classify` implementations in the repository
are test stubs. Driven through the eval harness's own wiring, before any change:

| Call                  | Outcome                                                      |
| --------------------- | ------------------------------------------------------------ |
| `vana.readAll(scope)` | 2,200 records                                                |
| `vana.classify(...)`  | `CAPABILITY_UNAVAILABLE` — "classify is not registered"      |
| `vana.search("quit")` | `SCRIPT_ERROR` — "was not resolved by the host for this run" |

There is no second path where it might have been registered: nothing outside
`scripts/query-eval-harness.ts` and the tests constructs a tool host at all, so
the eval path _is_ the only path. **Budget was not the cause** — the harness
passed no `classifyUsd`, and an undefined ceiling means no ceiling rather than
a ceiling of zero.

**And the model never tried.** Across the six retained agent sweeps — 279 rows,
880 retained scripts, none elided by the retention cap — the string
`vana.classify` appears **zero times**. The tool was simultaneously unreachable
and unreached, and each failure hid the other: had a script attempted it once,
the denial would have surfaced as a run error long before anyone read a counter.

**Why it was not a one-line fix.** Judgement needs a model call; a model call
needs network and a credential; and the OS sandbox denies both by construction
— `allowedDomains: []` with `strictAllowlist: true`, and the child spawned with
`stdio: ["ignore", "pipe", "pipe"]`. There is no egress and no channel back to
the host mid-run. `search` has the same problem and answers it by
precomputation, which `classify` cannot use: only the running script knows which
items it wants judged.

**What that already implies for §18.3.** §18.3 predicted semantic questions
dominate spend through per-item `classify`, and §19.8 reported that prediction
falsified. It was never tested. The cost model was not wrong about the system;
it described a capability the system did not have. The same holds for the
contract doc: `260828-query-layer-prompt.md` §5 routes **Q2, Q9, Q10 and Q15**
through `classify`, and Q9's row carries the warning that names this corpus's
actual Q9 failure exactly — "prefilter can miss the earliest oblique mention".
Four questions had a prescribed solution no run could execute.

**The change**, in two parts, both question-agnostic and inside one revert
boundary.

_Wiring._ `classify` becomes a deferred round trip — the shape of
`searchResults`, resolved between runs rather than before them. The runner looks
up `(instruction, items)` in a host-supplied `classifyResults` map; a miss ends
the run with `CLASSIFY_DEFERRED` and carries the batch outward in the result
frame's new `classifyRequest` field. The host judges it, caches it under the
runner's key, and replays the same script. Replay is sound because a script only
reads: it re-derives the same batch, finds it answered, and runs on to the next.
Bounded at eight rounds per `execute`, cached for the life of a request, capped
by `classifyUsd`, and an oversized batch is refused with
`CLASSIFY_BATCH_TOO_LARGE` rather than bursting a frame — a frame cut mid-write
costs the run all of its coverage. Verified working end to end against a stub
judge before the sweep: two batches deferred and answered in one `execute`,
coverage intact at 2,200 records and `complete: true`, the second turn of the
same request paying nothing, and an unregistered host still giving the honest
`CAPABILITY_UNAVAILABLE`.

_Guidance._ Rule 8 was a cost warning with nothing opposing it. It now leads
with the failure mode the tool exists to prevent — `filter`, `includes` and
`search` all match wording, so they miss any record carrying the property
without carrying its vocabulary — and keeps the cost sentence as a batching
instruction rather than a deterrent. It names no question, scope, metric or
planted value.

`gemini-3.7-flash`, `temperature: 0`, `dogfood` @ seed 20260828, N=3, all 18
questions, judged, same `runEval` grader. **Agent arm only:** `classify` is a
tool call and the stuffed baseline has no tool loop, so a baseline re-run would
have measured nothing here and was deliberately not spent.

| Arm       | Before                 | After                  | Δ rows |
| --------- | ---------------------- | ---------------------- | ------ |
| **Agent** | 19/54, strict 16, 7 Qs | 17/54, strict 14, 8 Qs | **−2** |

**Run-to-run variance is ~±3 rows, so −2 is not an effect. The change did
nothing measurable, and it is more interesting that it did not.**

**`classify` was called 0 times out of 54 — exactly as before.** Not once did a
script write `vana.classify`, in 219 scripts across the sweep. Relay calls: 0.
Items judged: 0. Cost: $0.00. The tool is now genuinely reachable and remains
entirely unused, so **§18.3's cost model is still untested**: making the
capability real was necessary to test it and was not sufficient.

Every moved row, attributed:

| Q       | Before | After | Reading                                          |
| ------- | ------ | ----- | ------------------------------------------------ |
| **Q2**  | 3/3    | 1/3   | −2, the largest single move; see below           |
| **Q13** | 2/3    | 1/3   | −1, within noise                                 |
| **Q8**  | 3/3    | 2/3   | −1, provider defect, not the change              |
| **Q6**  | 2/3    | 3/3   | +1, within noise                                 |
| **Q9**  | 0/3    | 1/3   | +1, within noise — and it did not use `classify` |

Six rows moved in absolute terms across five questions, netting −2. No question
moved by 3 or more, so none of these is separable from variance individually.
Q8's lost row produced no script at all: three consecutive replies discarded by
the provider with `MALFORMED_FUNCTION_CALL`, the known Gemini defect §19.12's
diagnostic channel exists to record. Rows that produced no script at all were 2
before and 3 after.

**Q9 is the question this was built for, and it is the clearest negative
result.** It moved 0/3 → 1/3, one row, inside the noise band — and the passing
run **did not call `classify`**. It scanned `notes`, `slack` and
`chatgpt.conversations` in full across five turns, worked out the shape of the
corpus's filler sentences, and found the planted oblique mention by elimination.
The two failing runs did what every previous sweep did: cited a later explicit
mention. So the one row that moved is not evidence for the tool; if anything it
is weak evidence for the rewritten rule 8's first half — the warning that a
keyword filter misses meaning — arrived at by a route the rule did not name.

**The other recall-shaped questions did not move at all.** Q5 0/3 → 0/3, Q15
0/3 → 0/3, Q3 0/3 → 0/3, Q10 0/3 → 0/3, each failing on the same recorded
reason as before: Q5 still admits the excluded restaurant, Q15 still names only
one of three abandoned intentions, Q3 still declines to decompose into
computable sub-quantities, Q10 still omits per-period coverage. **The semantic
recall class is untouched.**

**And it was not free.** Input tokens rose from 2.638M to 3.411M, **+29%**, for
a tool that was never called. Turn count barely moved (215 → 219 scripts), so
this is not more tool use; the median row rose 35.4k → 42.1k input tokens
(+19%) and the tail got heavier — Q6 run 0 took 15 turns against a prior worst
of 9, and Q17 run 0 cost 462k input tokens against a prior worst of 249k. The
longer rules block accounts for perhaps 2% of the median rise, so the rest is
behavioural: told that keyword filters miss things, the model scanned and
iterated more, and bought nothing with it. Output tokens fell slightly (170k →
156k) and wall time was flat (19.2 → 19.7 min). **A ~29% spend increase for a
−2 row change is the honest trade recorded here.**

**Verdict. The diagnosis is the result; the fix is not.** The finding worth
keeping is that a tool documented in the prompt, specified in the API contract
and prescribed as the solution to four separate questions had no implementation
for the entire life of the corpus, and that no counter caught it because nothing
ever called it. Making it real was correct on its own terms — a documented
capability that throws is a defect regardless of whether anything scores better
— but it moved no rows, and the guidance change that came with it cost 29% more
input tokens for nothing. On these numbers the wiring is worth keeping and the
rule-8 rewrite is not obviously worth its price; a cleaner experiment would
separate them, which this one deliberately did not.

**What this leaves for a human to decide, and does not decide.** §18.3's cost
model is now testable for the first time and still untested, because the model
does not reach for the tool even when told when to. Two readings are open:
either judgement is genuinely unnecessary for these questions, or the agent
cannot recognize the situations that call for it from a rule alone. Only the
second would be an argument for standing machinery. **Plan §6's "embeddings are
out of v1" therefore stands undisturbed here, and this section is not an
argument to revisit it** — the design's existing answer to semantic recall was
tested and produced no gain, but it was also never exercised, so nothing here
shows that lexical-plus-judgement is insufficient. What it does show is that
the next experiment on this class should make the agent's _use_ of judgement
the variable, not its availability.

Caveats. The ±3 band is inherited from prior identical-grader sweeps and was not
re-measured. Q2, Q13, Q9, Q3, Q10 and Q15 are model-graded. Wiring and prompt
guidance moved together, so their effects cannot be separated from this sweep.
`classify`'s cost path is exercised only by a stub judge, never by the relay, so
the price of real judgement remains unmeasured. `SYSTEM_PROMPT_VERSION` was left
at `vana-query-prompt/4` despite the template changing, matching §19.12's
precedent; a comment in `stuffed-answerer.ts` pins that string and that file was
out of scope. No tolerance, ground truth, expected answer, rubric, fixture or
grader was changed, and nothing here resolves an open item in plan §6.

### 19.15 `vana.search` was unusable too — and wiring it changed nothing, because the model writes its own search

§19.14 recorded, in passing, that `vana.search` was as unusable in the eval
harness as `classify`. The difference is that `search` has a real host-side
implementation — `search-bridge.ts`, MiniSearch-backed, grant-filtered,
deliberately host-authority — and that the model **does** reach for it. Across
the three retained agent sweeps before this one, `vana.search` appears in the
scripts of 4, 5 and 2 rows respectively, concentrated on exactly the questions
this section is about: Q3 four times, Q15 three, Q16 twice, Q5 once, Q4 once.
Every one of those calls threw.

**The cause was structural, not missing code.** `runner-entry.ts` served
`search` from a `searchResults` map the host precomputed _before_ the run, and
the host cannot predict what a running script will search for. The eval harness
supplied no map at all, so every call hit the honest denial. So the four
questions the contract doc routes through `prefilter → classify → min(date)`
had both halves unavailable, and the conclusion recorded against Q3, Q5, Q9,
Q10 and Q15 — that semantic recall is the architecture's one genuine weakness —
was measured against an agent holding no semantic tools.

**The change is wiring only.** `search` becomes a deferred round trip, reusing
§19.14's reverted `classify` pattern verbatim in shape: the runner looks up
`(query, scopes, limit)` in a host-supplied map keyed by an FNV-1a hash, a miss
ends the run with `SEARCH_DEFERRED` and carries the query outward in the result
frame's new `searchRequest` field, and the host resolves it against the index
and replays the same script. Replay is sound because a script only reads.
Bounded at eight rounds per `execute`, cached for the life of the request, and
capped at 25 hits. The index is built by handing documents to the repo's
existing `MiniSearchIndex` — the same thing `mcp/tools.ts` does per block page,
at the scale of a request instead of a page — so plan §5's "PR #231's mistake"
is not repeated: nothing is persisted, no second index implementation exists,
and no embedding or derivative is created.

Two properties were verified by execution before the sweep, against a
purpose-built harness: a search that the host cannot resolve still **denies**
rather than returning `[]` — an empty array reads as "there is nothing there",
which is the Q8 false negative, and only the index itself may say "no hits" —
and coverage accounting stays correct, with `vana.search` recording
`prefiltered()` and never contributing to `recordsScanned`. A grant-crossing
search returns nothing from the ungranted scope. Multi-round replay resolves
three distinct queries in one `execute`.

**No prompt text was changed.** Rule 4 and the API block already documented
`vana.search`, so nothing had to be said to make the tool known, and §19.14's
stated regret — that wiring and guidance moved together and could not be
attributed — is answered here by moving only the wiring. The single variable is
whether the tool works.

`gemini-3.7-flash`, `temperature: 0`, `dogfood` @ seed 20260828, N=3, all 18
questions, judged, same `runEval` grader. **Agent arm only:** the stuffed
baseline has no tool loop, so a baseline sweep would have measured nothing here
and was deliberately not spent.

| Arm       | Before                 | After                  | Δ rows |
| --------- | ---------------------- | ---------------------- | ------ |
| **Agent** | 19/54, strict 16, 7 Qs | 20/54, strict 16, 8 Qs | **+1** |

**Run-to-run variance is ~±3 rows, so +1 is not an effect.** Three rows moved
in absolute terms across three questions — Q6 2/3→3/3, Q9 0/3→1/3, Q8 3/3→2/3 —
netting +1. No question moved by 3 or more, so none is separable from variance
individually, and none of the three moved rows called `search`.

**The recall class did not move.**

| Q       | Before | After | Called `search` | Recorded failure, after                                 |
| ------- | ------ | ----- | --------------- | ------------------------------------------------------- |
| **Q3**  | 0/3    | 0/3   | 1 of 3          | still does not decompose into computable sub-quantities |
| **Q5**  | 0/3    | 0/3   | 0 of 3          | still admits the excluded restaurant                    |
| **Q9**  | 0/3    | 1/3   | 0 of 3          | two runs still cite a later explicit mention            |
| **Q10** | 0/3    | 0/3   | 0 of 3          | still omits per-period coverage                         |
| **Q15** | 0/3    | 0/3   | 0 of 3          | still names only one of three intentions                |

**`search` was called in 1 row of 54 — down from 4 of 54 when it did not
work.** Both counts are too small to read as a trend, and the honest statement
is that making the tool usable did not make it used. The one call, on Q3 run 0,
resolved: the run carries `method: "prefiltered"`, which `api.ts` sets only
after `deps.search` returns, so the deferred round trip is confirmed working
end to end in the live eval path. No `SEARCH_DEFERRED`, `SEARCH_ROUNDS_EXHAUSTED`
or `CAPABILITY_UNAVAILABLE` appears anywhere in the sweep. The query was
`"risk appetite risk tolerance investing portfolio stocks crypto asset
allocation financial goals retirement"` over `chatgpt.conversations`, it
returned hits, and Q3 failed for the same reason as before — a decomposition
failure that no retrieval improvement can touch.

**What the other 53 rows did instead is the finding.** The model does not
ignore search; it reimplements it.

| Behaviour, after sweep                                                         | Rows  |
| ------------------------------------------------------------------------------ | ----- |
| called `vana.search`                                                           | 1/54  |
| full scan via `vana.readAll` / `vana.stream`                                   | 50/54 |
| lexical matching **inside the script** (`includes`, `indexOf`, `match`, regex) | 34/54 |

In the recall class the split is total: **15 of 15 after-runs scanned, 15 of 15
did their own in-script lexical matching, and 1 of 15 called the tool**, each
run pulling 3,600 to 13,000 records into the sandbox to do it. On this 20.2MB
corpus that is a rational choice rather than a mistake — `readAll` is one call,
the filter that follows is exact rather than ranked, it needs no round trip,
and it produces the full-pass coverage that rule 4 demands for existence
questions, which a ranked prefilter explicitly cannot. **The tool loses to the
in-script substitute on this corpus on the merits.** That is a different and
more useful conclusion than "the tool does not help", and it does not survive a
corpus that no longer fits: the substitute's cost is linear in records and the
tool's is not, so the crossover is a property of corpus size, not of the model.

**Q9's single pass did not use search.** Run 1 scanned 12,600 records across
`notes`, `slack` and `chatgpt.conversations` in seven scripts and found the
planted oblique mention by exhaustion; the two failing runs cited a later
explicit mention, as every previous sweep did. This is the **second** time the
only passing run on a recall question has arrived by full scan rather than by
retrieval — §19.14 recorded the first, on the same question — and it is the
sharpest available evidence that on a corpus this size exhaustion is simply a
better strategy than ranking.

**Cost.** Input tokens rose 2.638M → 3.716M, **+41%**, and almost none of it is
attributable to this change: no prompt text moved, and 53 of 54 rows never
touched the new path. The rise is one runaway row — Q6 run 0, 19 scripts and
946k input tokens against a prior worst of 249k, which called `search` zero
times. Excluding the largest row from each sweep the rise is +16%; the median
row moved 35.4k → 37.3k, **+5.4%**. Scripts fell 215 → 203, output tokens fell
170k → 162k, and wall time was 18.7 min, in line with the 19.2–19.7 min of
prior sweeps despite replay being available. Read as variance, not as a price
paid for the tool.

**Verdict. The wiring is correct and the result is negative.** A documented
capability with a real implementation was unreachable for the entire life of
the corpus and is now reachable, verified by execution; it moved the score by
+1 row against a ±3 band, moved the recall class by nothing, and was called
once in 54 runs. On these numbers the wiring is worth keeping because a
documented capability that throws is a defect regardless of score, and the
retrieval story is worth nothing yet.

**What this does to "semantic recall is the architecture's weakness."** The
claim does not survive, and it does not die either — it changes from
unsupported-because-untested to unsupported in a new and more specific way.
Before this section the claim was an artifact: it was measured against an agent
whose semantic tools all threw. Now both the measurement and the tools are
real, and the claim is still unmeasured, because the agent does not use the
tools even when they work. What the corpus actually demonstrates is narrower
and firmer: **on 20.2MB, scanning beats retrieving, and the two recall rows
that have ever passed both passed by scanning.** Whether better retrieval would help
is a question this corpus cannot answer, because the agent has a cheaper
strategy available that ranking never gets to compete with.

**What this leaves for a human to decide, and does not decide.** One diagnostic
is worth recording as evidence, not as an argument. Replaying the queries the
model itself issued against the now-working index shows retrieval quality
varies enormously by question: `"Thai"` returns the three relevant restaurant
messages at the top; the Q15 query `"keep saying I will"` returns 4 hits
covering **2 distinct subjects**, 3 of them the same note, so it reinforces
exactly the one-intention answer Q15 already fails on; `"meaning to"` and
`"productivity"` return 0 hits each. That is a vocabulary-coverage failure, and
it is the failure mode embeddings exist to address — which is a fact about
lexical search, **not a recommendation**. Plan §6's "embeddings are out of v1"
is recorded as decided and nothing here reopens it; no index was built and none
is proposed. The prior question is cheaper anyway: a retrieval tool that is
never called cannot be improved into relevance, so the next experiment on this
class should make the agent's _use_ of retrieval the variable — or change the
corpus size until scanning stops being free — rather than its quality.

Caveats. The ±3 band is inherited from prior identical-grader sweeps and was not
re-measured. Q3, Q9, Q10 and Q15 are model-graded. Search usage is counted from
retained script text, so a call in a script elided by the retention cap would be
missed; no scripts were elided in this sweep. The tool-versus-scan comparison is
confounded with corpus size by construction and cannot be separated without a
larger corpus, which this run did not have. `vana.classify` remains
unimplemented and untouched, so the `prefilter → classify` path the contract doc
prescribes is still only half-available. `SYSTEM_PROMPT_VERSION` is unchanged
and correctly so, since no prompt text moved. No tolerance, ground truth,
expected answer, rubric, fixture or grader was changed, `stuffed-answerer.ts`
was not touched, and nothing here resolves an open item in plan §6. The wiring
reverts with
`git checkout d3c89d3 -- packages/core/src/query/tools/errors.ts packages/core/src/query/tools/index.ts packages/core/src/query/tools/protocol.ts packages/server/src/query/runner-entry.ts packages/server/src/query/sandbox-tool-host.ts packages/server/src/query/search-bridge.ts scripts/query-eval-harness.ts`,
verified by execution: after the revert `git diff d3c89d3` on those paths is 0
bytes, and re-applying restores all seven files to matching SHA-256 digests.
This section sits outside that boundary.

### 19.16 Scale: the same corpus semantics at 252MB

Every number in §19 was measured at 20.2MB. §18's "scanning is free" was a
simulation, and §19.15's finding — that the model reimplements search in
JavaScript rather than calling the tool — was explicitly flagged as a property
of corpus size, because the in-script substitute's cost is linear in records and
the tool's is not. This section measures both at 12.5x the corpus.

**The corpus.** A new profile, `dogfood-xl`: `full`'s record counts with
`dogfood`'s flags (`semanticProse`, `extraSources`, `nutritionCoverage 0.72`,
drifting FX). `full` itself was unusable for this because it sets
`semanticProse: false`, which makes Q2, Q9, Q10, Q13, Q15, Q16, Q17 and Q18's
nutrition join structurally vacuous. The four existing profiles were not
touched; a new key draws from its own per-stream `Rng`, so no committed trap
number moves.

|                | `dogfood` | `dogfood-xl` | ratio |
| -------------- | --------- | ------------ | ----- |
| bytes          | 20.2 MB   | **252.2 MB** | 12.5x |
| records        | 54,371    | **730,722**  | 13.4x |
| files / scopes | 20 / 18   | 24 / 18      |       |
| generation     | 151 ms    | 1,379 ms     | 9.1x  |

**The corpus grew 12.5x; the part any question can see grew 6.8x.** Summed over
the scopes some question is granted, 14.24MB -> 96.40MB. `spotify.streaming`
(4.87 -> 138.78MB) and `browser.history` (0.84 -> 16.76MB) grew most and are in
no grant. Eight scopes are day-indexed and do not scale at all, because
`sleepDays` is 1100 in every profile by the rule recorded in `profiles.ts`.
Per-question grant growth is therefore uneven, from 1.00x (Q1, Q18) through
8.5-8.9x (Q2, Q4, Q5, Q6, Q9, Q17) to 12.0x (Q11). **This is a density test, not
a longer-window test**, and the questions are not all scaled equally.

#### The ground truth recomputes, and one expectation correctly refuses to

The reference answerer passes the **identical 9/18** on both corpora — Q1, Q5,
Q6, Q7, Q8, Q11, Q14, Q17, Q18 — so no expectation is a hardcoded constant that
broke. Reference compute stays in milliseconds at 252MB: Q5 44 -> 316 ms, Q8
21 -> 205 ms, Q17 109 -> 705 ms, Q14 6 -> 13 ms. **§18.1's scan-is-free premise
is now measured rather than simulated.**

One expectation does not scale, and the code already knew: `readingsFor` returns
the enumerated readings only when `profile === "dogfood" && seed ===
DEFAULT_SEED`, because a reading is a window plus the number that window yields
and those numbers are facts about the 20MB corpus. On `dogfood-xl` every
question grades strictly. Nothing was regenerated. **The consequence is that the
comparable 20MB figure is the strict scoreboard, 16/54, not the headline 19/54**,
whose extra three rows were won by resolution-aware grading on Q1/Q14/Q18.

#### The planted anchors survive, except the one that cannot

Arc lines are emitted per-record at `ARC_LINE_CHANCE`, so they scale with
volume: Q9's oblique first-mention lines go 14 -> 109, 16 -> 111 and 9 -> 81,
Q2's `#office-move` rows 39 -> 354, Q16's stated morning claims 159 -> 1,232,
Q17's two Sarahs 454/448 -> 4,737/4,809 as distinct users. Q16's measured
rebuttal is preserved exactly — the commit stream still peaks at hour 7 with a
61.8% early-morning share on both corpora. Q8's fixed counts hold (340
documents, 22 unreadable, 0 occurrences of the conflict marker).

**Q5's needle is the exception, by construction.** It must occur exactly once,
so it went from 1-in-54,371 records to 1-in-730,722 — a 13.4x dilution, the only
anchor that gets relatively harder. Q5 was 0/3 at 20MB and 0/3 here, so this
cannot be read as a caused regression, but **Q5 at scale is not the same test as
Q5 at 20MB** and should not be compared as though it were.

#### The agent arm: sub-linear in every cost dimension

`gemini-3.7-flash`, `temperature: 0`, `dogfood-xl` @ seed 20260828, N=3, all 18
questions, judged, same `runEval` grader.

|                                 | 20.2MB       | 252.2MB      | ratio       |
| ------------------------------- | ------------ | ------------ | ----------- |
| records scanned, 54 rows        | 364,341      | 2,853,197    | 7.8x        |
| bytes streamed into the sandbox | 0.20 GB      | 1.36 GB      | 6.8x        |
| median row bytes streamed       | 2.0 MB       | 15.0 MB      | 7.5x        |
| max row bytes streamed          | 10.1 MB      | 75.1 MB      | 7.4x        |
| **input tokens**                | **2.638M**   | **4.421M**   | **1.68x**   |
| output tokens                   | 169.5k       | 203.2k       | 1.20x       |
| **wall clock**                  | **19.2 min** | **28.3 min** | **1.47x**   |
| scripts / tool calls            | 215          | 347          | 1.61x       |
| median row input tokens         | 35,415       | 57,130       | 1.61x       |
| **strict score**                | **16/54**    | **12/54**    | **-4 rows** |
| questions with >=1 strict pass  | 6            | 7            | +1          |

**A 6.8x working set costs 1.68x the tokens and 1.47x the wall clock.** The
mechanism is the one the architecture exists for: reduction happens inside the
sandbox and only summaries cross into context. Records scanned rose 7.8x while
input tokens rose 1.68x, and the residual tracks turn count (scripts +61%,
median row +61%) rather than record count — §19.8's "spend tracks turn count"
holding along a corpus-size axis it was never measured on.

**The -4 rows are at the edge of the ~±3 band and do not look like a scale
effect.** No question moved by 3 or more, so none is separable individually. And
the losses do not correlate with how much each question's data grew: Q18 lost
two rows while its grant is byte-identical on both corpora (1,007 records), Q13
lost two at 2.34x growth, Q2 lost two at 8.48x — while Q6 gained one at 8.59x
and Q11, the largest growth in the corpus at 12.0x, was 0/3 on both. If scale
were degrading answers the losses should concentrate on the high-growth
questions, and they do not.

**Failure kinds did not change.** The 42 failures are the same kinds as the 38
at 20MB, dominated by the same recorded reasons — set resolution, missing
per-period coverage, the Q9 oblique mention, the Q15 intentions. Harness-level
losses: two rows ended in `malformedToolCall` against one at 20MB, and one row
(Q9 run 1) ended in `stoppedBecause: "error"` after streaming 73.5MB across 20
tool calls. **No timeouts, no out-of-memory, no truncated scans, and zero budget
kills** (three budget-related reasons at 20MB, none here). The sandbox streamed
75.1MB into a single row without failing.

#### Coverage integrity held exactly, which is the safety result

Every `complete: true` row was checked row by row against the generated
per-scope record counts. **False completeness: 0 of 35 at 252MB, and 0 of 45 at
20MB.** Nothing scanned a fraction and reported success. The derivation in
`tools/coverage.ts` is why: `complete` is host-authored and requires
`#partiallyScanned.size === 0`, so a bounded read falsifies it and the model
cannot buy a completeness claim by sampling.

`complete` fired on 35/54 rows rather than 45/54, which is the honest direction —
more rows ran out of turns before covering the grant, and said so.

**Silent confidence stayed at 0/54 on the agent arm at both sizes.**

#### The baseline goes blind, as predicted, and that is the whole comparison

`--answerer stuffed`, same protocol. Its cost is context-bounded and did not
blow up: **40.03M -> 42.61M input tokens, +6.4% against a 12.5x corpus**,
confirming rather than assuming.

|                            | 20.2MB                 | 252.2MB                |
| -------------------------- | ---------------------- | ---------------------- |
| strict score               | 5/54                   | 5/54                   |
| questions with >=1 pass    | 3                      | 2                      |
| input tokens               | 40.03M                 | 42.61M                 |
| **fraction of grant seen** | **60.0%**              | **9.2%**               |
| `coverage.complete` true   | 23/54                  | 12/54                  |
| silently confident rows    | 19 (61% of incomplete) | 12 (29% of incomplete) |

**The one number this section exists for:**

| arm                                 | 20.2MB    | 252.2MB   |
| ----------------------------------- | --------- | --------- |
| **agent, fraction of grant seen**   | **95.1%** | **93.6%** |
| **stuffed, fraction of grant seen** | **60.0%** | **9.2%**  |

The agent's coverage is flat across a 12.5x corpus. The baseline's is inversely
proportional to it, which is what context-bounded means. At scale the stuffed
arm sees 3-4% of the grant on every prose-heavy question (Q2, Q5, Q9, Q10, Q15,
Q16) and 0% on Q11.

**The silent-confidence rate fell rather than rose, and the mechanism is
instructive.** 19 rows -> 12, and 61% -> 29% as a share of incomplete rows. It
did not get more honest by getting better: it got more honest because
`stuffed-answerer.ts` tells the model in the prompt how many records were
dropped, and at 252MB that warning fires on 42 of 54 rows instead of 31, so more
answers hedge. The absolute safety gap is still the finding — **0/54 silently
confident on the agent arm at both sizes, against 12-19 rows on the baseline** —
but the direction at scale is the opposite of what was expected, and is recorded
that way. (The "52% at 20MB" this run was set up to compare against does not
appear anywhere in this document; the only 52% here is §19.10's
resolution-aware pass rate, which is a different quantity. The measured
baseline figures are the ones above.)

#### The §19.15 crossover, on the demand side and then the supply side

**The model's strategy did change, and in exactly the predicted direction.**
`vana.search` calls rose from 4/54 to **16/54**, and became systematic instead
of sporadic: at scale they concentrate entirely on the recall class and appear
on nearly every run of it (Q3 3/3, Q9 3/3, Q10 3/3, Q16 3/3, Q15 2/3, Q5 1/3,
Q17 1/3). The shape is visible in the scripts — on Q9 run 0 the model's _first_
script is ten queries in a loop over `vana.search`, and only after it fails does
script 1 fall back to `vana.stream` with an in-script `includes` chain. Full
scanning did not decrease (49/54 rows at both sizes): retrieval was added on top
of scanning, not substituted for it.

Every one of those 16 calls threw, because the §19.15 wiring is reverted at this
commit. So the crossover was then measured directly: the patch was re-applied
and the recall class re-run at N=3 on the same corpus.

| recall class @ 252MB                        | search unwired | search wired      |
| ------------------------------------------- | -------------- | ----------------- |
| rows passing                                | 0/15           | 1/15              |
| rows calling `vana.search`                  | 12/15          | 10/15             |
| calls that resolved (`method: prefiltered`) | 0              | 10                |
| input tokens                                | 1.657M         | **0.986M (-40%)** |
| scripts                                     | 139            | **91 (-35%)**     |
| records scanned                             | 831,400        | 810,011 (-2.6%)   |
| `coverage.complete` true                    | 6              | **0**             |

**Wiring search at scale buys a 40% token reduction and 35% fewer turns, no
accuracy, and costs the completeness flag outright.** The score moved 0/15 ->
1/15, well inside the band. Records scanned barely fell, so the model still
scans — search made it reach the same scan in fewer iterations rather than
replacing it. This is a real cost effect where at 20MB there was none: §19.15
measured +41% attributable to one runaway row and a +5.4% median, i.e. nothing.

**The completeness cost is structural, not incidental.** `complete` requires
`method === "full"`, and any resolved `vana.search` sets `prefiltered`, so a run
that uses retrieval can never report complete coverage. Q10 went 3/3 complete to
0/3, Q3 2/3 to 0/3, Q15 1/3 to 0/3. For existence and exhaustiveness questions —
which is most of this class — that is a direct loss of the property rule 4
demands, traded for tokens.

**And the only recall run that passed still passed by scanning.** Q9 run 0
called no search, ran `method: full` over 112,400 records in 11 scripts, and
passed; both runs that did call search failed, one of them after scanning only
12,000 records because it trusted the ranked result. **This is the third
consecutive sweep in which the sole passing run on a recall question arrived by
exhaustion rather than retrieval** — §19.14 was the first, §19.15 the second.
Corpus size did not change that, which was the one thing it was most expected
to change.

#### Verdict

**The architecture survives scale.** At 12.5x the corpus and 13.4x the records
it answers the same questions, at 1.68x the token cost and 1.47x the wall clock,
with no new failure mode, no memory or timeout wall, coverage accounting that is
exactly correct on every row that claims it, and a strict score 4 rows down
against a ~±3 band with the losses uncorrelated with which questions actually
grew. The naive baseline over the same corpus costs 10x more tokens to see 9.2%
of the grant instead of 93.6%.

What scale did **not** fix is what §19.8 through §19.15 already identified: set
resolution, decomposition on Q3, per-period disclosure on Q10, the Q15
intentions. Those are unchanged in kind and in count. Scale was never going to
fix them, and it did not.

Caveats. The ±3 band is inherited from prior identical-grader sweeps and **was
not re-measured at this corpus size** — doing so honestly needs repeat sweeps
this run did not spend, so the -4 is reported as "at the edge of the band" and
not as an effect in either direction. Grading is strict on `dogfood-xl` and
resolution-aware on `dogfood`, so only the strict-vs-strict comparison above is
sound. Q2, Q3, Q4, Q9, Q10, Q12, Q13, Q15 and Q16 are model-graded, and a judge
is not a measurement. Growth is uneven across questions (1.00x to 12.0x) and the
two largest scopes are in no grant, so "12.5x corpus" and "6.8x working set" are
both true and neither alone describes what the agent experienced. Search usage
is counted from retained script text. The Stage 4 comparison is 15 rows, which
is small, and its token and turn reductions are the only differences there large
enough to read. No tolerance, ground truth, expected answer, rubric, fixture or
grader was changed; `stuffed-answerer.ts` and the four existing profiles were
not touched; nothing here resolves an open item in plan §6 and no index or
embedding was built. The §19.15 patch was applied for the Stage 4 run only and
reverted, verified by `git diff d3c89d3` on the seven files returning 0 bytes.
Reproduce with `./scripts/run-scale-bench.sh <outdir> dogfood-xl agent|stuffed`.

### 19.17 PS-Lite's execution path: three measurements, no decision

Plan §6 carries three open Lite items — QuickJS throughput, whether the WebView
host can guarantee `connect-src 'none'`, and what corpus Lite realistically
holds. §4.2 says of the first that how much slower Lite runs is "unmeasured and
unmeasurable from the literature" and instructs a throwaway benchmark before
committing. This section is that benchmark plus two audits. **It closes no open
item.** Two of the three results point away from what §4.1 assumed, which is
precisely why the choice belongs to a human.

Machine: Apple M4, 17.2 GB, macOS 25.5, Node v22.23.0.
`quickjs-emscripten@0.32.0` (MIT) was installed as a **root dev dependency for
the benchmark only** — neither `packages/lite` nor `packages/core` gained a
dependency, no Lite `Sandbox` was written, and `packages/lite/src` still imports
nothing from `query/`. Reproduce with
`npx tsx scripts/lite-sandbox-bench.ts --corpus <dir> --repeat 3 --probe-mem`,
where `<dir>` is a profile materialised by `generateInto` at `DEFAULT_SEED` —
the same generator `query-benchmark.ts` uses, so the corpora are the ones §19.16
measured.

#### The workload is a measured run, not a microbenchmark

§19.15 recorded that in the recall class **15 of 15 runs scanned with `readAll`
and 15 of 15 did their own in-script lexical matching**, "each run pulling 3,600
to 13,000 records into the sandbox to do it", and that Q9's single passing run
"scanned 12,600 records across `notes`, `slack` and `chatgpt.conversations` in
seven scripts". Those three scopes are Q9's whole grant, and they hold exactly
12,600 records on `dogfood` and 112,400 on `dogfood-xl` — the same 112,400
§19.16 reports for the Q9 run at scale. So the benchmark replays Q9's grant
rather than approximating it: `readAll` all three scopes, walk the ChatGPT
threads along `current_node`, match a 15-phrase list with `indexOf` on
lowercased text, sort the hits by time, return the earliest. Every arm returns
the identical answer at every size — the record count, the hit count and the
earliest hit all agree — so the arms are comparable.

| corpus       | records | grant JSON |
| ------------ | ------- | ---------- |
| `lite`       | 1,040   | 1.05 MB    |
| `dogfood`    | 12,600  | 9.80 MB    |
| `dogfood-xl` | 112,400 | 73.52 MB   |

The grant is a fraction of the corpus in each case (`dogfood-xl` is 252.2 MB
total), which matches §19.16's point that "12.5x corpus" and "6.8x working set"
are both true and neither alone describes what the agent experienced.

#### Measurement 1 — throughput (plan §6 item 3)

Four arms, N=3, medians, one child process per run so no arm inherits another's
resident memory. `native` is plain V8 and stands in for the blob-worker path,
which runs model code on the engine at full speed. `confined` is
`runConfinedScript` — the acorn-AST interpreter that `runQueryScript` actually
calls today (`packages/core/src/query/tools/runtime.ts:51`), i.e. the language
layer of the shipped Node paranoid path. `quickjs-json` crosses the data as JSON
text parsed inside the VM; `quickjs-ffi` builds it handle by handle, the FFI
marshaling §4.2 calls "precisely its worst case".

| arm            | `lite` 1,040 rec | `dogfood` 12,600 rec | `dogfood-xl` 112,400 rec |
| -------------- | ---------------- | -------------------- | ------------------------ |
| `native` (V8)  | 3 ms             | 42 ms                | 336 ms                   |
| `confined`     | 126 ms (37x)     | 879 ms (20.9x)       | 7,505 ms (22.4x)         |
| `quickjs-json` | 81 ms (23.8x)    | 393 ms (9.3x)        | 4,028 ms (12.0x)         |
| `quickjs-ffi`  | 55 ms (16.3x)    | 434 ms (10.3x)       | 4,307 ms (12.8x)         |

**QuickJS does 20 MB in 0.4 s and 252 MB in 4.0 s. It is not ruled out, and the
number that settles the item is the wrong way round from the way §4.2 posed
it:** QuickJS-WASM is **1.6x to 2.3x faster than the confined interpreter we
already ship and already accept on Node**. The paranoid path is not a thing Lite
might be too slow for; on this workload Lite's version of it would be quicker
than the Node one.

The two data-crossing strategies are within noise of each other (9.3x vs 10.3x,
12.0x vs 12.8x). **§4.2's fear that FFI marshaling of large payloads is
QuickJS's worst case is not what the measurement shows** — marshaling 112,400
records handle by handle costs 7% more than handing the VM a string, not an
order of magnitude.

`native` is 12x faster than QuickJS at scale, and that gap is the real price of
the choice, not the QuickJS number in isolation. §19.16 recorded Q9 taking 11
scripts at 252 MB. If each were a full grant pass — an upper bound, since they
are not all full passes — one question's sandbox time would be about 3.7 s
native, 44 s on QuickJS and 83 s on the confined interpreter, against the ~31 s
per row (model latency included) that §19.16 measured end to end. **At
`dogfood-xl` the engine choice would move total wall clock by more than the
model does. At `dogfood` the same arithmetic gives 0.5 s / 4.3 s / 9.7 s, which
is noise against model latency.** Corpus size decides whether this matters,
which is why item 5 below is not the small one.

#### Memory, and a silent failure worth knowing about

Host RSS does not separate the arms: it is dominated by the harness's own
`JSON.parse` of the grant before any arm runs (151 MB at `dogfood`, 542 MB at
`dogfood-xl`, within 3 MB across all four arms). QuickJS's own heap could not be
sampled either — the host is blocked while the VM runs, and by the time
`computeMemoryUsage()` is reachable the script has returned and its arrays are
collected (measured: 0.27 MB used, 346 live objects, immediately after a run
that had just held 12,600 records).

So the working set was measured the other way round: the smallest
`setMemoryLimit` under which the run still produces the **correct full-grant
answer**.

| corpus       | `quickjs-json` | `quickjs-ffi` |
| ------------ | -------------- | ------------- |
| `lite`       | ≤16 MB         | ≤16 MB        |
| `dogfood`    | 32 MB          | 16 MB         |
| `dogfood-xl` | 192 MB         | 32 MB         |

The FFI path needs 6x less heap at scale because the JSON path holds the source
text and the parsed structure simultaneously — `conversations.json` alone is
52 MB of text on `dogfood-xl`. Nothing here approaches WASM's 4 GB ceiling.

**One failure mode is worth recording because it would have been reported as a
success.** At a 16 MB limit on `dogfood-xl` the FFI arm returned
`ok: true, result: null` — the allocation failure inside the marshaling host
function raised no error, settled no promise, and left the host with no signal
that anything had gone wrong. The probe only caught it because it checks the
returned record and hit counts against the unbounded run. A Lite sandbox that
treated "no exception" as success would hand the model an empty result over a
truncated corpus, which is the silent-wrongness failure the whole coverage
contract exists to prevent. Any QuickJS host must verify the result frame, not
the absence of an error.

Two `quickjs-emscripten@0.32.0` mechanics, measured rather than read:
`setMaxStackSize` at or above **8 MB makes every `evalCode` fail** — including
`1+1` — with `SyntaxError: stack overflow`, because the requested limit exceeds
the WASM stack region; 0–4 MB work. And disposing a runtime that still owns a
handle aborts the WASM module with
`Assertion failed: list_empty(&rt->gc_obj_list)`, which takes the process with
it; resolving the script's promise through host-side globals rather than
`resolvePromise` avoids it. Neither is documented where you would look.

#### Measurement 2 — `connect-src 'none'` is not available on any host today (plan §6 item 4)

This is the item that decides blob-worker versus QuickJS, because zero egress is
the containment for prompt injection (plan §3 risk 2) and the blob-worker path
has no other. The answer from the code is **no**, and it is closer to "no" than
to "unknown".

**`packages/lite` ships no HTML and no CSP.** It is a library:
`packages/lite/package.json:14-21` exports a single `.` entry, `:27-29` publishes
only `dist`, and `:31-33` builds with `tsc` alone, so it has no document to
carry a policy. Repo-wide, `Content-Security-Policy` / `connect-src` /
`script-src` appear **only in prose in
`docs/260828-query-layer-implementation-plan.md`** (lines 615, 622, 635, 636,
702, 750) — nowhere in any package. `packages/lite/src` creates no Worker and no
blob URL. **The CSP is entirely the host's to supply, and Lite has no mechanism
to require or verify one.**

The three candidate hosts:

| host                                | hosts Lite?                     | CSP on the Lite document                          |
| ----------------------------------- | ------------------------------- | ------------------------------------------------- |
| Tauri desktop WebView               | **no** — ships the Node sidecar | `connect-src 'self' https://* http://localhost:*` |
| `apps/web` (Next.js)                | yes, in the page's own document | **none**                                          |
| `apps/mobile-shell` Flutter WebView | yes — the real "WebView host"   | **none**, and on iOS **not settable**             |

- The Tauri app is **not** the Lite host, which §4.1's framing implicitly
  assumed. `unity-surfaces/apps/desktop/src-tauri/tauri.conf.json:81-82` bundles
  the compiled Node sidecar as a resource, and
  `apps/desktop/src/pages/query-chat/use-query-chat.ts:18-19` says so outright.
  Its CSP (`tauri.conf.json:30`) permits all of `https://*` anyway — the exact
  opposite of `'none'`.
- `apps/web` boots Lite in the product document (`"use client"`,
  `apps/web/src/features/personal-server/web-ps-lite-runtime.ts:1,28`) with no
  CSP at all: `next.config.ts` has no `headers()`, and there is no
  `vercel.json` or `middleware.ts`. Even if one were added, `connect-src 'none'`
  is incompatible with an app that fetches its own API from the same document
  (`web-ps-lite-runtime.ts:44-45`), so `'none'` there needs a separate
  controller document that does not exist.
- The Flutter shell is the real WebView host —
  `apps/mobile-shell/assets/ps/index.html` loads the published Lite bundle and
  carries no `<meta http-equiv>` — and **on iOS the serving layer cannot emit a
  response header at all**: `lib/shell/origin_host.dart:19-29` records that
  `flutter_inappwebview`'s iOS handler replies with a plain `URLResponse`, not
  an `HTTPURLResponse`, so status and headers are "not settable"; the
  `InAppLocalhostServer` actually in use
  (`third_party/.../in_app_localhost_server.dart:108-119`) sets only
  `contentType`. Android could set headers and sets only `Cache-Control`
  (`origin_host.dart:163`).

**Not determinable from these repos:** whether a blob-URL worker inherits the
creator's CSP in the engines that matter. §4.1 calls this "verified behaviour"
(plan lines 612, 618-622) but **no test or code in either repo exercises it** —
repo-wide, `new Worker(` and `createObjectURL` for this purpose appear only in
that prose. Whether a `<meta http-equiv>`-delivered CSP (the only channel iOS
leaves open) governs blob-worker inheritance identically to a header is also not
determinable here, and it is the kind of claim a wrong "yes" turns into an
exfiltration path. It needs its own measurement on the actual WebViews.

Also relevant to §4.1's "fetch the bytes before locking CSP down" note: the
installed variant is **not** single-file. `@jitl/quickjs-wasmfile-release-sync`
ships `emscripten-module.wasm` as a separate **503,134-byte** file, so its load
is a real fetch that a strict policy would have to allow or pre-empt.

#### Measurement 3 — what Lite realistically holds (plan §6 item 5)

This one bounds the other two: if a realistic Lite corpus is 20 MB rather than
252 MB, a 12x-slower engine is a rounding error against model latency. **The
item is partly mis-framed, and the shipping host answers it more sharply than
the item expects.**

**On the mobile host, the storage is not OPFS.** `apps/mobile-shell` sets
`storageMode: options.storageMode ?? "indexeddb"` on the product path, with the
reason inline (`ps_bundle/src/harness.js:2441-2444`): "WKWebView can advertise
OPFS while failing its first real write. The product path therefore uses
PS-Lite's IndexedDB file-store adapter." That is a live hazard in Lite's own
code, not a hypothetical: `isOpfsAvailable()`
(`packages/lite/src/storage.ts:223-228`) only tests
`typeof navigator.storage?.getDirectory === "function"` and never probes a
write, while the OPFS store writes through `createWritable()`
(`storage.ts:271,330`). The harness comment at `harness.js:331-344` spells out
the consequence: "PS-Lite selects OPFS and then fails on every envelope write."
**Whether `createWritable` works on the target WebViews is not recorded in
either repo**; the `"indexeddb"` default is circumstantial evidence that it does
not.

**The real host enforces ceilings, and they are the best available answer to
this item.** On `apps/mobile-shell`:
`ps_vault_snapshot_store.dart:14` caps the native vault snapshot at
`128 * 1024 * 1024` — **128 MiB**, enforced on both read and write with "PS
snapshot exceeds the native persistence limit"; `native_ps_store.dart:11` caps a
single KV record at **1 MiB**, enforced in SQL as a `CHECK` constraint; and
`ps_host.dart:352-360` caps a file chunk at **128 KiB** decoded. Nothing
comparable exists on `apps/web`, which requests no persistence and sets no
quota. **So the one shipping host that bounds Lite bounds it at 128 MiB, which
puts `dogfood-xl` (252.2 MB) out of reach there and makes `dogfood` (20.2 MB)
the realistic operating point** — with the caveat that no recorded run has ever
approached that cap, and what happens to a user who exceeds it is a `StateError`
swallowed into a log line (`ps_service.dart:740-742`).

**Lite never asks the browser how much room it has, or for permission to keep
it.** `navigator.storage.persist()`, `.persisted()` and `.estimate()` are called
**nowhere** in `packages/lite` or `packages/core`. A grep trap worth naming:
`packages/lite/src/storage.ts:464` defines a local `async function persist()`
that snapshots runtime state — it is not the browser persistence API. So plan
§4.3's requirement ("IndexedDB is evictable; OPFS needs
`navigator.storage.persist()` … check persistence and report it in `coverage`",
plan lines 662-664) **is not implemented**, and Lite cannot currently report
whether its own storage is evictable. The only `persist()` call in either repo
is the mobile harness's, opt-in and **off by default**, with a recorded reason
(`harness.js:476-486`): the first device run that made the call "also saw every
subsequent OPFS read fail with WebKit's generic `UnknownError`, which wedged
sync permanently."

**A scaling property that matters more than quota.** On the IndexedDB fallback
path, `storage.ts:462-481` serialises the entire index — and every envelope —
into **one IndexedDB record**, rewritten on every write
(`storage.ts:526,766,794,809,832,848,879,917`). Write cost is therefore linear
in total corpus size on the very path the mobile product defaults to. No test or
comment measures this.

**The `lite` fixture is 3.2 MB and is not a claim about capacity.** Generated
fresh at `DEFAULT_SEED`: 18 files, 16 scopes, 3.2 MB, of which Q9's grant is
1.05 MB / 1,040 records. `profiles.ts:11-12` calls it "the PS-Lite profile (plan
§4.2): smaller again, and generated entirely in memory because the browser
runtime has no filesystem", states no byte size, and ties the counts to no
storage ceiling; it is used only as a fast unit-test fixture
(`generate.test.ts:30,40,107`, `dogfood.test.ts:55`,
`query-eval-harness.test.ts:58`). **No Lite eval profile in the phase-1 sense
exists** — which is exactly what plan §6 names as this item's resolver ("Phase
1, Lite profile"). The largest payload any test writes through a Lite storage
port is **10 KB**, and no test runs against real OPFS or real IndexedDB.

**The bounded-read machinery exists but is not the path the model takes.**
`storage/blocks` builds at a 48 KB target and a 256 KB hard cap
(`packages/core/src/storage/blocks/build.ts:43-44`), and a bounded read returns
at most 50 block ids (`select.ts:18`) under a caller-supplied `maxBytes`. That
is `vana.read`. But §19.15 measured 15 of 15 recall runs using `readAll` /
`stream`, which pass a whole scope and are bounded by nothing — which is why
Measurement 1's numbers are whole-grant numbers. Worse, the bound is on the
response, not the work: with no manifest sidecar, `storage.ts:543-552` reads the
whole envelope and rebuilds every block before paging. **Plan §4.3's "do not
parse a 53MB scope in one go" is advice to an implementation that does not yet
constrain the model's choice**, and the 53 MB figure itself appears exactly once
in the repo, derived from no constant, fixture or measurement.

**Not determinable from these repos:** what quota any real device grants (
`navigator.storage.estimate()` is called only in the mobile measurement harness,
and **no recorded output of it exists anywhere**); whether persistence would be
granted; whether eviction has ever occurred; whether OPFS `createWritable` works
on the target WebViews; and any OPFS throughput number at all — plan lines
703-705 said none were found and none have been added since. The largest OPFS
I/O any code exercises is the harness's ~960 KB torture default, with no timing
recorded.

#### The trade-off, as it stands for a human

There are three shapes, not two, because the confined interpreter is already
browser-safe and already denies egress by name — `fetch`, `XMLHttpRequest`,
`Worker`, `importScripts`, `WebAssembly`, `eval`, `Function` and `globalThis`
are all in `FORBIDDEN_IDENTIFIERS`
(`packages/core/src/query/tools/interpreter/realm.ts:38-56`), and the
`constructor` / `__proto__` bridge is closed at every member access.

| path                            | speed vs V8 | egress containment rests on                                                              | needs CSP? |
| ------------------------------- | ----------- | ---------------------------------------------------------------------------------------- | ---------- |
| Blob worker, model code native  | 1x          | CSP alone. Model code holds the worker global.                                           | **yes**    |
| Blob/plain worker + interpreter | 21–22x      | Enumeration in a hand-written AST walker. Already shipped, already hostile-suite tested. | no         |
| QuickJS-WASM                    | 9–13x       | Structure: a separate heap with no host bindings except those injected.                  | no         |

**Measurement 3 moves the operating point, and that changes how much
Measurement 1's gap matters.** If the shipping mobile host caps the vault at
128 MiB, `dogfood-xl` is not a Lite corpus and the relevant column is `dogfood`:
per script, 42 ms native against 393 ms on QuickJS. Over §19.16's 11-script Q9
that is roughly 0.5 s versus 4.3 s per question, against ~31 s per row of
measured end-to-end time. **At that size the engine choice is a few percent of
wall clock; at `dogfood-xl` it would be most of it.** Anyone weighing this
should decide which corpus Lite is being built for before deciding which engine
it needs, and note that the 128 MiB figure is a cap nothing has been measured
against, not an observed corpus.

What each buys and costs:

- **Blob worker** is the only path that keeps Lite within an order of magnitude
  of PS full, and it is 12x faster than QuickJS at scale. It is also the only
  path whose safety depends on something **no host in either repo currently
  provides**, one of which (iOS) cannot provide it through the documented API.
  Choosing it means committing to build the strict controller document first and
  to verify blob-worker CSP inheritance on each WebView — and accepting that if
  the guarantee ever lapses, model code authored from a malicious email has an
  open network.
- **QuickJS** costs 12x against native and needs 192 MB of heap at
  `dogfood-xl`, 32 MB at `dogfood`. It buys containment that does not depend on
  the host at all, and it is the only option that restores §19.7's two layers on
  a runtime where §4's table marks the OS layer "❌ impossible". It is also,
  measured here, faster than the interpreter the Node path already runs.
- **The confined interpreter alone** needs no new dependency and no CSP, and it
  is the same code already under test. It is the slowest of the three and, on
  Lite, it would be the **only** layer — on Node it is explicitly backed by the
  OS sandbox because §19.7 says neither layer suffices alone. A defect in a
  hand-written AST walker is an escape with nothing behind it.

A fourth thing is true regardless of which is chosen: **Lite's storage layer is
not ready for any of them.** It cannot say whether its own data is evictable, it
picks OPFS on a feature-detect that the mobile host already routes around, and
its IndexedDB fallback rewrites the whole corpus on every write. Those are
independent of the sandbox decision and none of them is a query-layer change.

**What would still need to be true.** For the blob worker: a controller document
that can be given `connect-src 'none'` on every host that ships Lite (today:
none), plus a measured demonstration of blob-worker CSP inheritance on that
host's engine, plus explicit deletion of `RTCPeerConnection`, which
`connect-src` does not cover (§4.1). For QuickJS: a host that verifies the
result frame rather than the absence of an error, given the `ok: true,
result: null` failure above; a stack limit under 4 MB; and acceptance of a
pre-1.0 dependency in the browser bundle. For either: Lite still has no
`Sandbox` implementation and `packages/lite/src` still imports no `query/*`, so
whichever is chosen is greenfield.

#### Caveats

One machine, one OS, one architecture (M4 / macOS / arm64) and one engine
version; a browser's WASM and a WebView's WASM are not this Node build's WASM,
and the `native` arm is Node's V8, not a WebView's. **No measurement here was
taken in a browser at all** — this is a throughput and memory characterisation
of the engines, not of the runtime they would ship in, and OPFS read cost is not
in any number above. The workload is one question's grant replayed; Q9 is
representative of the recall class by §19.15's counts, and is not representative
of the aggregation class, which touches far fewer records. Timings are medians
of three, and the arms differ by factors large enough that the spread (under 12%
within any arm) does not change the ordering. `--probe-mem` walks a coarse
ladder, so the memory figures are upper bounds within one ladder step, not
minima. No fixture, grader, expectation or query-layer module was modified; the
four profiles were generated fresh and byte-checked against §19.16's sizes
(`dogfood` 20.2 MB, `dogfood-xl` 252.2 MB). **Nothing here resolves plan §6
items 3, 4 or 5** — the throughput number the plan asked for exists now, the CSP
answer is "no host provides it today", and the corpus number is bounded above
rather than known. The choice between the three paths remains a human's.

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
