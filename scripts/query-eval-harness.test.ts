import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  generateInto,
  type CorpusManifest,
} from "../packages/core/src/query/evals/index.js";
import { createFakeInferenceProvider } from "../packages/core/src/derivatives/inference.js";

import { FsFixtureSink } from "./query-eval-fs-sink.js";
import { buildAgentAnswerer } from "./query-eval-harness.js";

/**
 * The harness must hand the tool host the CASE's grant, not the corpus.
 *
 * It used to pass every manifest scope on every question, so `grantedScopes`
 * was all 18 whatever the case declared. That is not a cosmetic difference:
 * the model was handed the whole corpus to answer a two-scope question,
 * `coverage.complete`'s "every granted scope accounted for" conjunct could
 * never fire because no question needs all 18, and every scope-binding
 * assertion downstream was grading against a grant nobody had asked for.
 *
 * These run the real nested path — the confined interpreter inside the OS
 * sandbox — because the binding is enforced in two places (`api.ts`'s
 * `requireGranted` and the OS `readPaths`) and only an end-to-end run
 * exercises both. They need `dist/query/runner.js`, so `npm run build` must
 * have run; that is the same precondition every other query suite carries.
 */

/** Emits one script, then answers with whatever the host sent back. */
function scriptOnce(script: string) {
  return createFakeInferenceProvider({
    respond: (input, n) => {
      if (n === 0) return { content: "```vana:run\n" + script + "\n```" };
      // Echo the host's rendered run output as the answer, so an assertion can
      // read what the sandbox actually said about the denied scope.
      const last = input.messages[input.messages.length - 1]?.content ?? "";
      return {
        content:
          "```vana:answer\n" +
          JSON.stringify({ answer: last, citations: [] }) +
          "\n```",
      };
    },
  });
}

describe("the eval harness narrows the tool host to the case's grant", () => {
  let dir: string;
  let manifest: CorpusManifest;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "harness-grant-"));
    const sink = new FsFixtureSink(dir);
    await sink.init();
    ({ manifest } = await generateInto(sink, { profile: "lite" }));
  }, 120_000);

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("shows the script only the scopes the case granted", async () => {
    // The manifest carries many scopes; this request grants one.
    expect(manifest.scopes.length).toBeGreaterThan(1);

    const answerer = await buildAgentAnswerer(
      dir,
      manifest,
      scriptOnce(
        `const list = await vana.scopes();
const names = [];
for (const s of list) { names.push(s.scope); }
vana.result({ answer: "visible:" + names.sort().join(","), citations: [] });`,
      ),
    );

    const answer = await answerer.answer({
      question: "which scopes can you see?",
      grantedScopes: ["oura.sleep"],
    });
    expect(answer.answer).toContain("visible:oura.sleep");
    expect(answer.answer).not.toContain("bank.transactions");
  }, 120_000);

  it("refuses a read of a scope the case did not grant", async () => {
    const answerer = await buildAgentAnswerer(
      dir,
      manifest,
      scriptOnce(
        `const rows = await vana.readAll("bank.transactions");
vana.result({ answer: "read " + rows.length + " rows", citations: [] });`,
      ),
    );

    const answer = await answerer.answer({
      question: "how much did I spend?",
      grantedScopes: ["oura.sleep"],
    });

    // The read must not have happened, and the denial must be legible rather
    // than an empty result the script could read as "there is nothing there".
    expect(answer.answer).not.toMatch(/read \d+ rows/);
    expect(answer.answer).toContain("bank.transactions");
    expect(answer.answer).toContain("not in this grant");
    expect(answer.coverage.scopesScanned).not.toContain("bank.transactions");
  }, 120_000);

  it("grants nothing when the case declares no scopes (Q12)", async () => {
    const answerer = await buildAgentAnswerer(
      dir,
      manifest,
      scriptOnce(
        `const list = await vana.scopes();
vana.result({ answer: "visible-count:" + list.length, citations: [] });`,
      ),
    );

    const answer = await answerer.answer({
      question: "what has this server told the builder about me?",
      grantedScopes: [],
    });

    expect(answer.answer).toContain("visible-count:0");
  }, 120_000);
});
