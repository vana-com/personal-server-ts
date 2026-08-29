/**
 * Which sampler-control parameters does Gemini's OpenAI-compat layer accept?
 *
 * Answers are not obvious from the docs, and a naive check gets them wrong:
 * Gemini returns errors as a JSON *array* `[{error:{...}}]`, so a test like
 * `if ('error' in body)` on the parsed value checks list membership and
 * reports a hard 400 as success.
 *
 *   npx tsx --env-file=.env scripts/probe-params.ts
 */
const KEY = process.env.INFERENCE_API_KEY;
if (!KEY) throw new Error("INFERENCE_API_KEY required");
const URL_ =
  "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";

/** Handles both the object and array error shapes. */
function readError(parsed: unknown): string | undefined {
  const one = Array.isArray(parsed) ? parsed[0] : parsed;
  if (one && typeof one === "object" && "error" in one) {
    const e = (one as { error: { message?: string } }).error;
    return e.message ?? JSON.stringify(e);
  }
  return undefined;
}

async function probe(label: string, extra: Record<string, unknown>) {
  const r = await fetch(URL_, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "gemini-3.7-flash",
      messages: [{ role: "user", content: "Reply with exactly: OK" }],
      max_tokens: 2048,
      ...extra,
    }),
  });
  const err = readError(await r.json());
  console.log(
    `  ${label.padEnd(28)} HTTP ${r.status}  ${err ? "REJECTED: " + err.slice(0, 80) : "accepted"}`,
  );
}

const main = async () => {
  console.log("Gemini OpenAI-compat parameter support:");
  await probe("temperature:0", { temperature: 0 });
  await probe("seed:42", { seed: 42 });
  await probe("temperature:0 + seed:42", { temperature: 0, seed: 42 });
  await probe("top_p:1", { top_p: 1 });
  await probe("provider:{...} (Phala)", {
    provider: { aci_verified: true, zdr: true },
  });
};
void main();
