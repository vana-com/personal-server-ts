/**
 * Manual smoke test of the E2EE v2 path against a real gateway: one
 * encrypted chat completion. Prints only the receipt id and the answer
 * length (never the answer).
 *
 *   INFERENCE_BASE_URL=https://inference.phala.com/v1 \
 *   INFERENCE_MODEL=z-ai/glm-5.2 INFERENCE_API_KEY=... npm run e2ee:smoke
 */

import {
  createOpenAiCompatibleInferenceProvider,
  createPhalaE2eeEncryption,
  DEFAULT_INFERENCE_BASE_URL,
  DEFAULT_INFERENCE_MODEL,
} from "@opendatalabs/personal-server-ts-core/derivatives";

async function main(): Promise<void> {
  const baseUrl = process.env.INFERENCE_BASE_URL ?? DEFAULT_INFERENCE_BASE_URL;
  const model = process.env.INFERENCE_MODEL ?? DEFAULT_INFERENCE_MODEL;
  const encryption = createPhalaE2eeEncryption({
    baseUrl,
    logger: {
      info: (payload, message) => console.log(message, payload),
      warn: (payload, message) => console.warn(message, payload),
    },
  });
  const provider = createOpenAiCompatibleInferenceProvider({
    baseUrl,
    model,
    apiKey: process.env.INFERENCE_API_KEY,
    encryption,
  });
  const started = Date.now();
  const result = await provider.chat({
    model,
    messages: [
      { role: "system", content: "Reply with one short sentence." },
      { role: "user", content: "Say hello to the Vana Personal Server." },
    ],
    maxTokens: 64,
  });
  console.log({
    baseUrl,
    model,
    keyId: encryption.currentKey()?.keyId ?? null,
    keysetDigest: encryption.currentKey()?.keysetDigest ?? null,
    receiptId: result.receiptId ?? null,
    aciIdentity: result.aciIdentity ?? null,
    answerLength: result.content.length,
    usage: result.usage ?? null,
    elapsedMs: Date.now() - started,
  });
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? `${err.name}: ${err.message}` : err);
  process.exit(1);
});
