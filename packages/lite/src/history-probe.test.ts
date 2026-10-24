import type {
  OriginalHistoryProbeInput,
  OriginalHistoryProbeMessage,
} from "./history-probe.worker.js";
import { createServer } from "node:http";
import { Worker } from "node:worker_threads";
import { build } from "esbuild";
import { expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { keccak256, stringToHex } from "viem";
import {
  createDataFileEnvelope,
  deriveMasterKey,
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";

it("checks retained originals through the real read-only worker without exposing decrypted data", async () => {
  const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
  const signature = await owner.signMessage({ message: "vana-master-key-v1" });
  const master = deriveMasterKey(signature);
  const candidates = [];
  const bodies = new Map<string, Uint8Array>();
  for (const [scope, kind] of [
    ["github.profile", "match"],
    ["github.repositories", "content"],
    ["github.starred", "metadata"],
  ] as const) {
    const envelope = createDataFileEnvelope(scope, "2026-06-17T01:00:00.000Z", {
      privateValue: "PRIVATE_RECOVERY_SENTINEL",
    });
    const plain = new TextEncoder().encode(JSON.stringify(envelope));
    const encrypted = await encryptWithPassword(
      plain,
      Buffer.from(deriveScopeKey(master, scope)).toString("hex"),
    );
    bodies.set(scope, encrypted);
    candidates.push({
      scope,
      expectedVersion: "1",
      dataHash: kind === "content" ? `0x${"00".repeat(32)}` : keccak256(plain),
      metadataHash:
        kind === "metadata"
          ? `0x${"00".repeat(32)}`
          : keccak256(
              stringToHex(
                JSON.stringify({
                  scope,
                  collectedAt: envelope.collectedAt,
                  sizeBytes: encrypted.length,
                }),
              ),
            ),
    });
  }
  const methods: string[] = [];
  let authSeen = false;
  const server = createServer((req, res) => {
    methods.push(req.method!);
    authSeen ||= Boolean(req.headers.authorization);
    const scope = req.url!.split("/").at(-2)!;
    const data = bodies.get(scope);
    res.writeHead(data ? 200 : 404);
    res.end(data ? Buffer.from(data) : undefined);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("No local listener");
  let worker: Worker | undefined;
  try {
    const bundled = await build({
      entryPoints: [
        new URL("./history-probe.worker.ts", import.meta.url).pathname,
      ],
      bundle: true,
      platform: "browser",
      format: "cjs",
      write: false,
      logLevel: "silent",
    });
    async function invoke(input: OriginalHistoryProbeInput) {
      worker = new Worker(
        `const {parentPort}=require('node:worker_threads');globalThis.postMessage=m=>parentPort.postMessage(m);parentPort.on('message',data=>globalThis.onmessage({data}));${bundled.outputFiles[0].text}`,
        { eval: true },
      );
      return new Promise<OriginalHistoryProbeMessage[]>((resolve, reject) => {
        const all: OriginalHistoryProbeMessage[] = [];
        const timer = setTimeout(
          () => reject(new Error("Probe did not finish")),
          15000,
        );
        worker!.on("error", reject);
        worker!.on("message", (event: OriginalHistoryProbeMessage) => {
          if (event.kind !== "complete") all.push(event);
          if (event.kind === "complete" || event.kind === "refused") {
            clearTimeout(timer);
            resolve(all);
          }
        });
        worker!.postMessage(input);
      });
    }
    const input: OriginalHistoryProbeInput = {
      ownerAddress: owner.address,
      ownerSignature: signature,
      storageEndpoint: `http://127.0.0.1:${address.port}`,
      candidates,
    };
    const events = await invoke(input);
    expect(events).toHaveLength(6);
    expect(
      events
        .filter((event) => event.kind === "candidate")
        .map((event) => event.code),
    ).toEqual([
      "exact_commitment_match",
      "exact_commitment_match",
      "data_hash_mismatch",
      "data_hash_mismatch",
      "metadata_hash_mismatch",
      "metadata_hash_mismatch",
    ]);
    expect(JSON.stringify(events)).not.toContain("PRIVATE_RECOVERY_SENTINEL");
    expect(JSON.stringify(events)).not.toContain(signature);
    expect(methods).toEqual(Array(6).fill("GET"));
    expect(authSeen).toBe(false);
    await worker?.terminate();
    const otherOwner = privateKeyToAccount(`0x${"13".repeat(32)}`);
    expect(
      await invoke({ ...input, ownerAddress: otherOwner.address }),
    ).toEqual([{ kind: "refused", code: "invalid_input_or_owner" }]);
    await worker?.terminate();
    expect(
      await invoke({ ...input, storageEndpoint: "https://storage.vana.org" }),
    ).toEqual([{ kind: "refused", code: "invalid_input_or_owner" }]);
    expect(methods).toHaveLength(6);
  } finally {
    await worker?.terminate();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}, 20000);
