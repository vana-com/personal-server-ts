import { gzipSync } from "node:zlib";
import { createServer, type ServerResponse } from "node:http";
import { afterEach, expect, it } from "vitest";
import {
  AdditionsBudget,
  readBoundedResponse,
  readBoundedJson,
} from "./budget.js";

const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of cleanup.splice(0)) await close();
});
async function transport(handler: (response: ServerResponse) => void) {
  const server = createServer((_request, response) => handler(response));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanup.push(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  );
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Missing local port");
  return `http://127.0.0.1:${address.port}`;
}

it.each(["oversized", "missing", "lying"])(
  "cancels %s encrypted HTTP bodies within the byte budget",
  async (mode) => {
    const url = await transport((response) => {
      if (mode === "lying") {
        const zipped = gzipSync(new Uint8Array(1024));
        response.setHeader("content-encoding", "gzip");
        response.setHeader("content-length", String(zipped.byteLength));
        response.end(zipped);
        return;
      }
      if (mode === "oversized") response.setHeader("content-length", "1000000");
      response.write(new Uint8Array(64));
      if (mode === "missing") response.end(new Uint8Array(64));
      else response.end();
    });
    const budget = new AdditionsBudget(32, 1000);
    const response = await fetch(url, { signal: budget.signal });
    await expect(readBoundedResponse(response, budget)).rejects.toThrow(
      /budget/,
    );
    expect(budget.remaining).toBeGreaterThanOrEqual(0);
  },
);

it("aborts a stalled actual HTTP stream and observes transport cancellation", async () => {
  let disconnected!: () => void;
  const closed = new Promise<void>((resolve) => {
    disconnected = resolve;
  });
  const url = await transport((response) => {
    response.write("x");
    response.on("close", disconnected);
  });
  const budget = new AdditionsBudget(1024, 100);
  const response = await fetch(url, { signal: budget.signal });
  await expect(readBoundedResponse(response, budget)).rejects.toThrow();
  await closed;
  expect(budget.signal?.aborted).toBe(true);
});

it("charges JSON decoding and aggregate responses to one recovery budget", async () => {
  const url = await transport((response) =>
    response.end('{"value":"abcdefgh"}'),
  );
  const budget = new AdditionsBudget(150, 1000);
  expect(await readBoundedJson(await fetch(url), budget)).toEqual({
    value: "abcdefgh",
  });
  await expect(readBoundedJson(await fetch(url), budget)).rejects.toThrow(
    /budget/,
  );
});

it("retains exhaustion after a failed charge", () => {
  const budget = new AdditionsBudget(10);
  expect(() => budget.charge(11)).toThrow();
  expect(() => budget.charge()).toThrow();
});
