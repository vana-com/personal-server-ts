/**
 * Node agent entrypoint. ENCLAVE_AGENT_SECRET is required;
 * ENCLAVE_AGENT_HOST defaults to 127.0.0.1, ENCLAVE_AGENT_PORT to 8787;
 * DSTACK_FAKE=1 selects the fake and DSTACK_FAKE_APP_ID names its app.
 */

import { createFakeDstackClient } from "../dstack/fake.js";
import { createRealDstackClient } from "../dstack/real.js";
import { createAgentServer } from "./http.js";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 8787;
const DEFAULT_FAKE_APP_ID = "0000000000000000000000000000000000000001";
const FAKE_DSTACK_ENABLED = "1";
const EXIT_FAILURE = 1;
const SIGTERM = "SIGTERM";

const secret = process.env.ENCLAVE_AGENT_SECRET;
if (!secret) {
  console.error("ENCLAVE_AGENT_SECRET is required");
  process.exitCode = EXIT_FAILURE;
} else {
  const host = process.env.ENCLAVE_AGENT_HOST ?? DEFAULT_HOST;
  const port = readPort(process.env.ENCLAVE_AGENT_PORT);
  const client =
    process.env.DSTACK_FAKE === FAKE_DSTACK_ENABLED
      ? createFakeDstackClient({
          appId: process.env.DSTACK_FAKE_APP_ID ?? DEFAULT_FAKE_APP_ID,
        })
      : createRealDstackClient();
  const server = createAgentServer({ client, secret });

  server.listen(port, host);
  process.once(SIGTERM, () => server.close());
}

function readPort(value: string | undefined): number {
  if (value === undefined) {
    return DEFAULT_PORT;
  }

  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("ENCLAVE_AGENT_PORT must be an integer from 1 to 65535");
  }

  return port;
}
