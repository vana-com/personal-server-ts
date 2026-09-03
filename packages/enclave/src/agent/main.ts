/**
 * Node agent entrypoint. ENCLAVE_AGENT_SECRET is required;
 * ENCLAVE_AGENT_HOST defaults to 127.0.0.1, ENCLAVE_AGENT_PORT to 8787;
 * DSTACK_FAKE=1 selects the fake and DSTACK_FAKE_APP_ID names its app.
 */

import { agentConfigFromEnv } from "./bootstrap.js";
import { createAgentServer } from "./http.js";

const EXIT_FAILURE = 1;
const SIGTERM = "SIGTERM";

try {
  const { client, host, port, secret } = agentConfigFromEnv(process.env);
  const server = createAgentServer({ client, secret });

  server.listen(port, host);
  process.once(SIGTERM, () => server.close());
} catch (error) {
  console.error(
    error instanceof Error ? error.message : "enclave agent failed to start",
  );
  process.exitCode = EXIT_FAILURE;
}
