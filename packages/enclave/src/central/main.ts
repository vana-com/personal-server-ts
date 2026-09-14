import { createRealDstackClient } from "../dstack/real.js";
import { startFleetCentral } from "./bootstrap.js";

void startFleetCentral(process.env, createRealDstackClient())
  .then((runtime) => {
    process.once("SIGTERM", () => {
      void runtime.close().catch(() => {
        process.exitCode = 1;
      });
    });
  })
  .catch((error) => {
    console.error({
      level: "error",
      message:
        error instanceof Error ? error.message : "Central startup failed",
    });
    process.exitCode = 1;
  });
