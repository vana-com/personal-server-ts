import { ServerConfigSchema } from "../schemas/server-config.js";
import {
  contractOk,
  contractProtocolError,
  type ContractResult,
} from "./http.js";

export function validateServerConfigContract(body: unknown): ContractResult {
  const result = ServerConfigSchema.safeParse(body);
  if (!result.success) {
    return {
      ok: false,
      status: 400,
      body: {
        error: {
          code: 400,
          errorCode: "VALIDATION_ERROR",
          message: "Invalid config",
          issues: result.error.issues,
        },
      },
    };
  }
  return contractOk({ status: "saved", config: result.data });
}

export function configReadErrorContract(
  kind: "not-found" | "read",
): ContractResult {
  if (kind === "not-found") {
    return contractProtocolError(404, "NOT_FOUND", "Config file not found");
  }
  return contractProtocolError(500, "READ_ERROR", "Failed to read config");
}

export function configWriteErrorContract(): ContractResult {
  return contractProtocolError(500, "WRITE_ERROR", "Failed to write config");
}
