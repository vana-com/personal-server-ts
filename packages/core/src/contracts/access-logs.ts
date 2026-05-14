import type { AccessLogReader } from "../logging/access-reader.js";
import {
  contractOk,
  normalizeIntegerParam,
  type ContractResult,
} from "./http.js";

export async function listAccessLogsContract(input: {
  accessLogReader: AccessLogReader;
  limit?: string | null;
  offset?: string | null;
}): Promise<ContractResult> {
  const limit = normalizeIntegerParam(input.limit, 50);
  const offset = normalizeIntegerParam(input.offset, 0);
  return contractOk(await input.accessLogReader.read({ limit, offset }));
}
