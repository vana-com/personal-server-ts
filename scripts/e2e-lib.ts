const VERCEL_PROTECTION_BYPASS = process.env.VERCEL_PROTECTION_BYPASS;
const REDACTED = "<redacted>";
const PRIVATE_KEYS = new Set(["authorization", "secret", "nodesecret"]);
type RequestPrivacy = "standard" | "secrets";

interface RequestDetails {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
}

interface ResponseDetails {
  status: number | string;
  body: unknown;
}

export class StepFailure extends Error {
  constructor(
    message: string,
    readonly request: RequestDetails,
    readonly response: ResponseDetails,
  ) {
    super(message);
  }
}

export interface HttpResult {
  request: RequestDetails;
  response: ResponseDetails & { status: number };
}

type StepState = "pass" | "fail" | "skip";

const stepStates = new Map<string, StepState>();
let failureCount = 0;

export function format(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export function printFailure(error: unknown): void {
  if (error instanceof StepFailure) {
    console.log(`  request: ${error.request.method} ${error.request.url}`);
    if (error.request.headers) {
      console.log(`  request headers: ${format(error.request.headers)}`);
    }
    if (error.request.body !== undefined) {
      console.log(`  request body: ${format(error.request.body)}`);
    }
    console.log(`  status: ${error.response.status}`);
    console.log(`  body: ${format(error.response.body)}`);
    console.log(`  diagnosis: ${error.message}`);
    return;
  }

  console.log("  request: local setup");
  console.log("  status: LOCAL_ERROR");
  console.log(
    `  body: ${error instanceof Error ? error.message : format(error)}`,
  );
}

export async function runStep(
  id: string,
  name: string,
  dependencies: string[],
  action: () => Promise<string | void>,
): Promise<void> {
  if (
    dependencies.some((dependency) => stepStates.get(dependency) !== "pass")
  ) {
    stepStates.set(id, "skip");
    console.log(`SKIP  ${id}. ${name}  dependency failed`);
    return;
  }

  const startedAt = performance.now();
  try {
    const detail = await action();
    stepStates.set(id, "pass");
    console.log(
      `PASS  ${id}. ${name}  ${Math.round(performance.now() - startedAt)}ms${detail ? `  ${detail}` : ""}`,
    );
  } catch (error) {
    stepStates.set(id, "fail");
    failureCount += 1;
    console.log(
      `FAIL  ${id}. ${name}  ${Math.round(performance.now() - startedAt)}ms`,
    );
    printFailure(error);
  }
}

export async function requestJson(
  method: string,
  url: string,
  body?: unknown,
  headers?: Record<string, string>,
  privacy: RequestPrivacy = "standard",
): Promise<HttpResult> {
  const request: RequestDetails = {
    method,
    url,
    ...(headers
      ? { headers: privacy === "secrets" ? redactRecord(headers) : headers }
      : {}),
    ...(body === undefined
      ? {}
      : { body: privacy === "secrets" ? redactValue(body) : body }),
  };

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(VERCEL_PROTECTION_BYPASS
          ? { "x-vercel-protection-bypass": VERCEL_PROTECTION_BYPASS }
          : {}),
        ...headers,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch (error) {
    const cause =
      error instanceof Error && error.cause instanceof Error
        ? `: ${error.cause.message}`
        : "";
    throw new StepFailure(`Gateway connection failed${cause}`, request, {
      status: "CONNECTION_ERROR",
      body: error instanceof Error ? error.message : String(error),
    });
  }

  const text = await response.text();
  let responseBody: unknown = text;
  if (text.length > 0) {
    try {
      responseBody = JSON.parse(text) as unknown;
    } catch {
      // Keep non-JSON response text for the diagnostic.
    }
  }

  return {
    request,
    response: { status: response.status, body: responseBody },
  };
}

function redactRecord(value: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      PRIVATE_KEYS.has(key.toLowerCase()) ? REDACTED : String(item),
    ]),
  );
}

function redactValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redactValue);
  }
  const object = record(value);
  if (!object) return value;

  return Object.fromEntries(
    Object.entries(object).map(([key, item]) => [
      key,
      PRIVATE_KEYS.has(key.toLowerCase()) ? REDACTED : redactValue(item),
    ]),
  );
}

export function requireResponse(
  result: HttpResult,
  status: number | readonly number[],
  validate: (body: unknown) => boolean,
  diagnosis: string,
): unknown {
  const statuses = Array.isArray(status) ? status : [status];
  if (
    !statuses.includes(result.response.status) ||
    !validate(result.response.body)
  ) {
    throw new StepFailure(diagnosis, result.request, result.response);
  }
  return result.response.body;
}

export function record(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

export function hasStepFailures(): boolean {
  return failureCount > 0;
}

export function printSummary(): void {
  const results = [...stepStates].map(([id, state]) => `${id}=${state}`);
  console.log(`RESULT  ${results.join(" | ")}`);
}
