export type ContractResult<TBody = unknown> =
  | { ok: true; status: number; body: TBody }
  | { ok: false; status: number; body: unknown };

export function contractOk<TBody>(
  body: TBody,
  status = 200,
): ContractResult<TBody> {
  return { ok: true, status, body };
}

export function contractError(
  status: number,
  error: string,
  message: string,
): ContractResult {
  return {
    ok: false,
    status,
    body: { error, message },
  };
}

export function contractProtocolError(
  status: number,
  errorCode: string,
  message: string,
): ContractResult {
  return {
    ok: false,
    status,
    body: {
      error: {
        code: status,
        errorCode,
        message,
      },
    },
  };
}

export function normalizeIntegerParam(
  value: string | null | undefined,
  fallback: number,
): number {
  if (value === null || value === undefined) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

export async function parseJsonObjectBody(
  request: Request,
  invalidJsonMessage = "Invalid JSON body",
): Promise<
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; result: ContractResult }
> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return {
      ok: false,
      result: contractError(400, "INVALID_BODY", invalidJsonMessage),
    };
  }

  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return {
      ok: false,
      result: contractError(
        400,
        "INVALID_BODY",
        "Request body must be a JSON object",
      ),
    };
  }

  return { ok: true, body: body as Record<string, unknown> };
}
