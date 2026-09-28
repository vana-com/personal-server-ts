/** Register the existing account-1 handle the way Desktop does at startup. */
export function legacyTestConnectionId(
  owner: string,
  sourceId: string,
): string {
  const connector = sourceId.split("/").filter(Boolean).at(-1) ?? sourceId;
  return `${connector}:${owner.toLowerCase()}`;
}

export async function registerTestConnection(
  app: {
    request(path: string, init?: RequestInit): Promise<Response>;
  },
  devToken: string,
  owner: string,
  sourceId: string,
  methodId = sourceId.split("/").filter(Boolean).at(-1) ?? sourceId,
): Promise<string> {
  const connectionId = legacyTestConnectionId(owner, sourceId);
  const ownerResponse = await app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: {
      authorization: `Bearer ${devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ source_id: sourceId }),
  });
  if (!ownerResponse.ok) {
    throw new Error(`owner token request failed: ${ownerResponse.status}`);
  }
  const { access_token: token } = (await ownerResponse.json()) as {
    access_token: string;
  };
  const registration = await app.request(
    `/pdpp/connections/${encodeURIComponent(connectionId)}`,
    {
      method: "PUT",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        source_id: sourceId,
        method_id: methodId,
        label: "Personal",
      }),
    },
  );
  if (!registration.ok) {
    throw new Error(`connection registration failed: ${registration.status}`);
  }
  return token;
}
