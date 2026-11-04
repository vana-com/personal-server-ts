/** Fee evidence only: callers must first authorize the app's live data grant. */
export async function isOwnAppRead(input: {
  accountUrl: string;
  appAddress: string;
  dataOwner: string;
  chainId: number;
}): Promise<boolean> {
  const network =
    input.chainId === 1480
      ? "mainnet"
      : input.chainId === 14800
        ? "moksha"
        : null;
  if (!network) throw new Error("Unsupported own-app network");
  const origin = new URL(input.accountUrl);
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    throw new Error("Own-app Account must be an HTTPS origin");
  }
  const url = new URL("/api/v1/apps/own-data-read-eligibility", origin);
  const appAddress = input.appAddress.toLowerCase();
  const dataOwner = input.dataOwner.toLowerCase();
  url.search = new URLSearchParams({
    appAddress,
    dataOwner,
    network,
  }).toString();
  const response = await fetch(url, {
    redirect: "error",
    cache: "no-store",
    signal: AbortSignal.timeout(6000),
  });
  if (!response.ok) throw new Error("Account own-app evidence unavailable");
  const body: unknown = await response.json();
  if (!body || typeof body !== "object")
    throw new Error("Invalid own-app evidence");
  const evidence = body as Record<string, unknown>;
  if (
    evidence.object !== "own_app_read_eligibility" ||
    evidence.appAddress !== appAddress ||
    evidence.dataOwner !== dataOwner ||
    evidence.network !== network ||
    !["eligible", "not_eligible"].includes(String(evidence.eligibility))
  ) {
    throw new Error("Mismatched own-app evidence");
  }
  return evidence.eligibility === "eligible";
}
