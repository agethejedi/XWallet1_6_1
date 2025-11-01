// worker/src/util.js

export const VERSION = "v1.5.9-plaintext";

export function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,OPTIONS,HEAD",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Content-Type": "application/json",
  };
}

export function json(data, init = 200) {
  return new Response(JSON.stringify(data), { status: init, headers: corsHeaders() });
}

export function badRequest(message = "bad request") {
  return json({ error: message }, 400);
}

export function notFound(message = "not found") {
  return json({ error: message }, 404);
}

export function okEmpty() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

// --- list helpers ---
export function parseListToSet(raw) {
  if (!raw) return new Set();
  // Accept very large plaintext variables; split on newlines/commas/whitespace
  return new Set(
    String(raw)
      .split(/[\r\n,]+/g)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

export function normalizeHexAddress(addr) {
  if (!addr) return null;
  const a = String(addr).trim().toLowerCase();
  return /^0x[a-f0-9]{40}$/.test(a) ? a : null;
}

// Risk normalization (front-end expects this shape)
export function buildRiskResponse({
  address,
  network = "unknown",
  score = 10,
  block = false,
  reasons = [],
  risk_factors = [],
  matched_in = { ofac: false, badlist: false, bad_ens: false },
  policy = block
    ? "XWallet policy: hard block on listed addresses"
    : "XWallet policy: warn and allow under threshold",
  source = "cloudflare:plaintext",
}) {
  return {
    version: VERSION,
    address,
    network,
    risk_score: score,
    block: !!block,
    reasons,
    risk_factors,
    policy,
    checked_at: new Date().toISOString(),
    source,
    matched_in,
  };
}
