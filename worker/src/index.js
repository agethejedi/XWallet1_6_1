// src/index.js
import {
  VERSION,
  corsHeaders,
  json,
  badRequest,
  notFound,
  okEmpty,
  parseListToSet,
  normalizeHexAddress,
  buildRiskResponse,
} from "./util.js";

/**
 * SafeSend Risk Worker — v1.5.9
 * Evaluates addresses against plaintext OFAC / bad lists.
 * Cloudflare Env Vars expected:
 *  - OFACLIST
 *  - OFAC_SET (optional)
 *  - BADLIST
 *  - BAD_ENS
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // --- CORS preflight ---
    if (request.method === "OPTIONS")
      return new Response(null, { status: 204, headers: corsHeaders() });

    if (request.method !== "GET" && request.method !== "HEAD")
      return badRequest("method not allowed");

    // --- Routes ---
    if (path === "/") return json({ version: VERSION, ok: true });
    if (path === "/sanity") return handleSanity(env);
    if (path === "/check") return handleCheck(url, env);
    if (path === "/analytics") return handleAnalytics(url);

    return notFound("no such endpoint");
  },
};

// --- Route Handlers ---

function handleSanity(env) {
  const ofacA = parseListToSet(env.OFACLIST);
  const ofacB = parseListToSet(env.OFAC_SET);
  const ofac = new Set([...ofacA, ...ofacB]);

  const bad = parseListToSet(env.BADLIST);
  const ens = parseListToSet(env.BAD_ENS);

  return json({
    version: VERSION,
    env_present: {
      OFACLIST: ofacA.size || undefined,
      OFAC_SET: ofacB.size || undefined,
      BADLIST: bad.size || undefined,
      BAD_ENS: ens.size || undefined,
    },
    note: "Lengths only for sanity.",
  });
}

function handleCheck(url, env) {
  const addr = normalizeHexAddress(url.searchParams.get("address"));
  const network =
    url.searchParams.get("chain") || url.searchParams.get("network") || "unknown";
  if (!addr) return badRequest("address required");

  // Load lists from env
  const ofacA = parseListToSet(env.OFACLIST);
  const ofacB = parseListToSet(env.OFAC_SET);
  const ofac = new Set([...ofacA, ...ofacB]);
  const bad = parseListToSet(env.BADLIST);
  const ens = parseListToSet(env.BAD_ENS);

  const inOfac = ofac.has(addr);
  const inBad = bad.has(addr);
  const inBadENS = false; // ENS future use

  let score = 35;
  let block = false;
  const reasons = [];
  const factors = [];

  // --- Policy ---
  if (inOfac) {
    score = 100;
    block = true;
    reasons.push("OFAC");
    factors.push("OFAC/sanctions list match");
  } else if (inBad) {
    score = 100;
    block = true;
    reasons.push("BADLIST");
    factors.push("Internal bad list match");
  }

  return json(
    buildRiskResponse({
      address: addr,
      network,
      score,
      block,
      reasons,
      risk_factors: factors,
      matched_in: { ofac: inOfac, badlist: inBad, bad_ens: inBadENS },
    })
  );
}

// Optional enrichment stub — used by analytics endpoint
function handleAnalytics(url) {
  const addr = normalizeHexAddress(url.searchParams.get("address"));
  const network =
    url.searchParams.get("chain") || url.searchParams.get("network") || "unknown";
  if (!addr) return okEmpty();

  return json({
    version: VERSION,
    address: addr,
    network,
    sanctions: { hit: false },
    exposures: { mixer: false, scam: false },
    heuristics: { ageDays: null },
    note: "analytics stub (no enrichment configured)",
  });
}
