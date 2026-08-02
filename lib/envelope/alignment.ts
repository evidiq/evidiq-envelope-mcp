// RFC 7489 identifier alignment — implemented locally because mailauth 4.13.3's
// getAlignment compares the REGISTRABLE domain of d= against the full From domain
// under strict mode (tools.js:477), which lets a subdomain signer pass strict
// alignment. RFC 7489 §3.1: strict requires d= to be IDENTICAL to the From domain;
// relaxed accepts the From domain or any subdomain of it.
//
// Deviation documented in README ("§6 fixture gate findings").

import { getDomain } from "tldts";

const TLDTS_OPTS = {
  allowPrivateDomains: true,
};

function normalize(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/, "");
}

/**
 * RFC 7489 DKIM identifier alignment.
 * @param signingDomain the DKIM d= domain
 * @param fromDomain    the domain part of the From header
 * @param mode          "strict" | "relaxed" (from DMARC adkim tag)
 */
export function checkDkimAlignment(
  signingDomain: string,
  fromDomain: string,
  mode: "strict" | "relaxed"
): boolean {
  const d = normalize(signingDomain);
  const f = normalize(fromDomain);
  if (!d || !f) return false;
  if (d === f) return true;
  if (mode === "strict") return false;
  const regD = getDomain(d, TLDTS_OPTS) ?? d;
  const regF = getDomain(f, TLDTS_OPTS) ?? f;
  return regD === regF || d.endsWith("." + f);
}

/**
 * RFC 7489 SPF identifier alignment.
 * @param spfDomain the domain of the envelope MAIL FROM (or HELO for null sender)
 * @param fromDomain the domain part of the From header
 * @param mode      "strict" | "relaxed" (from DMARC aspf tag)
 */
export function checkSpfAlignment(
  spfDomain: string,
  fromDomain: string,
  mode: "strict" | "relaxed"
): boolean {
  const d = normalize(spfDomain);
  const f = normalize(fromDomain);
  if (!d || !f) return false;
  if (d === f) return true;
  if (mode === "strict") return false;
  const regD = getDomain(d, TLDTS_OPTS) ?? d;
  const regF = getDomain(f, TLDTS_OPTS) ?? f;
  return regD === regF || d.endsWith("." + f);
}
