// Structural link analysis — never fetches a URL found in a message (PLAN §3:
// doing so would turn Envelope into a fetch proxy for attackers).
// Punycode hosts, anchor text disagreeing with href, credential-shaped URLs,
// redirector patterns, lookalike hosts.

import { getDomain } from "tldts";
import { detectLookalike, isPunycode } from "./spoofing.js";

const TLDTS_OPTS = { allowPrivateDomains: true };

export interface UrlInput {
  href: string;
  anchorText?: string;
}

export interface LinkFinding {
  kind: string;
  severity: "info" | "warning" | "high";
  message: string;
}

const REDIRECT_PATTERNS = [
  /^https?:\/\/[^\/]+\/(?:r|redirect|redir|go|click|track|trk|out|away|url|l\/|link)\b/i,
  /[?&](?:url|redirect|next|target|dest|destination|return|continue|go)=https?%3a/i,
];

const CREDENTIAL_PATTERNS = [
  /^https?:\/\/[^@\/]+\/[^@]*@/i,
  /[?&](?:login|signin|auth|token|key|pass|password|secret)=/i,
];

function hostOf(href: string): string {
  try {
    return new URL(href).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return "";
  }
}

export function assessLink(
  link: UrlInput,
  expectedSenders: string[] = []
): LinkFinding[] {
  const findings: LinkFinding[] = [];
  const host = hostOf(link.href);

  if (!host) {
    findings.push({
      kind: "unparseable-url",
      severity: "warning",
      message: `cannot parse URL "${link.href.slice(0, 80)}"`,
    });
    return findings;
  }

  if (isPunycode(host)) {
    findings.push({
      kind: "punycode-host",
      severity: "high",
      message: `host "${host}" is punycode-encoded — it displays as a different domain`,
    });
  }

  const anchor = (link.anchorText ?? "").trim();
  if (anchor && /^https?:\/\//i.test(anchor)) {
    const anchorHost = hostOf(anchor);
    if (anchorHost && anchorHost !== host) {
      findings.push({
        kind: "anchor-href-mismatch",
        severity: "high",
        message: `anchor text points to "${anchorHost}" but the link goes to "${host}"`,
      });
    }
  } else if (anchor && anchor.length > 0) {
    const anchorDomain = anchor.match(/[A-Za-z0-9.-]+\.[a-z]{2,}/i)?.[0];
    if (anchorDomain && host && !host.endsWith(anchorDomain.toLowerCase()) && !anchorDomain.toLowerCase().startsWith(host)) {
      findings.push({
        kind: "anchor-text-mismatch",
        severity: "warning",
        message: `anchor text "${anchor.slice(0, 40)}" does not match the destination host "${host}"`,
      });
    }
  }

  for (const pat of REDIRECT_PATTERNS) {
    if (pat.test(link.href)) {
      findings.push({
        kind: "redirector-pattern",
        severity: "warning",
        message: `URL uses a redirector/click-tracking pattern`,
      });
      break;
    }
  }

  for (const pat of CREDENTIAL_PATTERNS) {
    if (pat.test(link.href)) {
      findings.push({
        kind: "credential-shaped-url",
        severity: "warning",
        message: `URL embeds credential-shaped parameters`,
      });
      break;
    }
  }

  const regHost = getDomain(host, TLDTS_OPTS) ?? host;
  for (const expected of expectedSenders) {
    const expectedDomain = expected.split("@").pop()?.toLowerCase() ?? "";
    if (!expectedDomain) continue;
    const regExpected = getDomain(expectedDomain, TLDTS_OPTS) ?? expectedDomain;
    if (regHost === regExpected && host !== expectedDomain) {
      findings.push({
        kind: "subdomain-of-expected",
        severity: "info",
        message: `host "${host}" is a subdomain of expected domain "${expectedDomain}"`,
      });
    }
    const lookalike = detectLookalike(host, expectedDomain, 1);
    if (lookalike) {
      findings.push({
        kind: "lookalike-host",
        severity: "high",
        message: lookalike.message,
      });
    }
  }

  return findings;
}

export function assessLinkSurface(
  links: UrlInput[],
  expectedSenders: string[] = []
): { findings: LinkFinding[]; highCount: number; warningCount: number } {
  const findings: LinkFinding[] = [];
  for (const link of links) {
    findings.push(...assessLink(link, expectedSenders));
  }
  return {
    findings,
    highCount: findings.filter((f) => f.severity === "high").length,
    warningCount: findings.filter((f) => f.severity === "warning").length,
  };
}
