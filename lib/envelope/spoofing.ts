// Sender-spoofing detection: display-name impersonation, lookalike domains by
// homoglyph / punycode / edit distance against caller-supplied expected senders,
// and Reply-To / Return-Path divergence. Structural only — never contacts anyone.

import { getDomain } from "tldts";

const TLDTS_OPTS = { allowPrivateDomains: true };

export interface SpoofCheckOptions {
  from: string;
  fromDisplayName?: string;
  replyTo?: string;
  returnPath?: string;
  expectedSenders?: string[];
  homoglyphThreshold?: number;
}

export interface SpoofFinding {
  kind: string;
  severity: "info" | "warning" | "high";
  message: string;
}

const HOMOGLYPHS: Record<string, string> = {
  "а": "a", // cyrillic a
  "е": "e", // cyrillic e
  "о": "o", // cyrillic o
  "р": "p", // cyrillic er
  "с": "c", // cyrillic es
  "х": "x", // cyrillic ha
  "у": "y", // cyrillic u
  "ѕ": "s",
  "і": "i",
  "ј": "j",
  "ı": "i", // dotless i
  "ⅰ": "i",
  "ⅼ": "l",
  "ⅾ": "d",
  "０": "0",
  "１": "1",
  "２": "2",
  "３": "3",
  "４": "4",
  "５": "5",
  "６": "6",
  "７": "7",
  "８": "8",
  "９": "9",
};

function dehomoglyph(input: string): string {
  return [...input].map((ch) => HOMOGLYPHS[ch] ?? ch).join("");
}

function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[] = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(
        dp[j] + 1,
        dp[j - 1] + 1,
        prev + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
      prev = tmp;
    }
  }
  return dp[n];
}

export function domainOf(email: string): string {
  const trimmed = email.trim();
  // Prefer the LAST angle-bracket address — a display name may embed another email.
  const all = [...trimmed.matchAll(/<([^>]*@[^>]*)>/g)];
  const target = all.length > 0 ? all[all.length - 1][1] : trimmed;
  const m = target.match(/@([^\s>]+)/);
  return m ? m[1].toLowerCase().replace(/\.$/, "") : "";
}

export function isPunycode(domain: string): boolean {
  return domain.startsWith("xn--");
}

export function normalizeAscii(domain: string): string {
  return domain.toLowerCase().replace(/\.$/, "");
}

/**
 * Score a lookalike against an expected sender domain. Returns findings.
 * threshold: maximum edit distance for a domain to be considered a lookalike
 * (default 1, so "g00gle.com" vs "google.com" is a hit and "google.co.uk" is not).
 */
export function detectLookalike(
  candidate: string,
  expected: string,
  threshold = 1
): SpoofFinding | null {
  const c = normalizeAscii(candidate);
  const e = normalizeAscii(expected);
  if (!c || !e || c === e) return null;

  const plainC = dehomoglyph(c);
  const plainE = dehomoglyph(e);
  if (plainC === plainE && c !== e) {
    return {
      kind: "homoglyph",
      severity: "high",
      message: `domain "${c}" uses confusable characters for "${e}"`,
    };
  }

  const dist = editDistance(plainC, plainE);
  if (dist <= threshold && dist > 0) {
    return {
      kind: "lookalike",
      severity: "high",
      message: `domain "${c}" is ${dist} edit(s) away from expected "${e}"`,
    };
  }
  return null;
}

export function assessSpoofing(opts: SpoofCheckOptions): SpoofFinding[] {
  const findings: SpoofFinding[] = [];
  const fromDomain = domainOf(opts.from);

  if (!fromDomain) {
    findings.push({
      kind: "no-from-domain",
      severity: "warning",
      message: "From header has no parseable domain",
    });
  }

  // Display-name impersonation: the display name embeds an email-like pattern
  // whose domain differs from the From domain.
  const display = opts.fromDisplayName ?? "";
  if (display && fromDomain) {
    const dispEmail = display.match(/[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)/);
    if (dispEmail && domainOf(dispEmail[0]) !== fromDomain) {
      findings.push({
        kind: "display-name-email-mismatch",
        severity: "high",
        message: `display name embeds "${dispEmail[0]}" but the From domain is "${fromDomain}"`,
      });
    }
  }

  // Reply-To divergence.
  if (opts.replyTo) {
    const rtDomain = domainOf(opts.replyTo);
    if (rtDomain && fromDomain && rtDomain !== fromDomain) {
      findings.push({
        kind: "reply-to-divergence",
        severity: "warning",
        message: `Reply-To domain "${rtDomain}" differs from From domain "${fromDomain}"`,
      });
    }
  }

  // Return-Path divergence.
  if (opts.returnPath) {
    const rpDomain = domainOf(opts.returnPath);
    if (rpDomain && fromDomain && rpDomain !== fromDomain) {
      findings.push({
        kind: "return-path-divergence",
        severity: "info",
        message: `Return-Path domain "${rpDomain}" differs from From domain "${fromDomain}" (normal for forwarding)`,
      });
    }
  }

  // Lookalike / homoglyph / punycode against expected senders.
  const threshold = opts.homoglyphThreshold ?? 1;
  for (const expected of opts.expectedSenders ?? []) {
    const expectedDomain = domainOf(expected);
    if (!expectedDomain) continue;
    const hit = detectLookalike(fromDomain, expectedDomain, threshold);
    if (hit) findings.push(hit);
  }

  if (isPunycode(fromDomain)) {
    findings.push({
      kind: "punycode-domain",
      severity: "warning",
      message: `From domain "${fromDomain}" is punycode-encoded`,
    });
  }

  return findings;
}
