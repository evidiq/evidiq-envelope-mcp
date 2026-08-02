// Sender-domain posture: SPF record validity and lookup count, resolvable DKIM
// selectors, DMARC policy strength, DNSSEC, MX presence. Read-only DNS checks;
// the answers are pinned into the report.

import { PinningDns } from "./dns.js";

export interface PostureFinding {
  kind: string;
  severity: "info" | "warning" | "high";
  message: string;
}

export interface PostureResult {
  domain: string;
  spf: { record: string | null; valid: boolean; lookupCount: number; hardFail: boolean; issue?: string };
  dkim: { selector: string; resolvable: boolean }[];
  dmarc: { record: string | null; policy: "none" | "quarantine" | "reject" | null; strength: "none" | "weak" | "strong" | null };
  dnssec: boolean | null;
  mx: string[] | null;
  findings: PostureFinding[];
  pinnedDns: ReturnType<PinningDns["getPinned"]>;
}

function parseSpfLookups(record: string): { lookupCount: number; hardFail: boolean; valid: boolean; issue?: string } {
  const mechanisms = record.split(/\s+/);
  let lookupCount = 0;
  let hardFail = false;
  let valid = true;
  let issue: string | undefined;
  for (const m of mechanisms) {
    const mech = m.toLowerCase();
    if (mech.startsWith("include:")) lookupCount += 1;
    else if (mech.startsWith("redirect=")) lookupCount += 1;
    else if (mech === "a") lookupCount += 1;
    else if (mech === "mx") lookupCount += 1;
    else if (mech === "ip4" || mech.startsWith("ip4:")) lookupCount += 1;
    else if (mech === "ip6" || mech.startsWith("ip6:")) lookupCount += 1;
    else if (mech === "-all") hardFail = true;
    else if (/^[a-z0-9]*:/i.test(mech) && !mech.startsWith("v=spf1")) {
      valid = false;
      issue = `unknown mechanism "${mech}"`;
    }
  }
  if (lookupCount > 10) {
    valid = false;
    issue = "SPF lookup count exceeds the RFC 7208 limit of 10";
  }
  return { lookupCount, hardFail, valid, issue };
}

export async function screenDomainPosture(
  domain: string,
  opts: { resolvers?: string[]; dkimSelectors?: string[] } = {}
): Promise<PostureResult> {
  const dns = new PinningDns(opts.resolvers);
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  const findings: PostureFinding[] = [];

  // SPF.
  let spfRecord: string | null = null;
  try {
    const txts = await dns.query(d, "TXT");
    spfRecord = txts.find((t) => t.toLowerCase().startsWith("v=spf1")) ?? null;
  } catch {
    // no TXT
  }
  let spf = { record: spfRecord, valid: false, lookupCount: 0, hardFail: false };
  if (spfRecord) {
    const parsed = parseSpfLookups(spfRecord);
    spf = { record: spfRecord, ...parsed };
    if (!parsed.valid) {
      findings.push({ kind: "spf-invalid", severity: "warning", message: `SPF record is not RFC 7208 valid: ${parsed.issue}` });
    }
    if (!parsed.hardFail) {
      findings.push({ kind: "spf-no-hardfail", severity: "info", message: "SPF record does not end with -all (softfail/neutral allows forgery to appear neutral)" });
    }
  } else {
    findings.push({ kind: "no-spf", severity: "high", message: `no SPF record for ${d}` });
  }

  // DKIM selectors.
  const selectors = (opts.dkimSelectors ?? ["default", "selector1", "k1", "s1", "mail", "dkim"]).slice(0, 10);
  const dkim: { selector: string; resolvable: boolean }[] = [];
  for (const sel of selectors) {
    const q = `${sel}._domainkey.${d}`;
    try {
      const txts = await dns.query(q, "TXT");
      const hasKey = txts.some((t) => /^v=DKIM1/i.test(t));
      dkim.push({ selector: sel, resolvable: hasKey });
    } catch {
      dkim.push({ selector: sel, resolvable: false });
    }
  }
  const anySelector = dkim.some((s) => s.resolvable);
  if (!anySelector) {
    findings.push({ kind: "no-dkim-selectors", severity: "warning", message: `none of the probed DKIM selectors resolve for ${d}` });
  }

  // DMARC.
  let dmarcRecord: string | null = null;
  try {
    const txts = await dns.query(`_dmarc.${d}`, "TXT");
    dmarcRecord = txts.find((t) => t.toLowerCase().startsWith("v=dmarc1")) ?? null;
  } catch {
    // no DMARC
  }
  let dmarc = { record: dmarcRecord, policy: null as "none" | "quarantine" | "reject" | null, strength: null as "none" | "weak" | "strong" | null };
  if (dmarcRecord) {
    const p = dmarcRecord.match(/\bp=(none|quarantine|reject)\b/i)?.[1]?.toLowerCase() as "none" | "quarantine" | "reject";
    dmarc = {
      record: dmarcRecord,
      policy: p ?? null,
      strength: p === "reject" ? "strong" : p === "quarantine" ? "weak" : p === "none" ? "none" : null,
    };
    if (p !== "reject") {
      findings.push({ kind: "dmarc-weak", severity: p === "none" ? "warning" : "info", message: `DMARC policy is p=${p}; p=reject is the only policy that makes unaligned mail fail hard` });
    }
  } else {
    findings.push({ kind: "no-dmarc", severity: "high", message: `no DMARC record for ${d}` });
  }

  // DNSSEC.
  let dnssec: boolean | null = null;
  try {
    const keys = await dns.query(d, "DNSKEY");
    dnssec = keys.length > 0;
  } catch {
    dnssec = false;
  }
  if (dnssec === false) {
    findings.push({ kind: "no-dnssec", severity: "info", message: `no DNSSEC DNSKEY for ${d}` });
  }

  // MX.
  let mx: string[] | null = null;
  try {
    const rows = await dns.query(d, "MX");
    mx = rows;
  } catch {
    mx = null;
  }
  if (mx === null || mx.length === 0) {
    findings.push({ kind: "no-mx", severity: "info", message: `no MX record for ${d} — the domain does not receive mail` });
  }

  return { domain: d, spf, dkim, dmarc, dnssec, mx, findings, pinnedDns: dns.getPinned() };
}
