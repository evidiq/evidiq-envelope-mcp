import { createRequire } from "node:module";
import { authenticate } from "mailauth";
import type { AuthenticateResult } from "mailauth";
import { PinningDns } from "./dns.js";
import { checkDkimAlignment, checkSpfAlignment } from "./alignment.js";

const require = createRequire(import.meta.url);
export const MAILAUTH_VERSION: string =
  (require("mailauth/package.json") as { version: string }).version;

export interface AuthToolResult {
  ok: boolean;
  finding: string;
  checks: unknown;
  pinnedDns: ReturnType<PinningDns["getPinned"]>;
  libraryVersion: string;
  libraryRaw?: unknown;
}

export interface VerifyOptions {
  rawMessage: string;
  resolvers?: string[];
  disableArc?: boolean;
}

export async function runAuthenticate(
  rawMessage: string,
  opts: { resolvers?: string[]; disableArc?: boolean } = {}
): Promise<{ result: AuthenticateResult; dns: PinningDns }> {
  const dns = new PinningDns(opts.resolvers);
  const result = await authenticate(rawMessage, {
    trustReceived: true,
    resolver: dns.mailauthResolver,
    disableArc: opts.disableArc ?? false,
    disableBimi: true,
  });
  return { result, dns };
}

function mapDkimResult(r: AuthenticateResult["dkim"]["results"][number]) {
  const raw = r.status.result;
  return {
    signingDomain: r.signingDomain,
    selector: r.selector ?? null,
    algorithm: r.algorithm ?? null,
    canonicalization: r.canonicalization ?? null,
    result: raw === "pass" ? "pass" : raw === "fail" ? "fail" : raw === "policy" ? "policy" : "not-pass",
    rawStatus: raw,
    reason: r.status.comment ?? null,
    alignedToFrom: r.status.aligned ?? null,
  };
}

/**
 * RFC 7489 alignment computed by Envelope itself (see alignment.ts). Returns the
 * effective DMARC status with the alignment the library would NOT give us.
 */
export function computeDmarcAlignment(
  result: AuthenticateResult,
  dmarcRecord: string | undefined
): {
  dkimAligned: boolean;
  spfAligned: boolean;
  adkim: "strict" | "relaxed";
  aspf: "strict" | "relaxed";
  aligned: boolean;
  note?: string;
} {
  const fromDomain = result.dkim.headerFrom?.[0]?.split("@").pop() ?? "";

  const adkim = /adkim=s/i.test(dmarcRecord ?? "") ? "strict" : "relaxed";
  const aspf = /aspf=s/i.test(dmarcRecord ?? "") ? "strict" : "relaxed";

  let dkimAligned = false;
  for (const r of result.dkim.results) {
    if (r.status.result !== "pass") continue;
    if (checkDkimAlignment(r.signingDomain, fromDomain, adkim)) {
      dkimAligned = true;
      break;
    }
  }

  let spfAligned = false;
  const spfDomain = result.spf && result.spf.status.result === "pass"
    ? (result.spf.domain ?? result.spf["envelope-from"]?.split("@").pop() ?? "")
    : "";
  if (spfDomain && checkSpfAlignment(spfDomain, fromDomain, aspf)) {
    spfAligned = true;
  }

  return {
    dkimAligned,
    spfAligned,
    adkim,
    aspf,
    aligned: dkimAligned || spfAligned,
  };
}
