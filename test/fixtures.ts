import { generateKeyPairSync, randomBytes } from "node:crypto";
import { dkimSign, sealMessage } from "mailauth";
import type { DNSResolver } from "mailauth";

export interface TestKey {
  privateKey: string;
  publicKeyPem: string;
}

export function generateKey(): TestKey {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
  };
}

export function dkimPublicRecord(key: TestKey): string {
  const pem = key.publicKeyPem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\s+/g, "");
  return `v=DKIM1; k=rsa; p=${pem}`;
}

export type DnsMap = Map<string, string[]>;

export function makeResolver(map: DnsMap): DNSResolver {
  return async (domain: string, rrtype: string) => {
    if (rrtype !== "TXT") return [];
    const rows = map.get(domain.toLowerCase());
    if (!rows || rows.length === 0) {
      const err = new Error(`queryTxt ${domain} ENOTFOUND`) as Error & { code: string };
      err.code = "ENOTFOUND";
      throw err;
    }
    return rows.map((r) => [r]);
  };
}

export const FIXED_SIGN_TIME = "2026-01-02T10:00:00.000Z";

export interface BaseMessage {
  from: string;
  fromDomain: string;
  to: string;
  subject: string;
  body: string;
  clientIp: string;
  clientHost: string;
  envelopeFrom?: string;
}

export function buildMessage(opts: BaseMessage): string {
  const envFrom = opts.envelopeFrom ?? `<${opts.from}>`;
  return [
    `Received: from ${opts.clientHost} (${opts.clientHost} [${opts.clientIp}])`,
    `\tby mx.example.com with ESMTP id x${randomBytes(4).toString("hex")}`,
    `\tfor <${opts.to}>; Fri, 02 Jan 2026 10:01:00 +0000`,
    `Return-Path: ${envFrom}`,
    `From: ${opts.from}`,
    `To: ${opts.to}`,
    `Subject: ${opts.subject}`,
    `Date: Fri, 02 Jan 2026 10:00:00 +0000`,
    `Message-ID: <m${randomBytes(6).toString("hex")}@${opts.fromDomain}>`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset="utf-8"`,
    ``,
    opts.body,
    ``,
  ].join("\n");
}

export async function signWithDkim(
  message: string,
  opts: {
    signingDomain: string;
    selector: string;
    key: TestKey;
    signTime?: string;
  }
): Promise<string> {
  const result = await dkimSign(message, {
    signatureData: [
      {
        signingDomain: opts.signingDomain,
        selector: opts.selector,
        privateKey: opts.key.privateKey,
        algorithm: "rsa-sha256",
        canonicalization: "relaxed/relaxed",
        signTime: opts.signTime ?? FIXED_SIGN_TIME,
      },
    ],
    algorithm: "rsa-sha256",
    canonicalization: "relaxed/relaxed",
    signTime: opts.signTime ?? FIXED_SIGN_TIME,
    headerList: ["From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type"],
  });
  if (result.errors.length > 0) {
    throw new Error(`dkimSign failed: ${result.errors.map((e) => e.message).join("; ")}`);
  }
  return result.signatures + message;
}

export function tamperSignature(message: string, nth: number): string {
  const lines = message.split("\n");
  let seen = 0;
  let inHeader = false;
  let replaced = false;
  const out: string[] = [];
  for (const line of lines) {
    if (line.startsWith("DKIM-Signature:")) {
      seen += 1;
      inHeader = seen === nth;
      if (inHeader && !replaced) {
        const m = line.match(/b=([A-Za-z0-9+/=]+)/);
        if (m) {
          out.push(line.replace(m[1], m[1][0] === "A" ? "B" + m[1].slice(1) : "A" + m[1].slice(1)));
          replaced = true;
          continue;
        }
      }
      out.push(line);
      continue;
    }
    if (inHeader && !replaced && /^\s/.test(line)) {
      const m = line.match(/b=([A-Za-z0-9+/=]+)/);
      if (m) {
        out.push(line.replace(m[1], m[1][0] === "A" ? "B" + m[1].slice(1) : "A" + m[1].slice(1)));
        replaced = true;
        continue;
      }
    }
    if (inHeader && !/^\s/.test(line)) {
      inHeader = false;
    }
    out.push(line);
  }
  if (!replaced) throw new Error("tamperSignature: no b= tag found");
  return out.join("\n");
}

export function flipBodyByte(message: string): string {
  const idx = message.lastIndexOf("\n\n");
  if (idx === -1) throw new Error("no body separator");
  const head = message.slice(0, idx + 2);
  const body = message.slice(idx + 2);
  const buf = Buffer.from(body, "utf-8");
  const at = Math.min(buf.length - 1, 10);
  buf[at] = buf[at] ^ 0x01;
  return head + buf.toString("utf-8");
}

export async function sealWithArc(
  message: string,
  opts: { signingDomain: string; selector: string; key: TestKey }
): Promise<string> {
  const sealed = await sealMessage(message, {
    signingDomain: opts.signingDomain,
    selector: opts.selector,
    privateKey: opts.key.privateKey,
    algorithm: "rsa-sha256",
    canonicalization: "relaxed/relaxed",
    signTime: FIXED_SIGN_TIME,
    authResults:
      "dkim=pass header.i=@example.com header.d=example.com spf=pass smtp.mailfrom=alice@example.com",
    cv: "none",
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
  return sealed.toString("utf-8") + message;
}

export function dmarcRecord(policy: string, extra = ""): string {
  return `v=DMARC1; p=${policy}${extra ? "; " + extra : ""}`;
}
