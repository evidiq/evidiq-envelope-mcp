import { createHash } from "node:crypto";
import { recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

// Closed digest field set (PLAN §7). An upgrade that changes a verdict is visible
// because libraryVersion is part of the digest. Same raw message + same pinned DNS
// answers must produce an identical digest and signature.
export interface EnvelopeReport {
  messageHash: string;
  checks: unknown;
  verdict: unknown;
  pinnedDns: unknown;
  libraryVersion: string;
  verifiedAt: string;
}

export const DIGEST_FIELDS: (keyof EnvelopeReport)[] = [
  "messageHash",
  "checks",
  "verdict",
  "pinnedDns",
  "libraryVersion",
  "verifiedAt",
];

/** RFC 8785 Canonical JSON (JCS): keys sorted lexicographically by UTF-8 code point. */
export function canonicalJsonStringify(obj: unknown): string {
  if (obj === null || obj === undefined || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJsonStringify).join(",") + "]";
  }
  const parts: string[] = [];
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    const val = (obj as Record<string, unknown>)[key];
    if (val === undefined) continue;
    parts.push(`${JSON.stringify(key)}:${canonicalJsonStringify(val)}`);
  }
  return "{" + parts.join(",") + "}";
}

export function canonicalPayload(payload: EnvelopeReport): string {
  const closed: Record<string, unknown> = {};
  for (const field of DIGEST_FIELDS) {
    closed[field] = payload[field];
  }
  return canonicalJsonStringify(closed);
}

export function reportDigest(payload: EnvelopeReport): string {
  return "0x" + createHash("sha256").update(canonicalPayload(payload), "utf-8").digest("hex");
}

export function getSignerKey(env: NodeJS.ProcessEnv = process.env): string | null {
  const raw = env.ENVELOPE_SIGNER_PRIVATE_KEY ?? null;
  if (!raw) return null;
  const hex = raw.startsWith("0x") ? raw : `0x${raw}`;
  if (/^0x[0-9a-fA-F]{64}$/.test(hex)) return hex;
  return null;
}

export function requireSigner(env: NodeJS.ProcessEnv = process.env): { privateKey: `0x${string}`; address: `0x${string}` } {
  const pk = getSignerKey(env);
  if (!pk) {
    throw new Error(
      "ENVELOPE_SIGNER_PRIVATE_KEY missing or invalid — no fallback signing key exists",
    );
  }
  return { privateKey: pk as `0x${string}`, address: privateKeyToAccount(pk as `0x${string}`).address };
}

export function getSignerAddress(env: NodeJS.ProcessEnv = process.env): string | null {
  const pk = getSignerKey(env);
  if (!pk) return null;
  return privateKeyToAccount(pk as `0x${string}`).address;
}

export async function signDigest(
  digest: string,
  privateKey: `0x${string}`,
): Promise<{ signature: `0x${string}`; signer: `0x${string}` }> {
  const account = privateKeyToAccount(privateKey);
  const rawDigest = (digest.startsWith("0x") ? digest : `0x${digest}`) as `0x${string}`;
  const signature = await account.signMessage({
    message: { raw: rawDigest },
  });
  return { signature, signer: account.address };
}

export async function verifySignature(
  digest: string,
  signature: `0x${string}`,
  expectedSigner: `0x${string}`,
): Promise<boolean> {
  try {
    const rawDigest = (digest.startsWith("0x") ? digest : `0x${digest}`) as `0x${string}`;
    const recovered = await recoverMessageAddress({
      message: { raw: rawDigest },
      signature,
    });
    return recovered.toLowerCase() === expectedSigner.toLowerCase();
  } catch {
    return false;
  }
}
