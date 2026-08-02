import { describe, expect, it, beforeEach, afterEach } from "vitest";
import {
  EnvelopeReport,
  canonicalJsonStringify,
  canonicalPayload,
  getSignerAddress,
  getSignerKey,
  reportDigest,
  requireSigner,
  signDigest,
  verifySignature,
} from "../lib/envelope/report.js";

const TEST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // anvil #0 - throwaway, test-only

const report: EnvelopeReport = {
  messageHash: "0x" + "ab".repeat(32),
  checks: { dkim: [{ signingDomain: "example.com", result: "pass" }] },
  verdict: { verdict: "authenticated", finding: "ok" },
  pinnedDns: [{ domain: "example.com", rrtype: "TXT", records: ["v=spf1 -all"] }],
  libraryVersion: "4.13.3",
  verifiedAt: "2026-01-02T10:00:00.000Z",
};

describe("report digest (PLAN §7 closed field set)", () => {
  it("same payload → identical digest", () => {
    expect(reportDigest(report)).toBe(reportDigest({ ...report }));
  });

  it("libraryVersion is part of the digest — an upgrade that changes a verdict is visible", () => {
    const upgraded = { ...report, libraryVersion: "4.14.0" };
    expect(reportDigest(upgraded)).not.toBe(reportDigest(report));
  });

  it("verifiedAt is part of the digest", () => {
    const later = { ...report, verifiedAt: "2026-01-03T10:00:00.000Z" };
    expect(reportDigest(later)).not.toBe(reportDigest(report));
  });

  it("digest excludes nothing: extra keys are dropped by the closed set", () => {
    const withExtra = { ...report, rawMessage: "SECRET" };
    expect(reportDigest(withExtra as EnvelopeReport)).toBe(reportDigest(report));
  });

  it("canonicalJsonStringify sorts keys (RFC 8785)", () => {
    expect(canonicalJsonStringify({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("digest is a 0x-prefixed 64-hex string", () => {
    expect(reportDigest(report)).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

describe("signer (no fallback key)", () => {
  const KEY_ENV = "ENVELOPE_SIGNER_PRIVATE_KEY";

  afterEach(() => {
    delete process.env[KEY_ENV];
  });

  it("unset signer → requireSigner throws", () => {
    delete process.env[KEY_ENV];
    expect(() => requireSigner()).toThrow(/ENVELOPE_SIGNER_PRIVATE_KEY/);
  });

  it("invalid signer → requireSigner throws", () => {
    process.env[KEY_ENV] = "not-a-key";
    expect(() => requireSigner()).toThrow(/ENVELOPE_SIGNER_PRIVATE_KEY/);
  });

  it("bare 64-hex is accepted and normalised", () => {
    process.env[KEY_ENV] = TEST_KEY.slice(2);
    expect(getSignerKey()).toBe(TEST_KEY);
  });

  it("sign/verify round-trips to the fleet signer", async () => {
    process.env[KEY_ENV] = TEST_KEY;
    const digest = reportDigest(report);
    const { signature, signer } = await signDigest(digest, requireSigner().privateKey);
    expect(signer.toLowerCase()).toBe("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    expect(await verifySignature(digest, signature, signer)).toBe(true);
    expect(getSignerAddress()).toBe(signer);
  });

  it("tampered digest fails verification", async () => {
    process.env[KEY_ENV] = TEST_KEY;
    const { signature, signer } = await signDigest(reportDigest(report), requireSigner().privateKey);
    expect(await verifySignature(reportDigest({ ...report, verifiedAt: "2020-01-01T00:00:00.000Z" }), signature, signer)).toBe(false);
  });

  it("canonicalPayload is deterministic over the closed set", () => {
    expect(canonicalPayload(report)).toBe(canonicalPayload({ ...report }));
  });
});
