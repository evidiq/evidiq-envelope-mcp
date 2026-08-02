import { describe, expect, it } from "vitest";
import { authenticate } from "mailauth";
import { version as MAILAUTH_VERSION } from "mailauth/package.json";
import {
  BaseMessage,
  buildMessage,
  dkimPublicRecord,
  dmarcRecord,
  FIXED_SIGN_TIME,
  flipBodyByte,
  generateKey,
  makeResolver,
  DnsMap,
  sealWithArc,
  signWithDkim,
  tamperSignature,
} from "./fixtures.js";
import { checkDkimAlignment } from "../lib/envelope/alignment.js";

const common: BaseMessage = {
  from: "alice@example.com",
  fromDomain: "example.com",
  to: "bob@other.com",
  subject: "Fixture invoice",
  body: "Please settle the fixture invoice of 100 USDT0.",
  clientIp: "203.0.113.1",
  clientHost: "mail.example.com",
};

function authOpts(resolverMap: DnsMap) {
  return {
    resolver: makeResolver(resolverMap),
    trustReceived: true,
  };
}

describe("§6 fixture gate — mailauth " + MAILAUTH_VERSION, () => {
  it("F1: a valid DKIM signature → pass", async () => {
    const key = generateKey();
    const msg = await signWithDkim(buildMessage(common), {
      signingDomain: "example.com",
      selector: "sel1",
      key,
      signTime: FIXED_SIGN_TIME,
    });
    const dns = new Map<string, string[]>([
      ["sel1._domainkey.example.com", [dkimPublicRecord(key)]],
    ]);
    const res = await authenticate(msg, authOpts(dns));
    expect(res.dkim.results.length).toBe(1);
    expect(res.dkim.results[0].status.result).toBe("pass");
    expect(res.dkim.results[0].signingDomain).toBe("example.com");
    expect(res.dkim.results[0].status.aligned).toBe("example.com");
  });

  // Gate finding (reported, user-approved 2026-08-03): mailauth labels body-hash
  // mismatches `neutral`, not `fail` (dkim-verifier.js:224). Security outcome is
  // preserved — neutral is not a pass and DMARC cannot pass on it — so the fixture
  // asserts "not pass + stated reason" and the deviation is documented in the README.
  it("F2: one byte flipped in the body → not pass, with body-hash mismatch", async () => {
    const key = generateKey();
    const signed = await signWithDkim(buildMessage(common), {
      signingDomain: "example.com",
      selector: "sel1",
      key,
      signTime: FIXED_SIGN_TIME,
    });
    const dns = new Map<string, string[]>([
      ["sel1._domainkey.example.com", [dkimPublicRecord(key)]],
    ]);
    const res = await authenticate(flipBodyByte(signed), authOpts(dns));
    expect(res.dkim.results.length).toBe(1);
    expect(res.dkim.results[0].status.result).not.toBe("pass");
    expect(res.dkim.results[0].status.comment?.toLowerCase() ?? "").toMatch(/hash/);
  });

  // Gate finding (reported, user-approved 2026-08-03): mailauth labels a missing
  // key `neutral` ("no key"), not `fail`. It does not crash. Same security outcome.
  it("F3: key removed from DNS → not pass with key-not-found, not a crash", async () => {
    const key = generateKey();
    const signed = await signWithDkim(buildMessage(common), {
      signingDomain: "example.com",
      selector: "sel1",
      key,
      signTime: FIXED_SIGN_TIME,
    });
    const res = await authenticate(signed, authOpts(new Map()));
    expect(res.dkim.results.length).toBe(1);
    expect(res.dkim.results[0].status.result).not.toBe("pass");
    const comment = (res.dkim.results[0].status.comment ?? "").toLowerCase();
    expect(comment).toMatch(/key/);
  });

  // Gate finding (reported, user-approved 2026-08-03): mailauth's getAlignment
  // (tools.js:477) compares the REGISTRABLE domain of d= against the full From
  // domain under strict — a subdomain signer passes strict alignment, deviating
  // from RFC 7489 (strict requires d= identical to From). Envelope therefore
  // computes RFC 7489 alignment itself and the F4 fixture tests OUR function.
  it("F4: d= misaligned with From → RFC 7489 strict fails, relaxed passes", async () => {
    const fromDomain = "example.com";
    expect(checkDkimAlignment("mailer.example.com", fromDomain, "strict")).toBe(false);
    expect(checkDkimAlignment("mailer.example.com", fromDomain, "relaxed")).toBe(true);
    expect(checkDkimAlignment("attacker.net", fromDomain, "relaxed")).toBe(false);
    expect(checkDkimAlignment("example.com", fromDomain, "strict")).toBe(true);
    expect(checkDkimAlignment("mail.example.com", "mail.example.com", "strict")).toBe(true);
  });

  it("F5: two signatures, one valid one broken → per-signature detail", async () => {
    const keyA = generateKey();
    const keyB = generateKey();
    const base = buildMessage(common);
    const withA = await signWithDkim(base, {
      signingDomain: "example.com",
      selector: "sel1",
      key: keyA,
      signTime: FIXED_SIGN_TIME,
    });
    const withBoth = await signWithDkim(withA, {
      signingDomain: "example.com",
      selector: "sel2",
      key: keyB,
      signTime: FIXED_SIGN_TIME,
    });
    const dns = new Map<string, string[]>([
      ["sel1._domainkey.example.com", [dkimPublicRecord(keyA)]],
      ["sel2._domainkey.example.com", [dkimPublicRecord(keyB)]],
    ]);
    const broken = await authenticate(tamperSignature(withBoth, 1), authOpts(dns));
    expect(broken.dkim.results.length).toBe(2);
    const statuses = broken.dkim.results.map((r) => r.status.result);
    expect(statuses).toContain("pass");
    expect(statuses).toContain("fail");
  });

  it("F6: SPF pass but From domain unaligned → the classic phish shape must not read as safe", async () => {
    const key = generateKey();
    const phish = buildMessage({
      ...common,
      from: "victim@example.com",
      fromDomain: "example.com",
      envelopeFrom: "<bounce@spf-example.com>",
    });
    const signed = await signWithDkim(phish, {
      signingDomain: "spf-example.com",
      selector: "sel1",
      key,
      signTime: FIXED_SIGN_TIME,
    });
    const dns = new Map<string, string[]>([
      ["spf-example.com", ["v=spf1 ip4:203.0.113.1 -all"]],
      ["sel1._domainkey.spf-example.com", [dkimPublicRecord(key)]],
      ["_dmarc.example.com", [dmarcRecord("reject", "aspf=s")]],
    ]);
    const res = await authenticate(signed, authOpts(dns));
    expect(res.spf).not.toBe(false);
    expect(res.spf!.status.result).toBe("pass");
    expect(res.dmarc).not.toBe(false);
    expect(res.dmarc!.status.result).toBe("fail");
    expect(res.dmarc!.alignment.spf.strict).toBe(true);
  });

  it("F7: a forwarded message with a valid ARC chain → not treated as forgery", async () => {
    const origKey = generateKey();
    const fwdKey = generateKey();
    const original = await signWithDkim(buildMessage(common), {
      signingDomain: "example.com",
      selector: "sel1",
      key: origKey,
      signTime: FIXED_SIGN_TIME,
    });
    const dns = new Map<string, string[]>([
      ["sel1._domainkey.example.com", [dkimPublicRecord(origKey)]],
      ["arc2026._domainkey.fwd.example.net", [dkimPublicRecord(fwdKey)]],
    ]);
    const forwarded = await sealWithArc(original, {
      signingDomain: "fwd.example.net",
      selector: "arc2026",
      key: fwdKey,
    });
    const res = await authenticate(forwarded, authOpts(dns));
    expect(res.arc).not.toBe(false);
    expect(res.arc!.status.result).toBe("pass");
    const dkimPass = res.dkim.results.filter((r) => r.status.result === "pass");
    expect(dkimPass.length).toBeGreaterThanOrEqual(1);
  });
});
