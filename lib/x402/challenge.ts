import { X402Challenge, X402AcceptRequirement } from "./types.js";
import { getX402Config } from "./config.js";

export const TOOL_PRICES_ATOMIC: Record<string, string> = {
  verify_dkim: "5000",               // 0.005 USDT0
  check_dmarc_alignment: "5000",     // 0.005 USDT0
  verify_message_auth: "10000",      // 0.01 USDT0
  validate_arc_chain: "10000",       // 0.01 USDT0
  detect_sender_spoofing: "15000",   // 0.015 USDT0
  audit_header_chain: "15000",       // 0.015 USDT0
  assess_attachment_surface: "20000",// 0.02 USDT0
  assess_link_surface: "20000",      // 0.02 USDT0
  screen_domain_posture: "20000",    // 0.02 USDT0
  attest_message_verdict: "30000",   // 0.03 USDT0
};

export const TOOL_PRICES_HUMAN: Record<string, string> = {
  verify_dkim: "0.005 USDT0",
  check_dmarc_alignment: "0.005 USDT0",
  verify_message_auth: "0.01 USDT0",
  validate_arc_chain: "0.01 USDT0",
  detect_sender_spoofing: "0.015 USDT0",
  audit_header_chain: "0.015 USDT0",
  assess_attachment_surface: "0.02 USDT0",
  assess_link_surface: "0.02 USDT0",
  screen_domain_posture: "0.02 USDT0",
  attest_message_verdict: "0.03 USDT0",
};

export const FREE_TOOL_NAMES: string[] = [
  "envelope_capabilities",
  "estimate_cost",
  "validate_message_input",
  "parse_message_structure",
  "explain_auth_result",
  "check_dns_txt",
  "verify_envelope_report",
  "get_artifact",
];

export function createChallenge(toolName: string): X402Challenge {
  const cfg = getX402Config();
  const atomicAmount = TOOL_PRICES_ATOMIC[toolName] || "5000";
  const humanAmount = TOOL_PRICES_HUMAN[toolName] || "0.005 USDT0";

  const acceptReq: X402AcceptRequirement = {
    scheme: "exact",
    network: cfg.chain,
    asset: cfg.asset,
    amount: atomicAmount,
    payTo: cfg.payTo,
    maxTimeoutSeconds: 300,
    extra: {
      name: cfg.domainName,
      version: cfg.domainVersion,
    },
  };

  return {
    x402Version: 2,
    resource: {
      url: `${cfg.publicBaseUrl}/mcp`,
      description: "EVIDIQ Envelope — cryptographic verification of inbound messages: SPF, DKIM, DMARC and ARC on the raw message, sender-spoofing and lookalike-domain detection, header-chain forensics, and structural risk of attachments and links — with the DNS answers pinned into a signed report.",
      mimeType: "application/json",
    },
    accepts: [acceptReq],
    error: `Payment Required for tool '${toolName}'. Costs ${humanAmount}.`,
  };
}

export function encodeChallengeToBase64(challenge: X402Challenge): string {
  const { error, ...headerChallenge } = challenge;
  return Buffer.from(JSON.stringify(headerChallenge)).toString("base64");
}

export function getX402DiscoveryCatalog() {
  const cfg = getX402Config();
  return {
    x402Version: 2,
    resource: {
      url: `${cfg.publicBaseUrl}/mcp`,
      description: "EVIDIQ Envelope — cryptographic verification of inbound messages. Free tools (envelope_capabilities, estimate_cost, validate_message_input, parse_message_structure, explain_auth_result, check_dns_txt, verify_envelope_report, get_artifact) remain free.",
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: cfg.chain,
        asset: cfg.asset,
        amount: "5000",
        payTo: cfg.payTo,
        maxTimeoutSeconds: 300,
        extra: {
          name: cfg.domainName,
          version: cfg.domainVersion,
        },
      },
    ],
    pricing: [
      { tool: "verify_dkim", amount: "5000", usd: 0.005 },
      { tool: "check_dmarc_alignment", amount: "5000", usd: 0.005 },
      { tool: "verify_message_auth", amount: "10000", usd: 0.01 },
      { tool: "validate_arc_chain", amount: "10000", usd: 0.01 },
      { tool: "detect_sender_spoofing", amount: "15000", usd: 0.015 },
      { tool: "audit_header_chain", amount: "15000", usd: 0.015 },
      { tool: "assess_attachment_surface", amount: "20000", usd: 0.02 },
      { tool: "assess_link_surface", amount: "20000", usd: 0.02 },
      { tool: "screen_domain_posture", amount: "20000", usd: 0.02 },
      { tool: "attest_message_verdict", amount: "30000", usd: 0.03 },
      { tool: "envelope_capabilities", amount: "0", usd: 0, free: true },
      { tool: "estimate_cost", amount: "0", usd: 0, free: true },
      { tool: "validate_message_input", amount: "0", usd: 0, free: true },
      { tool: "parse_message_structure", amount: "0", usd: 0, free: true },
      { tool: "explain_auth_result", amount: "0", usd: 0, free: true },
      { tool: "check_dns_txt", amount: "0", usd: 0, free: true },
      { tool: "verify_envelope_report", amount: "0", usd: 0, free: true },
      { tool: "get_artifact", amount: "0", usd: 0, free: true },
    ],
    guidance: "Before paying, call the free validate_message_input tool first; envelope_capabilities and estimate_cost are also free.",
  };
}
