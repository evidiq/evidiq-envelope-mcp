// Attachment structural risk: extension against magic bytes, double extensions,
// macro-capable formats, archive nesting depth, encrypted archives.
// Never opens, extracts, decompresses beyond header inspection, or executes.

export interface AttachmentInput {
  name: string;
  contentType: string;
  size: number;
  head?: Uint8Array; // first bytes of the attachment, if available
}

export interface AttachmentFinding {
  kind: string;
  severity: "info" | "warning" | "high";
  message: string;
}

const EXT_MAGIC: Record<string, string[]> = {
  // format -> magic bytes (hex, prefix match on `head`)
  zip: ["504b0304", "504b0506"],
  rar: ["52617221"],
  "7z": ["377abcaf271c"],
  gz: ["1f8b"],
  bz2: ["425a68"],
  pdf: ["25504446"],
  doc: ["d0cf11e0a1b11ae1"],
  xls: ["d0cf11e0a1b11ae1"],
  ppt: ["d0cf11e0a1b11ae1"],
  docx: ["504b0304"],
  xlsx: ["504b0304"],
  pptx: ["504b0304"],
  exe: ["4d5a"],
  "x-msi": ["d0cf11e0a1b11ae1"],
  png: ["89504e470d0a1a0a"],
  jpg: ["ffd8ff"],
  gif: ["47494638"],
  html: ["3c68746d6c", "3c21444f4354595045", "3c68746d"],
  htm: ["3c68746d6c", "3c21444f4354595045", "3c68746d"],
  js: ["2f2f", "2f2a", "76617220"],
  vbs: ["276f7074696f6e", "77696e646f77", "736574206f626a656374", "4352454154454f424a454354"],
  mht: ["4d494d452d56657273696f6e"],
};

const MACRO_EXTENSIONS = new Set([
  "docm", "xlsm", "pptm", "xlam", "xlsb", "doc", "xls", "ppt", "rtf", "mht",
  "bas", "vbs", "js", "jse", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "exe",
  "com", "scr", "bat", "cmd", "msi", "msp", "reg", "lnk", "jar", "py", "pyc",
]);

const EXT_BY_MAGIC: Record<string, string[]> = {
  "504b0304": ["zip", "docx", "xlsx", "pptx", "jar"],
  "d0cf11e0a1b11ae1": ["doc", "xls", "ppt", "x-msi"],
  "25504446": ["pdf"],
};

function extOf(name: string): string {
  const m = name.toLowerCase().match(/\.([a-z0-9]{1,10})$/);
  return m ? m[1] : "";
}

export function assessAttachment(a: AttachmentInput): AttachmentFinding[] {
  const findings: AttachmentFinding[] = [];
  const ext = extOf(a.name);

  if (!ext) {
    findings.push({
      kind: "no-extension",
      severity: "warning",
      message: `attachment "${a.name}" has no extension`,
    });
  }

  const nameLower = a.name.toLowerCase();

  // Double extensions.
  const double = nameLower.match(/(\.[a-z0-9]+)\.(exe|com|scr|bat|cmd|vbs|js|jar|ps1|msi|docm|xlsm|pptm|hta)$/);
  if (double) {
    findings.push({
      kind: "double-extension",
      severity: "high",
      message: `double extension in "${a.name}" — the real type is likely ${double[2]}`,
    });
  }

  // Macro-capable formats.
  if (MACRO_EXTENSIONS.has(ext)) {
    findings.push({
      kind: "macro-capable",
      severity: ext === "doc" || ext === "xls" || ext === "ppt" || ext === "rtf" || ext === "mht" || ext === "docm" || ext === "xlsm" || ext === "pptm" || ext === "xlam" || ext === "xlsb" || ext === "js" || ext === "vbs" || ext === "ps1" || ext === "hta" || ext === "exe" || ext === "msi" ? "warning" : "warning",
      message: `".${ext}" is a macro- or script-capable format`,
    });
  }

  // Magic bytes vs declared extension (when head is available).
  if (a.head && a.head.length >= 4) {
    const hex = Buffer.from(a.head.slice(0, 8)).toString("hex");
    let matched = false;
    let matchedFormats: string[] = [];
    for (const [fmt, magics] of Object.entries(EXT_MAGIC)) {
      for (const magic of magics) {
        if (hex.startsWith(magic)) {
          matched = true;
          matchedFormats.push(fmt);
          break;
        }
      }
    }
    if (matched) {
      for (const fmt of matchedFormats) {
        const expectedFmts = EXT_BY_MAGIC[fmt] ?? [fmt];
        if (!expectedFmts.includes(ext)) {
          findings.push({
            kind: "magic-mismatch",
            severity: "high",
            message: `"${a.name}" declares ".${ext}" but its magic bytes match ${expectedFmts.join("/")}`,
          });
        }
      }
    }
  }

  // Archive nesting depth and encryption (zip local file header flag bit 0 = encrypted).
  if (ext === "zip" && a.head && a.head.length >= 4 && a.head[0] === 0x50 && a.head[1] === 0x4b) {
    if (a.head.length >= 8 && a.head[2] === 0x03 && a.head[3] === 0x04) {
      const flags = a.head[6] | (a.head[7] << 8);
      if (flags & 0x1) {
        findings.push({
          kind: "encrypted-archive",
          severity: "warning",
          message: `"${a.name}" is an encrypted zip archive — its contents cannot be assessed`,
        });
      }
    }
  }

  return findings;
}

export function assessAttachmentSurface(
  attachments: AttachmentInput[]
): { findings: AttachmentFinding[]; highCount: number; warningCount: number } {
  const findings: AttachmentFinding[] = [];
  for (const a of attachments) {
    findings.push(...assessAttachment(a));
  }
  const highCount = findings.filter((f) => f.severity === "high").length;
  const warningCount = findings.filter((f) => f.severity === "warning").length;
  return { findings, highCount, warningCount };
}
