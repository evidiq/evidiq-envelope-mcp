import Database from "better-sqlite3";

export interface StoredArtifact {
  digest: string;
  report: unknown;
  signature: string;
  signer: string;
  anchorRoot: string | null;
  anchorTx: string | null;
  createdAt: string;
}

export function openArtifactStore(dbPath: string): Database.Database {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS artifacts (
      digest TEXT PRIMARY KEY,
      report TEXT NOT NULL,
      signature TEXT NOT NULL,
      signer TEXT NOT NULL,
      anchor_root TEXT,
      anchor_tx TEXT,
      created_at TEXT NOT NULL
    );
  `);
  return db;
}

export function saveArtifact(
  db: Database.Database,
  artifact: Omit<StoredArtifact, "createdAt">,
): void {
  db.prepare(
    `INSERT OR REPLACE INTO artifacts
     (digest, report, signature, signer, anchor_root, anchor_tx, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    artifact.digest,
    JSON.stringify(artifact.report),
    artifact.signature,
    artifact.signer,
    artifact.anchorRoot,
    artifact.anchorTx,
    new Date().toISOString(),
  );
}

export function getArtifact(db: Database.Database, digest: string): StoredArtifact | null {
  const row = db.prepare(`SELECT * FROM artifacts WHERE digest = ?`).get(digest) as
    | {
        digest: string;
        report: string;
        signature: string;
        signer: string;
        anchor_root: string | null;
        anchor_tx: string | null;
        created_at: string;
      }
    | undefined;
  if (!row) return null;
  return {
    digest: row.digest,
    report: JSON.parse(row.report),
    signature: row.signature,
    signer: row.signer,
    anchorRoot: row.anchor_root,
    anchorTx: row.anchor_tx,
    createdAt: row.created_at,
  };
}
