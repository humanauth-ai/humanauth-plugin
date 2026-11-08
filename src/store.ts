// Single-use receipts across hook processes. Each hook invocation is a fresh
// Node process, so the replay store has to live on disk. One file per receipt
// id, created with O_EXCL: the filesystem does the atomic claim.

import { mkdirSync, openSync, closeSync, writeSync, readFileSync, readdirSync, unlinkSync, statSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { ReplayStore } from "@humanauth/verifier";

interface ClaimFile {
  jti: string;
  idem: string | null;
  at: string;
  expires_at: number;
}

export class FileReplayStore implements ReplayStore {
  private readonly dir: string;

  constructor(dataDir: string) {
    this.dir = join(dataDir, "receipts");
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }

  private pathFor(jti: string): string {
    return join(this.dir, createHash("sha256").update(jti).digest("hex") + ".json");
  }

  async claim(jti: string, idempotencyKey: string | null, ttlSec: number): Promise<{ claimed: boolean; firstClaimAt: Date }> {
    this.prune();
    const file = this.pathFor(jti);
    const now = Date.now();
    const record: ClaimFile = { jti, idem: idempotencyKey, at: new Date(now).toISOString(), expires_at: now + ttlSec * 1000 };
    try {
      const fd = openSync(file, "wx", 0o600);
      try {
        writeSync(fd, JSON.stringify(record));
      } finally {
        closeSync(fd);
      }
      return { claimed: true, firstClaimAt: new Date(now) };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    let prev: ClaimFile | null = null;
    try {
      prev = JSON.parse(readFileSync(file, "utf8")) as ClaimFile;
    } catch {
      prev = null;
    }
    // A live claim under any key: refuse. The hook never passes an
    // idempotency key, so every re-presentation is a replay.
    return { claimed: false, firstClaimAt: prev ? new Date(prev.at) : new Date(0) };
  }

  /** Drop claim files whose receipt has long expired. Best effort. */
  private prune(): void {
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return;
    }
    const now = Date.now();
    for (const name of names) {
      const p = join(this.dir, name);
      try {
        const st = statSync(p);
        // Receipts are capped at 600 s validity plus skew; a day is generous.
        if (now - st.mtimeMs > 24 * 3600 * 1000) unlinkSync(p);
      } catch {
        /* ignore */
      }
    }
  }
}
