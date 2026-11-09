// Per-session memory for the policy. Each hook invocation is a fresh process,
// so what the session has written so far lives in a small JSON file in the
// plugin's data directory: when the hook first saw the session, and the
// absolute paths every Write/Edit targeted (gated or not). The policy uses it
// to gate `bash x.sh`, `make`, `npm run` and friends when the file they run
// was written in this session.

import { mkdirSync, readFileSync, writeFileSync, readdirSync, statSync, unlinkSync, renameSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";

export interface SessionState {
  session: string;
  /** Epoch ms of the first hook call in this session. */
  started_at: number;
  /** Absolute paths, oldest first, capped. */
  written: string[];
}

const MAX_WRITTEN = 2000;
const KEEP_MS = 7 * 24 * 3600 * 1000;

function fileFor(dataDir: string, sessionId: string): string {
  return join(dataDir, "sessions", createHash("sha256").update(sessionId).digest("hex").slice(0, 32) + ".json");
}

/** Load the session's state, creating it (started now) on first sight. */
export function loadSession(dataDir: string, sessionId: string, now: number = Date.now()): SessionState {
  const file = fileFor(dataDir, sessionId);
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as Partial<SessionState>;
    if (typeof parsed.started_at === "number" && Array.isArray(parsed.written)) {
      return { session: sessionId, started_at: parsed.started_at, written: parsed.written.filter((p) => typeof p === "string") };
    }
  } catch {
    /* first sight, or unreadable: start afresh */
  }
  const state: SessionState = { session: sessionId, started_at: now, written: [] };
  save(file, state);
  prune(join(dataDir, "sessions"), now);
  return state;
}

/** Remember that an edit tool targeted `filePath` (resolved against `cwd` when relative). */
export function recordWritten(dataDir: string, state: SessionState, filePath: string, cwd?: string): SessionState {
  const abs = filePath.startsWith("/") ? resolve(filePath) : cwd ? resolve(cwd, filePath) : null;
  if (!abs) return state;
  if (state.written.includes(abs)) return state;
  const written = [...state.written, abs].slice(-MAX_WRITTEN);
  const next = { ...state, written };
  save(fileFor(dataDir, state.session), next);
  return next;
}

function save(file: string, state: SessionState): void {
  try {
    mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
    renameSync(tmp, file);
  } catch {
    /* the decision does not depend on the record being saved */
  }
}

function prune(dir: string, now: number): void {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    try {
      const p = join(dir, name);
      if (now - statSync(p).mtimeMs > KEEP_MS) unlinkSync(p);
    } catch {
      /* ignore */
    }
  }
}
