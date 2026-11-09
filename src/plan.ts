// The plan: the one flat object the approver's phone renders and signs, and
// the one the verifier re-hashes before the tool call is allowed. Everything
// the tool will act on is in it, derived from the validated tool input and
// nothing from the model's prose (no `description`). Session and call ids make
// every plan unique, so a receipt for one call can never match another.

import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

export interface HookInput {
  session_id: string;
  tool_name: string;
  tool_input: unknown;
  tool_use_id: string;
  cwd?: string;
  hook_event_name?: string;
  permission_mode?: string;
  agent_id?: string;
  agent_type?: string;
}

export type Plan = Record<string, string | number | boolean>;

export class PlanError extends Error {
  readonly code = "MALFORMED_TOOL_INPUT";
}

/** Longest value that travels in clear; longer values travel as hash + preview. */
export const INLINE_LIMIT = 4000;
export const PREVIEW_LIMIT = 600;
/** Platform limit on the serialized plan (CONTENT_LIMITS.max_plan_bytes). */
export const PLAN_BYTES_LIMIT = 32_768;

const ID = /^[A-Za-z0-9_.:-]{1,200}$/;

export function sha256(s: string): string {
  return "sha256:" + createHash("sha256").update(s, "utf8").digest("hex");
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string") throw new PlanError(`tool_input.${key} must be a string`);
  return v;
}

function optionalString(obj: Record<string, unknown>, key: string): string | undefined {
  const v = obj[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "string") throw new PlanError(`tool_input.${key} must be a string`);
  return v;
}

/** Longest tail shown when a value is too long to travel in clear. */
export const TAIL_LIMIT = 300;

/**
 * Characters that change what a human sees without changing what runs:
 * C0 controls other than tab/newline, DEL, zero-width and bidi controls.
 */
const DECEPTIVE_CHARS = new RegExp("[\\u0000-\\u0008\\u000b-\\u001f\\u007f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]");

const MASK = "•••";

/**
 * Credential-looking substrings, masked before the text leaves the machine.
 * The approver sees the shape of the secret, never its value, and the hash of
 * the unmasked text travels beside it so the receipt still binds the real
 * command. Order matters: structured forms first, bare tokens last.
 */
const SECRET_PATTERNS: ReadonlyArray<[RegExp, string | ((...m: string[]) => string)]> = [
  // URL userinfo: scheme://user:pass@host
  [/(\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@'"]+):([^\s@'"]+)@/gi, `$1:${MASK}@`],
  // Authorization headers and bearer tokens
  [/(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}/g, `$1${MASK}`],
  [/(\bAuthorization:\s*(?:Basic|Token|token|Bearer)?\s*)[A-Za-z0-9._~+/=-]{8,}/g, `$1${MASK}`],
  // key=value forms: password=, PASSWORD=, api_key=, token=, secret=, with optional quotes and -D/--define prefixes
  [/(\b[A-Za-z_]*(?:password|passwd|pwd|secret|token|api_?key|access_key|private_key|client_secret)[A-Za-z_]*\s*[=:]\s*["']?)(?!["'\s])([^\s"'&;,]+)/gi, (_m, pre) => `${pre}${MASK}`],
  // mysql/psql style inline passwords: -pSECRET, --password=SECRET, --password SECRET, PGPASSWORD=
  [/(\b(?:mysql|mariadb|mysqladmin|mysqldump|mysqlimport|psql|pg_dump|pg_restore|mongosh|mongo|redis-cli)\b[^|;&\n]*?\s-p)(?=\S)([^\s]+)/g, `$1${MASK}`],
  [/(--password[= ])(?!["'\s])(\S+)/g, `$1${MASK}`],
  [/(\bredis-cli\b[^|;&\n]*?\s-a\s+)(\S+)/g, `$1${MASK}`],
  // Well-known token shapes
  [/\b(gh[pousr])_[A-Za-z0-9]{20,}\b/g, `$1_${MASK}`],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, `github_pat_${MASK}`],
  [/\bsk_(live|test)_[A-Za-z0-9]{8,}\b/g, `sk_$1_${MASK}`],
  [/\brk_(live|test)_[A-Za-z0-9]{8,}\b/g, `rk_$1_${MASK}`],
  [/\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b/g, `sk-${MASK}`],
  [/\bha_(live|test)_[A-Za-z0-9_-]{8,}\b/g, `ha_$1_${MASK}`],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, `xox${MASK}`],
  [/\bAKIA[0-9A-Z]{16}\b/g, `AKIA${MASK}`],
  [/\bAIza[0-9A-Za-z_-]{30,}\b/g, `AIza${MASK}`],
  [/\bya29\.[0-9A-Za-z_-]{20,}\b/g, `ya29.${MASK}`],
  [/\bglpat-[A-Za-z0-9_-]{16,}\b/g, `glpat-${MASK}`],
  [/\bnpm_[A-Za-z0-9]{30,}\b/g, `npm_${MASK}`],
  // JWTs: three base64url segments, 40+ chars in all
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, (m) => (m.length >= 40 ? `eyJ${MASK}` : m)],
  // PEM blocks
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, `-----BEGIN PRIVATE KEY-----${MASK}-----END PRIVATE KEY-----`],
];

/** Mask credential-looking substrings. Returns the text and whether anything changed. */
export function maskSecrets(text: string): { masked: string; changed: boolean } {
  let out = text;
  for (const [re, rep] of SECRET_PATTERNS) {
    out = typeof rep === "string" ? out.replace(re, rep) : out.replace(re, rep as (...args: string[]) => string);
  }
  return { masked: out, changed: out !== text };
}

/**
 * Put a text value in the plan. Short values travel in clear, long ones as
 * hash + head + tail. Credentials are masked in whatever travels; the plan
 * then carries `<name>_masked: true` and a hash of the unmasked text
 * (`<name>_sha256` for long values, `<name>_secret_sha256` for inline ones),
 * so the approval still binds the real text while the platform never sees it.
 */
function textFields(plan: Plan, name: string, value: string): void {
  const { masked, changed } = maskSecrets(value);
  if (value.length <= INLINE_LIMIT) {
    plan[name] = masked;
    if (changed) plan[`${name}_secret_sha256`] = sha256(value);
  } else {
    // Head and tail both shown: a payload hidden at the end of a long
    // command still reaches the approver's eyes, and the hash binds all of it.
    plan[`${name}_sha256`] = sha256(value);
    plan[`${name}_chars`] = value.length;
    plan[`${name}_preview`] = masked.slice(0, PREVIEW_LIMIT);
    plan[`${name}_tail`] = masked.slice(-TAIL_LIMIT);
  }
  if (changed) plan[`${name}_masked`] = true;
  if (DECEPTIVE_CHARS.test(value)) plan[`${name}_has_control_chars`] = true;
}

/** Build the plan for a tool call, or throw PlanError when the input is not what the tool expects. */
export function buildPlan(input: HookInput): Plan {
  if (typeof input.session_id !== "string" || !ID.test(input.session_id)) {
    throw new PlanError("session_id missing or malformed");
  }
  if (typeof input.tool_use_id !== "string" || !ID.test(input.tool_use_id)) {
    throw new PlanError("tool_use_id missing or malformed");
  }
  if (typeof input.tool_name !== "string" || input.tool_name.length === 0 || input.tool_name.length > 200) {
    throw new PlanError("tool_name missing or malformed");
  }
  const raw = input.tool_input;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PlanError("tool_input must be an object");
  }
  const obj = raw as Record<string, unknown>;

  const plan: Plan = {
    tool: input.tool_name,
    session: input.session_id,
    call: input.tool_use_id,
  };
  if (typeof input.cwd === "string" && input.cwd.length > 0) plan.cwd = input.cwd.slice(0, 1000);
  if (typeof input.agent_id === "string" && input.agent_id.length > 0) plan.agent = input.agent_id.slice(0, 200);

  switch (input.tool_name) {
    case "Bash": {
      const command = requireString(obj, "command");
      if (command.trim().length === 0) throw new PlanError("tool_input.command is empty");
      textFields(plan, "command", command);
      if (obj.run_in_background === true) plan.background = true;
      // Everything else Claude Code lets the model set on a Bash call is
      // bound too, so a receipt for a sandboxed call cannot run it unsandboxed.
      if (obj.dangerouslyDisableSandbox === true) plan.sandbox_disabled = true;
      if (typeof obj.timeout === "number" && Number.isFinite(obj.timeout)) plan.timeout_ms = obj.timeout;
      break;
    }
    case "Write": {
      const filePath = requireString(obj, "file_path");
      const content = requireString(obj, "content");
      plan.file_path = filePath;
      plan.bytes = Buffer.byteLength(content, "utf8");
      // The hash is over the real content; what travels is masked.
      plan.content_sha256 = sha256(content);
      const { masked, changed } = maskSecrets(content);
      // Full content in clear up to the inline limit; beyond that head, tail and length.
      if (content.length <= INLINE_LIMIT) {
        plan.content = masked;
      } else {
        plan.content_chars = content.length;
        plan.content_preview = masked.slice(0, PREVIEW_LIMIT);
        plan.content_tail = masked.slice(-TAIL_LIMIT);
      }
      if (changed) plan.content_masked = true;
      if (DECEPTIVE_CHARS.test(content)) plan.content_has_control_chars = true;
      break;
    }
    case "Edit": {
      const filePath = requireString(obj, "file_path");
      const oldS = requireString(obj, "old_string");
      const newS = requireString(obj, "new_string");
      plan.file_path = filePath;
      plan.old_sha256 = sha256(oldS);
      plan.new_sha256 = sha256(newS);
      const oldM = maskSecrets(oldS);
      const newM = maskSecrets(newS);
      plan.old_preview = oldM.masked.slice(0, PREVIEW_LIMIT);
      plan.new_preview = newM.masked.slice(0, PREVIEW_LIMIT);
      if (oldM.changed) plan.old_masked = true;
      if (newM.changed) plan.new_masked = true;
      plan.replace_all = obj.replace_all === true;
      break;
    }
    default: {
      // MultiEdit, NotebookEdit, any other built-in, and every MCP tool: bind
      // the whole input. The phone shows the canonical JSON when it fits.
      const fp = optionalString(obj, "file_path") ?? optionalString(obj, "notebook_path");
      if (fp) plan.file_path = fp;
      const canonical = canonicalize(obj);
      if (canonical === undefined) throw new PlanError("tool_input is not JSON-serialisable");
      textFields(plan, "input", canonical);
      if (!("input" in plan)) plan.input_sha256 = sha256(canonical);
      break;
    }
  }

  const bytes = Buffer.byteLength(JSON.stringify(plan), "utf8");
  if (bytes > PLAN_BYTES_LIMIT) {
    // Only reachable if a path or preview is absurd; refuse rather than trim silently.
    throw new PlanError(`plan is ${bytes} bytes, over the ${PLAN_BYTES_LIMIT} byte limit`);
  }
  return plan;
}

/** sha256 over RFC 8785 canonical JSON, exactly as the platform computes plan_hash. */
export function planHash(plan: Plan): string {
  const canonical = canonicalize(plan);
  if (canonical === undefined) throw new PlanError("plan is not JSON-serialisable");
  return sha256(canonical);
}

/** The caption the phone shows above the plan rows. Derived, not model prose. */
export function describe(input: HookInput, plan: Plan): string {
  const where = typeof input.cwd === "string" && input.cwd ? ` in ${input.cwd.split("/").filter(Boolean).pop() ?? input.cwd}` : "";
  // The caption is not hashed, so it can be made safe to read: control and
  // bidi characters become a visible marker naming the code point, so the
  // approver can see what was there (⟨U+202E⟩ is a right-to-left override).
  const clip = (s: string, n = 140) => {
    const clean = s.replace(new RegExp(DECEPTIVE_CHARS.source, "g"), (ch) => `⟨U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟩`);
    return clean.length > n ? clean.slice(0, n - 1) + "…" : clean;
  };
  switch (input.tool_name) {
    case "Bash": {
      const cmd = typeof plan.command === "string" ? plan.command : String(plan.command_preview ?? "");
      return clip(`Claude Code wants to run${where}: ${cmd.replace(/\s+/g, " ").trim()}`);
    }
    case "Write":
      return clip(`Claude Code wants to write ${plan.bytes} bytes to ${plan.file_path}`);
    case "Edit":
    case "MultiEdit":
    case "NotebookEdit":
      return clip(`Claude Code wants to edit ${plan.file_path ?? "a file"}${where}`);
    default:
      return clip(`Claude Code wants to call ${input.tool_name}${where}`);
  }
}
