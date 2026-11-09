// One PreToolUse decision: gate? → ask the phone → verify the receipt → allow.
// Everything that is not a verified approval of this exact call is a deny.

import { appendFileSync, mkdirSync, writeFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  HumanAuthVerifier,
  ApprovalDeniedError,
  ApprovalExpiredError,
  ApprovalTimeoutError,
  RequestPollError,
  HumanAuthVerifierError,
  type VerifiedReceipt,
} from "@humanauth/verifier";
import type { JWK } from "jose";
import { evaluate, EDIT_TOOLS, type Scope, type PolicyDecision } from "./policy.js";
import { buildPlan, describe, planHash, PlanError, type HookInput, type Plan } from "./plan.js";
import { FileReplayStore } from "./store.js";
import { loadSession, recordWritten, type SessionState } from "./session.js";

export interface HookConfig {
  apiKey?: string;
  /** `hu_…` or `grp_…` */
  approver?: string;
  scope: Scope;
  extraPattern?: RegExp | null;
  /** The compile error of `extra_pattern`, when it is not a valid regular expression. Every non-read-only call is then refused. */
  extraPatternError?: string | null;
  ttlSeconds: number;
  platformUrl: string;
  /** Expected `iss` on receipts. Defaults to platformUrl. */
  issuer?: string;
  /** What to do when the platform cannot be reached or the plugin is misconfigured. Decisions are never affected. */
  onError: "deny" | "ask";
  /** Lowest approver assurance accepted, whatever the tenant policy stamped. */
  minAssurance: "tap" | "biometric" | "elevated";
  /** Only loopback platform URLs may be plain http unless this is set (development). */
  allowInsecureUrl: boolean;
  /** Directories on this process's PATH; writes into them are gated in scope `destructive`. */
  pathDirs: string[];
  dataDir: string;
}

const ASSURANCE_RANK: Record<string, number> = { tap: 0, biometric: 1, elevated: 2, hardware: 2 };

export interface HookDeps {
  fetch: typeof fetch;
  /** Inline JWKS for tests; production resolves `${platformUrl}/.well-known/jwks.json`. */
  jwks?: { keys: JWK[] };
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  pollIntervalMs?: number;
  /** Where the audit line goes; defaults to `${dataDir}/audit.jsonl`. */
  audit?: (entry: AuditEntry) => void;
}

export interface HookOutput {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "allow" | "deny" | "ask";
    permissionDecisionReason: string;
    /**
     * Text Claude Code adds to the model's context next to the tool result.
     * On `allow`, permissionDecisionReason goes to the debug log only (the
     * model saw "no permission decision reason" in the 2026-11-09 live
     * test), so the receipt line travels here too. Absent on deny and ask,
     * where the reason itself reaches the model or the user.
     */
    additionalContext?: string;
  };
}

export interface AuditEntry {
  at: string;
  session: string;
  call: string;
  tool: string;
  action: string;
  matched?: string;
  plan_hash?: string;
  request_id?: string;
  /**
   * `pending` is written the moment the request exists on the platform, the
   * final decision when the wait ends. Two lines per gated call keep the
   * file chronological (a 300 s expiry is no longer logged after calls that
   * finished earlier) and leave a trace if the hook dies mid-wait.
   */
  decision: "pending" | "allow" | "deny" | "ask";
  reason: string;
  receipt_id?: string;
  approvers?: string[];
  /** Path, relative to the data dir, of the retained receipt and plan. */
  evidence?: string;
  /** Answers the platform refused (4xx on POST /v1/respond) while this call waited, oldest first. */
  respond_attempts?: RespondAttempt[];
}

/** One rejected answer, as GET /v1/requests/:id reports it. */
export interface RespondAttempt {
  at: string;
  http_status: number;
  reason: string;
}

function readRespondAttempts(v: unknown): RespondAttempt[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: RespondAttempt[] = [];
  for (const a of v as Array<Record<string, unknown>>) {
    if (!a || typeof a !== "object") continue;
    if (typeof a.at !== "string" || typeof a.http_status !== "number" || typeof a.reason !== "string") continue;
    out.push({ at: a.at, http_status: a.http_status, reason: a.reason.slice(0, 300) });
  }
  return out;
}

/** "an approval attempt was rejected at <time> (HTTP 401: …)", newest attempt, with a count when there were several. */
function describeRejected(attempts: RespondAttempt[]): string | null {
  if (attempts.length === 0) return null;
  const newest = attempts.reduce((a, b) => (Date.parse(b.at) >= Date.parse(a.at) ? b : a));
  const head = attempts.length === 1 ? "an approval attempt was rejected" : `${attempts.length} approval attempts were rejected, the latest`;
  return `${head} at ${newest.at} (HTTP ${newest.http_status}: ${newest.reason})`;
}

const SCOPES: ReadonlySet<string> = new Set(["destructive", "all", "off"]);
const TTL_MIN = 30;
const TTL_MAX = 3600;

function pick(env: NodeJS.ProcessEnv, key: string): string | undefined {
  const a = env[`CLAUDE_PLUGIN_OPTION_${key}`];
  if (a !== undefined && a !== "") return a;
  const b = env[`HUMANAUTH_${key}`];
  if (b !== undefined && b !== "") return b;
  return undefined;
}

/** Plugin user config (CLAUDE_PLUGIN_OPTION_*) with HUMANAUTH_* fallbacks for headless runs. */
export function configFromEnv(env: NodeJS.ProcessEnv): HookConfig {
  const scopeRaw = pick(env, "SCOPE") ?? "destructive";
  const scope = (SCOPES.has(scopeRaw) ? scopeRaw : "destructive") as Scope;
  let extraPattern: RegExp | null = null;
  let extraPatternError: string | null = null;
  const extra = pick(env, "EXTRA_PATTERN");
  if (extra) {
    try {
      extraPattern = new RegExp(extra);
    } catch (e) {
      // Not swallowed: an operator who typed a broken pattern meant to gate
      // more, so until it is fixed every non-read-only call is refused.
      extraPattern = null;
      extraPatternError = e instanceof Error ? e.message : String(e);
    }
  }
  const ttlRaw = Number(pick(env, "TTL_SECONDS") ?? 300);
  const ttlSeconds = Number.isFinite(ttlRaw) ? Math.min(TTL_MAX, Math.max(TTL_MIN, Math.floor(ttlRaw))) : 300;
  const platformUrl = (pick(env, "PLATFORM_URL") ?? "https://api.humanauth.ai").replace(/\/+$/, "");
  const onError = pick(env, "ON_ERROR") === "ask" ? "ask" : "deny";
  const minRaw = pick(env, "MIN_ASSURANCE") ?? "biometric";
  const minAssurance = (minRaw in ASSURANCE_RANK && minRaw !== "hardware" ? minRaw : "biometric") as HookConfig["minAssurance"];
  const dataDir = env.CLAUDE_PLUGIN_DATA && env.CLAUDE_PLUGIN_DATA !== "" ? env.CLAUDE_PLUGIN_DATA : join(homedir(), ".humanauth", "claude-plugin");
  const pathDirs = (env.PATH ?? "")
    .split(":")
    .map((d) => d.trim().replace(/\/+$/, ""))
    .filter((d) => d.startsWith("/"));
  return {
    apiKey: pick(env, "API_KEY"),
    approver: pick(env, "APPROVER"),
    scope,
    extraPattern,
    extraPatternError,
    ttlSeconds,
    platformUrl,
    issuer: pick(env, "ISSUER") ?? platformUrl,
    onError,
    minAssurance,
    allowInsecureUrl: env.HUMANAUTH_ALLOW_INSECURE_URL === "1",
    pathDirs,
    dataDir,
  };
}

function isLoopback(url: string): boolean {
  try {
    const h = new URL(url).hostname;
    return h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h === "::1" || h.endsWith(".localhost");
  } catch {
    return false;
  }
}

/** Keep the verified receipt and the plan it was checked against, so the allow can be re-verified later without the platform. */
function persistEvidence(dataDir: string, jti: string, record: unknown): string | undefined {
  try {
    const dir = join(dataDir, "evidence");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const name = createHash("sha256").update(jti).digest("hex").slice(0, 32) + ".json";
    writeFileSync(join(dir, name), JSON.stringify(record, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    return `evidence/${name}`;
  } catch {
    return undefined;
  }
}

function out(decision: HookOutput["hookSpecificOutput"]["permissionDecision"], reason: string): HookOutput {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
      permissionDecisionReason: reason,
      ...(decision === "allow" ? { additionalContext: reason } : {}),
    },
  };
}

function mtimeOrNull(p: string): number | null {
  try {
    return statSync(p).mtimeMs;
  } catch {
    return null;
  }
}

/** HTTP statuses on the poll that mean "try again": the platform or the network, not the request. */
function retryablePoll(status: number): boolean {
  return status >= 500 || status === 404 || status === 410 || status === 429 || status === 408;
}

function defaultAudit(dataDir: string): (e: AuditEntry) => void {
  return (e) => {
    try {
      mkdirSync(dataDir, { recursive: true, mode: 0o700 });
      appendFileSync(join(dataDir, "audit.jsonl"), JSON.stringify(e) + "\n", { mode: 0o600 });
    } catch {
      /* the decision stands even if the local log cannot be written */
    }
  };
}

interface AuthorizeResponse {
  request_id: string;
  ttl: number;
  expires_at: string;
}

/** GET /v1/requests/:id, the fields the hook reads. */
interface PollBody {
  status?: string;
  result?: string;
  receipt_jws?: string | null;
  respond_attempts?: unknown;
  tenant?: { tenant_id?: string };
  tenant_id?: string;
}

/**
 * Decide one tool call. Returns null when the call is not gated (Claude Code
 * then applies its normal permission flow), otherwise an allow/deny/ask.
 */
export async function runHook(input: HookInput, cfg: HookConfig, deps: HookDeps): Promise<HookOutput | null> {
  const cwd = typeof input.cwd === "string" && input.cwd.length > 0 ? input.cwd : undefined;
  // What this session has written so far, so a script the model wrote and
  // then runs is gated at the run. Recorded for every edit tool call, gated
  // or not; the hook sees them all.
  let session: SessionState | undefined;
  if (cfg.scope !== "off" && typeof input.session_id === "string" && input.session_id.length > 0) {
    try {
      session = loadSession(cfg.dataDir, input.session_id);
    } catch {
      session = undefined;
    }
  }
  const policy: PolicyDecision = evaluate(input.tool_name, input.tool_input, {
    scope: cfg.scope,
    extraPattern: cfg.extraPattern,
    extraPatternError: cfg.extraPatternError,
    pathDirs: cfg.pathDirs,
    cwd,
    writtenPaths: session ? new Set(session.written) : undefined,
    sessionStartMs: session?.started_at,
    fs: { mtimeMs: (p) => mtimeOrNull(p) },
  });
  if (session && EDIT_TOOLS.has(input.tool_name)) {
    const ti = (input.tool_input ?? {}) as Record<string, unknown>;
    const fp = ti.file_path ?? ti.notebook_path;
    if (typeof fp === "string" && fp.length > 0) {
      try {
        recordWritten(cfg.dataDir, session, fp, cwd);
      } catch {
        /* best effort */
      }
    }
  }
  if (!policy.gated) return null;

  // Under bypassPermissions and dontAsk nobody answers an `ask`; Claude Code
  // treats it as approved or denied without a human. Only deny is safe there.
  const unattended = input.permission_mode === "bypassPermissions" || input.permission_mode === "dontAsk";
  if (unattended && cfg.onError === "ask") cfg = { ...cfg, onError: "deny" };

  const audit = deps.audit ?? defaultAudit(cfg.dataDir);
  const base: Omit<AuditEntry, "decision" | "reason"> = {
    at: new Date().toISOString(),
    session: String(input.session_id ?? ""),
    call: String(input.tool_use_id ?? ""),
    tool: String(input.tool_name ?? ""),
    action: policy.action,
    matched: policy.matched,
  };
  // Answers the platform refused while we waited (a 401 on the device proof,
  // say), as GET /v1/requests/:id reports them. Without these a rejected
  // approval is indistinguishable from nobody answering (live test
  // 2026-11-09). Every outcome's audit line carries whatever was seen.
  let rejected: RespondAttempt[] = [];
  const finish = (decision: HookOutput["hookSpecificOutput"]["permissionDecision"], reason: string, extra: Partial<AuditEntry> = {}): HookOutput => {
    // Each line carries the time it was written, so the allow/deny line is
    // stamped at decision time, not copied from the pending line.
    audit({ ...base, at: new Date().toISOString(), ...(rejected.length > 0 ? { respond_attempts: rejected } : {}), ...extra, decision, reason });
    return out(decision, `HumanAuth: ${reason}`);
  };
  const fail = (reason: string, extra: Partial<AuditEntry> = {}): HookOutput =>
    finish(cfg.onError, `${reason}${cfg.onError === "ask" ? " (falling back to the keyboard prompt)" : ""}`, extra);

  if (policy.refuse) {
    // A misconfiguration the operator must fix: refused outright, never `ask`.
    return finish("deny", `${policy.refuse}. Fix extra_pattern under /plugin → humanauth → Configure (or HUMANAUTH_EXTRA_PATTERN); until then every non-read-only call is refused`);
  }

  if (!cfg.apiKey || !cfg.approver) {
    // Freshly installed and never configured: hand the call back to the
    // ordinary keyboard prompt rather than refusing everything consequential
    // in every session. Headless `-p` runs treat `ask` as a deny, and the
    // unattended modes above already forced `deny`, so nothing becomes
    // fail-open where nobody is watching.
    const decision = unattended ? "deny" : "ask";
    return finish(decision, `plugin is not configured${decision === "ask" ? ", falling back to the keyboard prompt" : ""}. Set api_key and approver under /plugin → humanauth → Configure, or HUMANAUTH_API_KEY and HUMANAUTH_APPROVER in the environment`);
  }
  if (!/^(hu|grp)_[A-Za-z0-9_-]{2,80}$/.test(cfg.approver)) {
    return fail(`approver "${cfg.approver}" is not a hu_… or grp_… id`);
  }
  if (!cfg.platformUrl.startsWith("https://") && !(isLoopback(cfg.platformUrl) || cfg.allowInsecureUrl)) {
    return fail(`platform_url ${cfg.platformUrl} is not https; receipts over plain http cannot be trusted`);
  }

  let plan: Plan;
  try {
    plan = buildPlan(input);
  } catch (e) {
    const msg = e instanceof PlanError ? e.message : "tool input could not be validated";
    return finish("deny", `refused: ${msg}`);
  }
  const hash = planHash(plan);
  base.plan_hash = hash;

  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${cfg.apiKey}`, Accept: "application/json" };
  const target = cfg.approver.startsWith("grp_") ? { group_id: cfg.approver } : { human_id: cfg.approver };

  let authorize: AuthorizeResponse;
  try {
    const res = await deps.fetch(`${cfg.platformUrl}/v1/authorize`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        ...target,
        action: policy.action,
        description: describe(input, plan),
        severity: "high",
        intent: "authorize",
        plan,
        ttl: cfg.ttlSeconds,
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return fail(`could not create the approval request (HTTP ${res.status}${body ? `: ${body.slice(0, 200)}` : ""})`);
    }
    authorize = (await res.json()) as AuthorizeResponse;
    if (typeof authorize.request_id !== "string") return fail("platform returned no request_id");
  } catch (e) {
    return fail(`could not reach ${cfg.platformUrl} (${(e as Error).message})`);
  }
  base.request_id = authorize.request_id;
  // The request exists; say so now. The final line comes when the wait ends,
  // so a crash or kill in between still leaves the request id on disk.
  audit({ ...base, at: new Date().toISOString(), decision: "pending", reason: `awaiting approval from ${cfg.approver} for up to ${cfg.ttlSeconds}s` });

  // Poll to a terminal state, then verify. Same loop as the verifier's
  // waitForReceipt, kept here so the raw receipt JWS can be retained as
  // evidence after verification. The receipt's `aud` is the tenant id; the
  // platform tells us ours on the request it just created, over the same
  // authenticated channel, so the first successful poll also supplies it.
  //
  // A poll that fails (network error, 5xx, 429) is not a denial: the request
  // is still live on the platform and the approver may be tapping right now.
  // Failures are retried with the same backoff until the deadline; only a
  // deadline that passes while still failing refuses the call, naming the
  // last error. Other 4xx mean the request itself is wrong and fail at once.
  let verified: VerifiedReceipt;
  let receiptJws = "";
  let tenantId: string | undefined;
  try {
    const now = deps.now ?? (() => Date.now());
    const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const deadline = now() + cfg.ttlSeconds * 1000 + 15_000;
    let interval = deps.pollIntervalMs ?? 2_000;
    const url = `${cfg.platformUrl}/v1/requests/${encodeURIComponent(authorize.request_id)}`;
    let lastError: string | null = null;
    let consecutiveFailures = 0;
    let lastStatus: string | undefined;
    for (;;) {
      let body: PollBody | null = null;
      try {
        const res = await deps.fetch(url, { headers });
        if (res.ok) {
          body = (await res.json()) as PollBody;
        } else if (retryablePoll(res.status)) {
          lastError = `HTTP ${res.status}`;
        } else {
          throw new RequestPollError(`GET /v1/requests/${authorize.request_id} → HTTP ${res.status}`);
        }
      } catch (e) {
        if (e instanceof RequestPollError) throw e;
        lastError = (e as Error).message;
      }
      if (body) {
        consecutiveFailures = 0;
        lastError = null;
        if (!tenantId) {
          // GET /v1/requests/:id nests it as `tenant.tenant_id`; older
          // platforms (and the list endpoint) put it at the top level.
          const found = body.tenant?.tenant_id ?? body.tenant_id;
          if (typeof found !== "string" || found.length === 0) return fail("approval request carries no tenant_id");
          tenantId = found;
        }
        rejected = readRespondAttempts(body.respond_attempts) ?? rejected;
        lastStatus = body.status;
        if (body.status === "expired") throw new ApprovalExpiredError(`request ${authorize.request_id} expired`);
        if (body.status === "decided") {
          if (body.result === "denied") throw new ApprovalDeniedError(`request ${authorize.request_id} was denied`);
          if (typeof body.receipt_jws === "string" && body.receipt_jws.length > 0) {
            receiptJws = body.receipt_jws;
            break;
          }
        }
      } else {
        consecutiveFailures++;
      }
      if (now() >= deadline) {
        if (lastError !== null) {
          throw new RequestPollError(`GET /v1/requests/${authorize.request_id} kept failing until the deadline (${consecutiveFailures} consecutive failures, last error: ${lastError})`);
        }
        throw new ApprovalTimeoutError(`request ${authorize.request_id} still ${lastStatus ?? "pending"}`);
      }
      await sleep(Math.max(0, Math.min(interval, deadline - now())));
      interval = Math.min(Math.floor(interval * 1.5), 15_000);
    }
    const verifier = new HumanAuthVerifier({
      audience: tenantId!,
      issuer: cfg.issuer ?? cfg.platformUrl,
      ...(deps.jwks ? { jwks: deps.jwks } : { jwksUri: `${cfg.platformUrl}/.well-known/jwks.json` }),
      replayStore: new FileReplayStore(cfg.dataDir),
    });
    verified = await verifier.requireReceipt(receiptJws, {
      action: policy.action,
      plan,
      idempotencyKey: null, // one call, one receipt, one use
    });
  } catch (e) {
    if (e instanceof ApprovalDeniedError) {
      return finish("deny", `the approver denied this ${input.tool_name} call (request ${authorize.request_id}). Do not retry it, split it up, or reach the same effect another way; tell the user it was denied.`);
    }
    if (e instanceof ApprovalExpiredError || e instanceof ApprovalTimeoutError) {
      // A rejected answer must not read as a timeout: name it, newest first.
      const rejectedLine = describeRejected(rejected);
      return finish(
        "deny",
        `${rejectedLine ? `${rejectedLine}; ` : ""}nobody approved this ${input.tool_name} call within ${cfg.ttlSeconds}s (request ${authorize.request_id}). Not approved means denied; do not retry on your own.${rejectedLine ? " Tell the user their approval was rejected by the platform, not ignored." : ""}`,
      );
    }
    if (e instanceof RequestPollError) {
      return fail(`could not poll the approval request (${e.message})`);
    }
    if (e instanceof HumanAuthVerifierError) {
      return finish("deny", `the receipt for request ${authorize.request_id} did not verify (${e.code}: ${e.message}). The call is refused.`);
    }
    return fail(`verification failed (${(e as Error).message})`);
  }

  // Bind the receipt to this request and to the configured approver, not
  // just to a plan that happens to hash the same.
  if (verified.raw.ha.request_id !== authorize.request_id) {
    return finish("deny", `receipt ${verified.raw.jti} is for request ${verified.raw.ha.request_id}, not ${authorize.request_id}`);
  }
  const approvers = verified.approvers.map((a) => a.huid);
  if (cfg.approver.startsWith("hu_")) {
    const strangers = approvers.filter((h) => h !== cfg.approver);
    if (strangers.length > 0 || approvers.length === 0) {
      return finish("deny", `receipt was approved by ${approvers.join(", ") || "nobody"}; this plugin accepts approvals only from ${cfg.approver}`, {
        receipt_id: verified.raw.jti,
        approvers,
      });
    }
  }
  if (cfg.approver.startsWith("grp_")) {
    // A group receipt must carry the requirement it was decided under, so
    // the verifier has already checked threshold and membership against it.
    const approval = verified.raw.ha.approval;
    if (!approval || !Array.isArray(approval.required_principals) || approval.required_principals.length === 0) {
      return finish("deny", `receipt ${verified.raw.jti} for group ${cfg.approver} names no required principals, so membership cannot be checked here`, {
        receipt_id: verified.raw.jti,
        approvers,
      });
    }
  }
  const weak = verified.approvers.filter((a) => (ASSURANCE_RANK[a.assurance] ?? -1) < ASSURANCE_RANK[cfg.minAssurance]!);
  if (weak.length > 0) {
    return finish(
      "deny",
      `receipt ${verified.raw.jti} was approved with "${weak.map((a) => a.assurance).join(", ")}" assurance; this plugin requires at least "${cfg.minAssurance}" (min_assurance)`,
      { receipt_id: verified.raw.jti, approvers },
    );
  }
  if (verified.replay) {
    return finish("deny", `receipt ${verified.raw.jti} was already used`, { receipt_id: verified.raw.jti, approvers });
  }

  const evidence = persistEvidence(cfg.dataDir, verified.raw.jti, {
    verified_at: new Date().toISOString(),
    request_id: authorize.request_id,
    receipt_id: verified.raw.jti,
    action: policy.action,
    plan,
    plan_hash: hash,
    receipt_jws: receiptJws,
    jwks_uri: deps.jwks ? null : `${cfg.platformUrl}/.well-known/jwks.json`,
    approvers: verified.approvers,
  });

  const who = verified.approvers.map((a) => `${a.huid} (${a.assurance})`).join(", ");
  return finish(
    "allow",
    `approved by ${who} · receipt ${verified.raw.jti} · plan ${hash.slice(0, 23)}… · request ${authorize.request_id}`,
    { receipt_id: verified.raw.jti, approvers, evidence },
  );
}
