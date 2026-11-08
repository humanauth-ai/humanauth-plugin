// One PreToolUse decision: gate? → ask the phone → verify the receipt → allow.
// Everything that is not a verified approval of this exact call is a deny.

import { appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  HumanAuthVerifier,
  ApprovalDeniedError,
  ApprovalExpiredError,
  ApprovalTimeoutError,
  HumanAuthVerifierError,
  type VerifiedReceipt,
} from "@humanauth/verifier";
import type { JWK } from "jose";
import { evaluate, type Scope, type PolicyDecision } from "./policy.js";
import { buildPlan, describe, planHash, PlanError, type HookInput, type Plan } from "./plan.js";
import { FileReplayStore } from "./store.js";

export interface HookConfig {
  apiKey?: string;
  /** `hu_…` or `grp_…` */
  approver?: string;
  scope: Scope;
  extraPattern?: RegExp | null;
  ttlSeconds: number;
  platformUrl: string;
  /** Expected `iss` on receipts. Defaults to platformUrl. */
  issuer?: string;
  /** What to do when the platform cannot be reached or the plugin is misconfigured. Decisions are never affected. */
  onError: "deny" | "ask";
  dataDir: string;
}

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
  decision: "allow" | "deny" | "ask";
  reason: string;
  receipt_id?: string;
  approvers?: string[];
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
  const extra = pick(env, "EXTRA_PATTERN");
  if (extra) {
    try {
      extraPattern = new RegExp(extra);
    } catch {
      extraPattern = null;
    }
  }
  const ttlRaw = Number(pick(env, "TTL_SECONDS") ?? 300);
  const ttlSeconds = Number.isFinite(ttlRaw) ? Math.min(TTL_MAX, Math.max(TTL_MIN, Math.floor(ttlRaw))) : 300;
  const platformUrl = (pick(env, "PLATFORM_URL") ?? "https://api.humanauth.ai").replace(/\/+$/, "");
  const onError = pick(env, "ON_ERROR") === "ask" ? "ask" : "deny";
  const dataDir = env.CLAUDE_PLUGIN_DATA && env.CLAUDE_PLUGIN_DATA !== "" ? env.CLAUDE_PLUGIN_DATA : join(homedir(), ".humanauth", "claude-plugin");
  return {
    apiKey: pick(env, "API_KEY"),
    approver: pick(env, "APPROVER"),
    scope,
    extraPattern,
    ttlSeconds,
    platformUrl,
    issuer: pick(env, "ISSUER") ?? platformUrl,
    onError,
    dataDir,
  };
}

function out(decision: HookOutput["hookSpecificOutput"]["permissionDecision"], reason: string): HookOutput {
  return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: reason } };
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

/**
 * Decide one tool call. Returns null when the call is not gated (Claude Code
 * then applies its normal permission flow), otherwise an allow/deny/ask.
 */
export async function runHook(input: HookInput, cfg: HookConfig, deps: HookDeps): Promise<HookOutput | null> {
  const policy: PolicyDecision = evaluate(input.tool_name, input.tool_input, { scope: cfg.scope, extraPattern: cfg.extraPattern });
  if (!policy.gated) return null;

  const audit = deps.audit ?? defaultAudit(cfg.dataDir);
  const base: Omit<AuditEntry, "decision" | "reason"> = {
    at: new Date().toISOString(),
    session: String(input.session_id ?? ""),
    call: String(input.tool_use_id ?? ""),
    tool: String(input.tool_name ?? ""),
    action: policy.action,
    matched: policy.matched,
  };
  const finish = (decision: HookOutput["hookSpecificOutput"]["permissionDecision"], reason: string, extra: Partial<AuditEntry> = {}): HookOutput => {
    audit({ ...base, ...extra, decision, reason });
    return out(decision, `HumanAuth: ${reason}`);
  };
  const fail = (reason: string, extra: Partial<AuditEntry> = {}): HookOutput =>
    finish(cfg.onError, `${reason}${cfg.onError === "ask" ? " (falling back to the keyboard prompt)" : ""}`, extra);

  if (!cfg.apiKey || !cfg.approver) {
    return fail("plugin is not configured. Set api_key and approver under /plugin → humanauth → Configure, or HUMANAUTH_API_KEY and HUMANAUTH_APPROVER in the environment");
  }
  if (!/^(hu|grp)_[A-Za-z0-9_-]{2,80}$/.test(cfg.approver)) {
    return fail(`approver "${cfg.approver}" is not a hu_… or grp_… id`);
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

  // The receipt's `aud` is the tenant id; the platform tells us ours on the
  // request it just created, over the same authenticated channel.
  let tenantId: string;
  try {
    const res = await deps.fetch(`${cfg.platformUrl}/v1/requests/${encodeURIComponent(authorize.request_id)}`, { headers });
    if (!res.ok) return fail(`could not read the approval request (HTTP ${res.status})`);
    const detail = (await res.json()) as { tenant_id?: string };
    if (typeof detail.tenant_id !== "string" || detail.tenant_id.length === 0) return fail("approval request carries no tenant_id");
    tenantId = detail.tenant_id;
  } catch (e) {
    return fail(`could not read the approval request (${(e as Error).message})`);
  }

  const verifier = new HumanAuthVerifier({
    audience: tenantId,
    issuer: cfg.issuer ?? cfg.platformUrl,
    ...(deps.jwks ? { jwks: deps.jwks } : { jwksUri: `${cfg.platformUrl}/.well-known/jwks.json` }),
    replayStore: new FileReplayStore(cfg.dataDir),
  });

  let verified: VerifiedReceipt;
  try {
    verified = await verifier.waitForReceipt(authorize.request_id, {
      apiKey: cfg.apiKey,
      action: policy.action,
      plan,
      idempotencyKey: null, // one call, one receipt, one use
      baseUrl: cfg.platformUrl,
      timeoutMs: cfg.ttlSeconds * 1000 + 15_000,
      pollIntervalMs: deps.pollIntervalMs,
      fetch: deps.fetch,
      sleep: deps.sleep,
      now: deps.now,
    });
  } catch (e) {
    if (e instanceof ApprovalDeniedError) {
      return finish("deny", `the approver denied this ${input.tool_name} call (request ${authorize.request_id}). Do not retry it, split it up, or reach the same effect another way; tell the user it was denied.`);
    }
    if (e instanceof ApprovalExpiredError || e instanceof ApprovalTimeoutError) {
      return finish("deny", `nobody approved this ${input.tool_name} call within ${cfg.ttlSeconds}s (request ${authorize.request_id}). Not approved means denied; do not retry on your own.`);
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
  if (verified.replay) {
    return finish("deny", `receipt ${verified.raw.jti} was already used`, { receipt_id: verified.raw.jti, approvers });
  }

  const who = verified.approvers.map((a) => `${a.huid} (${a.assurance})`).join(", ");
  return finish(
    "allow",
    `approved by ${who} · receipt ${verified.raw.jti} · plan ${hash.slice(0, 23)}… · request ${authorize.request_id}`,
    { receipt_id: verified.raw.jti, approvers },
  );
}
