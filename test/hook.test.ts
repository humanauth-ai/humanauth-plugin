import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runHook, configFromEnv, type HookConfig, type AuditEntry } from "../src/hook.js";
import { buildPlan, planHash, type HookInput } from "../src/plan.js";
import { createFakePlatform, type FakePlatform } from "./fake-platform.js";

const BASE = "https://platform.test";

const input = (over: Partial<HookInput> = {}): HookInput => ({
  session_id: "sess_1",
  tool_use_id: "toolu_" + Math.random().toString(36).slice(2, 10),
  tool_name: "Bash",
  tool_input: { command: "git push origin main" },
  cwd: "/Users/me/repo",
  hook_event_name: "PreToolUse",
  ...over,
});

let platform: FakePlatform;
let cfg: HookConfig;
let audit: AuditEntry[];
const deps = () => ({ fetch: platform.fetch, jwks: platform.jwks, sleep: async () => {}, pollIntervalMs: 1, audit: (e: AuditEntry) => void audit.push(e) });

beforeEach(async () => {
  platform = await createFakePlatform({ baseUrl: BASE });
  audit = [];
  cfg = {
    apiKey: "ha_test_key",
    approver: "hu_alice",
    scope: "destructive",
    ttlSeconds: 300,
    platformUrl: BASE,
    onError: "deny",
    minAssurance: "biometric",
    allowInsecureUrl: false,
    pathDirs: [],
    dataDir: mkdtempSync(join(tmpdir(), "humanauth-hook-")),
  };
});

describe("not gated", () => {
  it("returns null so Claude Code applies its normal flow, and calls the platform not at all", async () => {
    const r = await runHook(input({ tool_input: { command: "git status" } }), cfg, deps());
    expect(r).toBeNull();
    expect(platform.recorded.authorizeBodies).toHaveLength(0);
    expect(audit).toHaveLength(0);
  });
  it("scope off returns null even for destructive commands", async () => {
    expect(await runHook(input(), { ...cfg, scope: "off" }, deps())).toBeNull();
  });
});

describe("approved", () => {
  it("allows with the approver, receipt id and plan hash in the reason", async () => {
    const i = input();
    const r = await runHook(i, cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("allow");
    const reason = r!.hookSpecificOutput.permissionDecisionReason;
    expect(reason).toContain("approved by hu_alice (biometric)");
    expect(reason).toMatch(/receipt rct_test_/);
    expect(reason).toContain(planHash(buildPlan(i)).slice(0, 23));
    // Claude Code only logs the reason on allow; the model reads additionalContext.
    expect(r!.hookSpecificOutput.additionalContext).toBe(reason);
    expect(reason).toMatch(/^HumanAuth: approved by hu_alice \(biometric\) · receipt rct_test_\S+ · plan sha256:[0-9a-f]{16}… · request req_1$/);
    // Two lines per gated call: pending when the request exists, the decision when the wait ends.
    expect(audit).toHaveLength(2);
    expect(audit[0]).toMatchObject({ decision: "pending", tool: "Bash", action: "claude_code:bash", request_id: "req_1", call: i.tool_use_id });
    expect(audit[0]!.plan_hash).toBe(planHash(buildPlan(i)));
    expect(audit[0]!.reason).toContain("awaiting approval from hu_alice");
    expect(audit[1]).toMatchObject({ decision: "allow", tool: "Bash", action: "claude_code:bash", approvers: ["hu_alice"], request_id: "req_1", call: i.tool_use_id });
    expect(audit[1]!.plan_hash).toBe(planHash(buildPlan(i)));
    // The decision line is stamped when it is written, not copied from the pending line
    // (the fake platform's polls take real time, so the two differ).
    expect(Date.parse(audit[1]!.at)).toBeGreaterThan(Date.parse(audit[0]!.at));
  });

  it("writes the pending line before the wait, so a call that never ends still leaves its request id", async () => {
    platform.setOutcome({ kind: "pending" });
    let polls = 0;
    const neverEnds = new Promise<never>(() => {});
    // Hang on the first poll after the tenant lookup; the pending line must already be on disk.
    const hanging: typeof platform.fetch = async (url, init) => {
      if (String(url).includes("/v1/requests/") && ++polls > 1) return neverEnds;
      return platform.fetch(url, init);
    };
    void runHook(input(), cfg, { ...deps(), fetch: hanging });
    await new Promise((r) => setTimeout(r, 50));
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ decision: "pending", request_id: "req_1", action: "claude_code:bash" });
  });

  it("sends the derived plan and caption, severity high, the configured TTL and approver", async () => {
    const i = input({ tool_input: { command: "git push origin main", description: "harmless" } });
    await runHook(i, cfg, deps());
    const body = platform.recorded.authorizeBodies[0] as Record<string, unknown>;
    expect(body.human_id).toBe("hu_alice");
    expect(body.action).toBe("claude_code:bash");
    expect(body.plan).toEqual(buildPlan(i));
    expect(body.severity).toBe("high");
    expect(body.ttl).toBe(300);
    expect(body.description).toBe("Claude Code wants to run in repo: git push origin main");
    expect(JSON.stringify(body)).not.toContain("harmless");
  });

  it("targets a group when the approver is a grp_ id and accepts a receipt that carries the group's requirement", async () => {
    platform.setOutcome({ kind: "approve", approval: { threshold: 1, required_principals: ["hu_alice", "hu_bob"] } });
    const r = await runHook(input(), { ...cfg, approver: "grp_ops" }, deps());
    expect((platform.recorded.authorizeBodies[0] as Record<string, unknown>).group_id).toBe("grp_ops");
    expect(r?.hookSpecificOutput.permissionDecision).toBe("allow");
  });

  it("refuses a group receipt that names no required principals (membership unverifiable)", async () => {
    const r = await runHook(input(), { ...cfg, approver: "grp_ops" }, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("names no required principals");
  });

  it("keeps the receipt and the plan as evidence next to the audit line", async () => {
    const { audit: _drop, ...rest } = deps();
    void _drop;
    const r = await runHook(input(), cfg, rest);
    expect(r?.hookSpecificOutput.permissionDecision).toBe("allow");
    const lines = readFileSync(join(cfg.dataDir, "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lines.map((l) => l.decision)).toEqual(["pending", "allow"]);
    const line = lines[1];
    expect(line.evidence).toMatch(/^evidence\/[0-9a-f]{32}\.json$/);
    const ev = JSON.parse(readFileSync(join(cfg.dataDir, line.evidence), "utf8"));
    expect(ev.receipt_jws).toMatch(/^eyJ/);
    expect(ev.plan_hash).toBe(line.plan_hash);
    expect(ev.plan.command).toBe("git push origin main");
  });

  it("refuses a receipt below the configured minimum assurance", async () => {
    platform.setOutcome({ kind: "approve", assurance: "tap" });
    const r = await runHook(input(), cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain('requires at least "biometric"');
    platform.setOutcome({ kind: "approve", assurance: "tap" });
    const lax = await runHook(input(), { ...cfg, minAssurance: "tap" }, deps());
    expect(lax?.hookSpecificOutput.permissionDecision).toBe("allow");
  });

  it("refuses a plain-http platform URL unless it is loopback or explicitly allowed", async () => {
    const r = await runHook(input(), { ...cfg, platformUrl: "http://platform.local" }, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("not https");
    expect(configFromEnv({ HUMANAUTH_ALLOW_INSECURE_URL: "1" }).allowInsecureUrl).toBe(true);
  });

  it("downgrades on_error=ask to deny when nobody can answer (bypassPermissions, dontAsk)", async () => {
    platform.setOutcome({ kind: "http_error", status: 503 });
    const r = await runHook(input({ permission_mode: "bypassPermissions" }), { ...cfg, onError: "ask" }, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    platform.setOutcome({ kind: "http_error", status: 503 });
    const d = await runHook(input({ permission_mode: "dontAsk" }), { ...cfg, onError: "ask" }, deps());
    expect(d?.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("writes the default audit file when no audit sink is injected", async () => {
    const { audit: _drop, ...rest } = deps();
    void _drop;
    await runHook(input(), cfg, rest);
    const file = join(cfg.dataDir, "audit.jsonl");
    expect(existsSync(file)).toBe(true);
    const line = JSON.parse(readFileSync(file, "utf8").trim().split("\n").pop()!);
    expect(line.decision).toBe("allow");
  });
});

describe("denied, expired, unverifiable", () => {
  it("denies when the approver denies, and tells the model not to retry", async () => {
    platform.setOutcome({ kind: "deny" });
    const r = await runHook(input(), cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toMatch(/denied .*Do not retry/);
    // Deny and ask output is unchanged: the reason already reaches the model / the user.
    expect(r?.hookSpecificOutput).not.toHaveProperty("additionalContext");
    const ask = await runHook(input(), { ...cfg, apiKey: undefined }, deps());
    expect(ask?.hookSpecificOutput.permissionDecision).toBe("ask");
    expect(ask?.hookSpecificOutput).not.toHaveProperty("additionalContext");
  });

  it("denies when the request expires", async () => {
    platform.setOutcome({ kind: "expire" });
    const r = await runHook(input(), cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("within 300s");
  });

  it("denies when nobody answers before the TTL", async () => {
    platform.setOutcome({ kind: "pending" });
    let t = 0;
    const r = await runHook(input(), cfg, { ...deps(), now: () => (t += 60_000) });
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("Not approved means denied");
    expect(r?.hookSpecificOutput.permissionDecisionReason).not.toContain("rejected");
    expect(audit.at(-1)).not.toHaveProperty("respond_attempts");
  });

  // Live test 2026-11-09: Touch ID approval, POST /v1/respond → 401, and five
  // minutes later the hook said "nobody approved". The platform now reports
  // refused answers on the request; the hook must repeat them.
  it("names the rejected approval attempt when the request expires, instead of calling it a timeout", async () => {
    const attempt = { at: "2026-11-09T00:10:30.000Z", http_status: 401, reason: "Invalid device proof: invalid device public key encoding" };
    platform.setOutcome({ kind: "expire", respondAttempts: [attempt] });
    const r = await runHook(input(), cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    const reason = r!.hookSpecificOutput.permissionDecisionReason;
    expect(reason).toContain(
      "an approval attempt was rejected at 2026-11-09T00:10:30.000Z (HTTP 401: Invalid device proof: invalid device public key encoding); nobody approved this Bash call within 300s",
    );
    expect(reason).toContain("rejected by the platform, not ignored");
    // The audit line carries the attempts too.
    expect(audit.at(-1)).toMatchObject({ decision: "deny", request_id: "req_1", respond_attempts: [attempt] });
  });

  it("surfaces the newest of several rejected attempts, with the count, when the wait runs out", async () => {
    const older = { at: "2026-11-09T00:10:00.000Z", http_status: 401, reason: "Invalid device proof: signature does not verify" };
    const newer = { at: "2026-11-09T00:12:00.000Z", http_status: 400, reason: "Device does not belong to the specified human" };
    platform.setOutcome({ kind: "pending", respondAttempts: [newer, older] }); // order from the platform is not relied on
    let t = 0;
    const r = await runHook(input(), cfg, { ...deps(), now: () => (t += 60_000) });
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain(
      "2 approval attempts were rejected, the latest at 2026-11-09T00:12:00.000Z (HTTP 400: Device does not belong to the specified human); nobody approved this Bash call within 300s",
    );
    expect(audit.at(-1)!.respond_attempts).toEqual([newer, older]);
  });

  it("denies a receipt signed over a different plan (the call changed after the tap)", async () => {
    platform.setOutcome({ kind: "approve", planOverride: { tool: "Bash", command: "git status" } });
    const r = await runHook(input(), cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("PLAN_HASH_MISMATCH");
  });

  it("denies a receipt for a different request id", async () => {
    platform.setOutcome({ kind: "approve", requestIdOverride: "req_other" });
    const r = await runHook(input(), cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("denies when someone other than the configured approver approved", async () => {
    platform.setOutcome({ kind: "approve", approver: "hu_mallory" });
    const r = await runHook(input(), cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("approved by hu_mallory");
  });

  it("denies a replayed receipt on the second presentation", async () => {
    platform.setOutcome({ kind: "approve", jti: "rct_fixed" });
    const first = await runHook(input(), cfg, deps());
    expect(first?.hookSpecificOutput.permissionDecision).toBe("allow");
    // Same jti again for a new call; the fake mints a fresh receipt per
    // request, so pin the plan too to make it a true replay of bytes.
    const second = await runHook(input(), cfg, deps());
    expect(second?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(second?.hookSpecificOutput.permissionDecisionReason).toMatch(/already used|RECEIPT_REPLAYED/);
  });

  it("denies when the tool input cannot be validated into a plan", async () => {
    const r = await runHook(input({ tool_input: { command: ["rm", "-rf", "/"] } }), { ...cfg, scope: "all" }, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("must be a string");
    expect(platform.recorded.authorizeBodies).toHaveLength(0);
    // No request was created, so no pending line: one deny only.
    expect(audit.map((e) => e.decision)).toEqual(["deny"]);
  });
});

describe("errors and configuration", () => {
  it("denies by default when the platform is unreachable", async () => {
    platform.setOutcome({ kind: "network_error" });
    const r = await runHook(input(), cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("could not reach");
  });

  it("asks instead when on_error is ask, but only for transport errors", async () => {
    platform.setOutcome({ kind: "http_error", status: 503 });
    const r = await runHook(input(), { ...cfg, onError: "ask" }, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("ask");
    platform.setOutcome({ kind: "deny" });
    const d = await runHook(input(), { ...cfg, onError: "ask" }, deps());
    expect(d?.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("falls back to the keyboard prompt with setup instructions when api key or approver is missing", async () => {
    const r = await runHook(input(), { ...cfg, apiKey: undefined }, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("ask");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("not configured");
    const r2 = await runHook(input(), { ...cfg, approver: "alice" }, deps());
    expect(r2?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r2?.hookSpecificOutput.permissionDecisionReason).toContain("not a hu_");
  });

  it("still denies an unconfigured gated call under bypassPermissions and dontAsk", async () => {
    for (const permission_mode of ["bypassPermissions", "dontAsk"]) {
      const r = await runHook({ ...input(), permission_mode }, { ...cfg, apiKey: undefined }, deps());
      expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
      expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("not configured");
    }
  });

  it("reads plugin options first, HUMANAUTH_* second, and clamps the TTL", () => {
    const c = configFromEnv({
      CLAUDE_PLUGIN_OPTION_API_KEY: "opt",
      HUMANAUTH_API_KEY: "env",
      HUMANAUTH_APPROVER: "hu_env",
      CLAUDE_PLUGIN_OPTION_SCOPE: "all",
      CLAUDE_PLUGIN_OPTION_TTL_SECONDS: "5",
      CLAUDE_PLUGIN_OPTION_EXTRA_PATTERN: "make\\s+release",
      CLAUDE_PLUGIN_OPTION_PLATFORM_URL: "https://ha.example.com/",
      CLAUDE_PLUGIN_DATA: "/tmp/x",
    });
    expect(c.apiKey).toBe("opt");
    expect(c.approver).toBe("hu_env");
    expect(c.scope).toBe("all");
    expect(c.ttlSeconds).toBe(30);
    expect(c.extraPattern?.test("make release")).toBe(true);
    expect(c.platformUrl).toBe("https://ha.example.com");
    expect(c.issuer).toBe("https://ha.example.com");
    expect(c.dataDir).toBe("/tmp/x");
    expect(c.onError).toBe("deny");
    const d = configFromEnv({});
    expect(d.scope).toBe("destructive");
    expect(d.ttlSeconds).toBe(300);
    expect(d.platformUrl).toBe("https://api.humanauth.ai");
    const bad = configFromEnv({ CLAUDE_PLUGIN_OPTION_SCOPE: "yolo", CLAUDE_PLUGIN_OPTION_EXTRA_PATTERN: "(" , CLAUDE_PLUGIN_OPTION_TTL_SECONDS: "99999"});
    expect(bad.scope).toBe("destructive");
    expect(bad.extraPattern).toBeNull();
    expect(bad.ttlSeconds).toBe(3600);
  });
});
