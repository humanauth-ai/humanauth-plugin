// End to end through the committed bundle: a real child process, stdin JSON,
// a real HTTP fake platform, stdout JSON. This is what Claude Code runs.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createFakePlatform, type FakePlatform } from "./fake-platform.js";

const BUNDLE = fileURLToPath(new URL("../scripts/phone-approval.mjs", import.meta.url));

let server: Server;
let baseUrl: string;
let platform: FakePlatform;

beforeAll(async () => {
  // Bind first so the fake knows its own URL (it strips it from paths).
  server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  baseUrl = `http://127.0.0.1:${port}`;
  platform = await createFakePlatform({ baseUrl });
  server.on("request", async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks).toString("utf8");
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers[k === "authorization" ? "Authorization" : k] = v;
    const r = await platform.fetch(`${baseUrl}${req.url}`, { method: req.method, headers, body: body || undefined });
    res.writeHead(r.status, { "content-type": "application/json" });
    res.end(await r.text());
  });
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

function run(stdin: unknown, env: Record<string, string>): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BUNDLE], {
      env: { PATH: process.env.PATH ?? "", ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => resolve({ stdout, stderr, code }));
    child.stdin.end(JSON.stringify(stdin));
  });
}

const hookInput = (command: string) => ({
  session_id: "sess_bundle",
  hook_event_name: "PreToolUse",
  tool_name: "Bash",
  tool_input: { command },
  tool_use_id: "toolu_" + Math.random().toString(36).slice(2, 10),
  cwd: "/tmp/repo",
});

describe("scripts/phone-approval.mjs", () => {
  it("exists (run `npm run build` if this fails)", () => {
    expect(existsSync(BUNDLE)).toBe(true);
  });

  it("stays silent for a call the policy does not gate", async () => {
    const r = await run(hookInput("git status"), { HUMANAUTH_API_KEY: "k", HUMANAUTH_APPROVER: "hu_alice", HUMANAUTH_PLATFORM_URL: baseUrl });
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toBe("");
  });

  it("allows an approved call, verifying the receipt against the served JWKS", async () => {
    platform.setOutcome({ kind: "approve" });
    const r = await run(hookInput("git push origin main"), {
      HUMANAUTH_API_KEY: "k",
      HUMANAUTH_APPROVER: "hu_alice",
      HUMANAUTH_PLATFORM_URL: baseUrl,
      CLAUDE_PLUGIN_DATA: mkdtempSync(join(tmpdir(), "humanauth-bundle-")),
    });
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(out.hookSpecificOutput.permissionDecision).toBe("allow");
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain("approved by hu_alice");
  }, 20_000);

  it("denies a denied call", async () => {
    platform.setOutcome({ kind: "deny" });
    const r = await run(hookInput("rm -rf build"), {
      HUMANAUTH_API_KEY: "k",
      HUMANAUTH_APPROVER: "hu_alice",
      HUMANAUTH_PLATFORM_URL: baseUrl,
      CLAUDE_PLUGIN_DATA: mkdtempSync(join(tmpdir(), "humanauth-bundle-")),
    });
    const out = JSON.parse(r.stdout);
    expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
  }, 20_000);

  it("denies on malformed stdin rather than letting the call through", async () => {
    const r = await new Promise<{ stdout: string }>((resolve) => {
      const child = spawn(process.execPath, [BUNDLE], { env: { PATH: process.env.PATH ?? "" } });
      let stdout = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.on("close", () => resolve({ stdout }));
      child.stdin.end("not json");
    });
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("denies when unconfigured", async () => {
    const r = await run(hookInput("git push"), { CLAUDE_PLUGIN_DATA: mkdtempSync(join(tmpdir(), "humanauth-bundle-")) });
    const out = JSON.parse(r.stdout);
    expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain("not configured");
  });
});
