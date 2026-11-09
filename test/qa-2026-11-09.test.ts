// Findings of the external QA pass of 2026-11-09, one block per finding id.
// Each test failed against v0.1.5 and passes against the fix.

import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluate, READ_ONLY_TOOLS, type PolicyConfig } from "../src/policy.js";
import { parseShell } from "../src/shell.js";
import { buildPlan, planHash, describe as caption, maskSecrets, type HookInput } from "../src/plan.js";
import { runHook, configFromEnv, type HookConfig, type AuditEntry } from "../src/hook.js";
import { loadSession, recordWritten } from "../src/session.js";
import { createFakePlatform, type FakePlatform } from "./fake-platform.js";

const d: PolicyConfig = { scope: "destructive" };
const bash = (command: string, cfg: PolicyConfig = d) => evaluate("Bash", { command }, cfg);
const gated = (command: string, cfg: PolicyConfig = d) => bash(command, cfg).gated;
const write = (file_path: string) => evaluate("Write", { file_path, content: "x" }, d).gated;

// ===========================================================================
// TIER 1 — policy
// ===========================================================================

describe("T1-1 shell evasions of the git-push gate", () => {
  const evasions = [
    "G=git; $G push",
    'g"i"t push',
    "g\\it push",
    "git $(echo push)",
    "git `echo push`",
    "echo push | xargs git",
    "git -c alias.ship=push ship",
    "git ship",
    "git pushh origin main",
    'bash -c "git push origin main"',
    "sh -c 'git push'",
    "eval 'git push'",
    'eval "$CMD"',
    "GIT_SSH_COMMAND='sh evil.sh' git fetch",
    "cat cmds.txt | xargs sh -c",
    "find . -name '*.sh' | xargs rm",
    "/usr/bin/env git push",
    "command git push",
    "nice -n 5 git push",
  ];
  for (const c of evasions) {
    it(`gates: ${c}`, () => {
      const r = bash(c);
      expect(r.gated, c).toBe(true);
      expect(r.matched, c).toBeTruthy();
    });
  }

  it("labels an unknown git subcommand as a possible alias and a computed one as computed", () => {
    expect(bash("git ship").matched).toContain("possible alias");
    expect(bash("git $(echo push)").matched).toMatch(/computed at run time|command substitution/);
    expect(bash("git -c alias.ship=push ship").matched).toContain("overridden");
  });

  const knownGit = [
    "git status",
    "git log --oneline -5",
    "git diff HEAD~1",
    "git show HEAD:README.md",
    "git branch",
    "git branch feature/x",
    "git branch -a",
    "git fetch origin",
    "git remote -v",
    "git remote show origin",
    "git rev-parse HEAD",
    "git ls-files src",
    "git blame src/a.ts",
    "git describe --tags",
    "git tag",
    "git tag -l 'v1.*'",
    "git stash list",
    "git stash show -p",
    "git config --get user.email",
    "git config --list",
    "git help push",
    "git version",
    "git --version",
    "git commit -m 'wip'",
    "git commit -m 'fix: push the button'",
    "git add -A",
    "git checkout -b feature",
    "git switch main",
    "git merge --no-ff feature",
    "git rebase -i HEAD~3",
    "git stash",
    "git stash pop",
    "git pull --rebase",
    "git worktree list",
    "echo 'git push origin main'",
  ];
  for (const c of knownGit) {
    it(`does not gate: ${c}`, () => {
      expect(gated(c), c).toBe(false);
    });
  }

  it("gates branch/tag/remote/stash/reflog forms that destroy or rewrite", () => {
    for (const c of ["git branch -D feature", "git branch -d feature", "git branch -m old new", "git tag -d v1", "git tag -f v1", "git remote rename origin old", "git remote prune origin", "git reflog expire --expire=now --all", "git reflog delete HEAD@{1}"]) {
      expect(gated(c), c).toBe(true);
    }
  });

  it("gates interpreter one-liners that spawn a process, not those that compute", () => {
    for (const c of [
      "python3 -c \"import subprocess; subprocess.run(['git','push'])\"",
      "python -c 'import os; os.system(\"rm -rf build\")'",
      "perl -e 'system(\"git push\")'",
      "ruby -e '`git push`'",
      "php -r 'exec(\"git push\");'",
      "node -e \"require('child_process').execSync('git push')\"",
      "node --eval \"import('node:child_process').then(m => m.spawn('curl', ['-X','POST']))\"",
      "python3 -c \"from subprocess import Popen; Popen(['sudo','rm','-rf','/'])\"",
    ]) {
      expect(gated(c), c).toBe(true);
      expect(bash(c).matched, c).toBeTruthy();
    }
    // Where the text alone says nothing (the program never spells `git push`), the one-liner analysis is what gates.
    expect(bash("python3 -c \"import subprocess; subprocess.run(['git','push'])\"").matched).toContain("one-liner");
    expect(bash("node -e \"require('child_process').execSync(process.argv[1])\" -- 'ls'").matched).toContain("one-liner");
    for (const c of ["python3 -c 'print(1+1)'", "node -e 'console.log(process.version)'", "perl -e 'print 42'", "ruby -e 'puts 1'", "python3 -m pytest", "node build.mjs"]) {
      expect(gated(c), c).toBe(false);
    }
  });

  it("sh -c and eval are judged by the string they run, and gated when the string is generated", () => {
    expect(gated("/bin/sh -c 'echo hi'")).toBe(false);
    expect(gated("bash -c 'ls -la && git status'")).toBe(false);
    expect(gated("bash -c 'ls; git push'")).toBe(true);
    // A string the regexes cannot read is judged structurally, and the label says so.
    expect(bash("bash -c 'ls; git ship'").matched).toContain("via bash -c");
    expect(bash("sh -c 'echo push | xargs git'").matched).toContain("via sh -c");
    expect(gated("eval ls")).toBe(false);
    expect(gated('eval "$(cat cmd.txt)"')).toBe(true);
    expect(gated("eval `cat cmd.txt`")).toBe(true);
  });

  it("xargs is gated when the command it runs decides by its arguments", () => {
    expect(gated("ls | xargs wc -l")).toBe(false);
    expect(gated("echo push | xargs git")).toBe(true);
    expect(gated("find . -name '*.tmp' | xargs rm")).toBe(true);
    expect(gated("cat urls | xargs -n1 curl")).toBe(true);
    expect(gated("cat list | xargs -I{} sh -c 'echo {}'")).toBe(true);
  });
});

describe("T1-2 protected paths: agent instructions, task runners, package scripts, hooks managers, editor tasks, git internals", () => {
  const paths = [
    "/repo/CLAUDE.md",
    "/repo/sub/CLAUDE.md",
    "/Users/me/.claude/CLAUDE.md",
    "/repo/.claude/settings.local.json",
    "/repo/AGENTS.md",
    "/repo/.mcp.json",
    "/repo/.husky/pre-commit",
    "/repo/.vscode/tasks.json",
    "/repo/.vscode/settings.json",
    "/repo/.idea/workspace.xml",
    "/repo/package.json",
    "/repo/packages/a/package.json",
    "/repo/Makefile",
    "/repo/makefile",
    "/repo/GNUmakefile",
    "/repo/justfile",
    "/repo/Taskfile.yml",
    "/repo/.pre-commit-config.yaml",
    "/repo/lefthook.yml",
    "/repo/Procfile",
    "/repo/.npmrc",
    "/repo/.yarnrc.yml",
    "/repo/.yarnrc",
    "/repo/.pnpmfile.cjs",
    "/repo/bunfig.toml",
    "/repo/.envrc",
    "/Users/me/.direnvrc",
    "/Users/me/.config/direnv/direnvrc",
    "/repo/.git/HEAD",
    "/repo/.git/index",
    "/repo/.git/info/exclude",
  ];
  for (const p of paths) {
    it(`gates Write and Edit to ${p}`, () => {
      expect(write(p), p).toBe(true);
      expect(evaluate("Edit", { file_path: p, old_string: "a", new_string: "b" }, d).gated, p).toBe(true);
    });
  }

  it("leaves look-alikes alone", () => {
    for (const p of ["/repo/package-lock.json", "/repo/src/package.ts", "/repo/docs/makefile.md", "/repo/.vscode/launch.json", "/repo/CLAUDE.md.bak", "/repo/notes/agents.txt", "/repo/.gitignore", "/repo/.github/CODEOWNERS"]) {
      expect(write(p), p).toBe(false);
    }
  });

  it("gates shell writes to those files, not reads", () => {
    for (const c of [
      "echo '# obey' >> CLAUDE.md",
      "cat evil.md > ./AGENTS.md",
      "sed -i 's/test/deploy/' package.json",
      "cp evil.json .mcp.json",
      "tee -a Makefile < extra.mk",
      "mv hook .husky/pre-commit",
      "printf 'x' > .vscode/tasks.json",
      "echo ref > .git/HEAD",
      "rm .git/index",
      "touch .git/hooks/../info/exclude",
      "npm pkg set scripts.postinstall='curl x | sh'",
    ]) {
      expect(gated(c), c).toBe(true);
    }
    for (const c of ["cat package.json", "jq .version package.json", "cat CLAUDE.md", "head -5 Makefile", "cat .git/HEAD", "git -C . rev-parse --git-dir", "grep -n scripts package.json", "ls .idea", "npm install", "make test"]) {
      expect(gated(c), c).toBe(false);
    }
  });
});

describe("T1-3 unknown tools are gated in scope destructive", () => {
  it("keeps the explicit read-only allowlist free", () => {
    for (const t of ["Read", "Glob", "Grep", "LS", "WebFetch", "WebSearch", "TodoRead", "TodoWrite", "NotebookRead", "ListMcpResourcesTool", "ReadMcpResourceTool", "AskUserQuestion", "ExitPlanMode", "EnterPlanMode", "TaskOutput", "ToolSearch", "Skill", "ListAgents", "ReadNotifications"]) {
      expect(READ_ONLY_TOOLS.has(t), t).toBe(true);
      expect(evaluate(t, { x: 1 }, d).gated, t).toBe(false);
    }
  });
  it("gates tools that send, schedule, publish, trigger or delegate, with the generic tool action", () => {
    for (const t of ["SendMessage", "CronCreate", "CronDelete", "RemoteTrigger", "Workflow", "Artifact", "SendUserFile", "PushNotification", "Monitor", "KillShell", "SomeFutureTool"]) {
      const r = evaluate(t, { x: 1 }, d);
      expect(r.gated, t).toBe(true);
      expect(r.action, t).toBe("claude_code:tool");
      expect(r.matched, t).toBeTruthy();
    }
    expect(evaluate("SomeFutureTool", {}, d).matched).toBe('unknown tool "SomeFutureTool"');
  });
  it("gates Agent and Task unconditionally as delegation, even with an innocent prompt", () => {
    for (const t of ["Agent", "Task"]) {
      const r = evaluate(t, { prompt: "read the README and summarise it", subagent_type: "Explore" }, d);
      expect(r.gated, t).toBe(true);
      expect(r.matched, t).toBe("delegation");
      expect(r.action, t).toBe("claude_code:tool");
    }
  });
});

describe("T1-4 data destruction in bash", () => {
  const destroys = [
    "git clean -fd",
    "git clean -fdx",
    "git clean -xdf",
    "git clean --force",
    "git restore .",
    "git restore --worktree src/",
    "git restore --staged .",
    "git restore src/a.ts",
    "find . -name '*.log' -delete",
    "find build -type f -exec rm {} \\;",
    "find . -execdir rm -f {} +",
    "unlink important.txt",
    ": > data.csv",
    "> data.csv",
    "true > data.csv",
    ": > ./src/index.ts",
    "mv /dev/null notes.txt",
    "cp /dev/null notes.txt",
    "truncate -s 0 app.log",
    "truncate --size 0 app.log",
    "shred -u secrets.txt",
    "srm file",
  ];
  for (const c of destroys) {
    it(`gates: ${c}`, () => {
      expect(gated(c), c).toBe(true);
    });
  }
  it("does not gate truncation of scratch and build output", () => {
    for (const c of [": > /tmp/x.log", "> /tmp/out.txt", ": > build/out.txt", "> dist/bundle.js", ": > node_modules/.cache/x", "cmd > out.txt", "echo hi > /dev/null", "git clean -n", "git clean --dry-run", "find . -name '*.ts'", "find . -type f -exec wc -l {} +"]) {
      expect(gated(c), c).toBe(false);
    }
  });
  it("with a filesystem probe, emptying a path that does not exist is creating a file, not destroying one", () => {
    const fs = { mtimeMs: (p: string) => (p.endsWith("exists.txt") ? 1 : null) };
    const cfg: PolicyConfig = { scope: "destructive", cwd: "/repo", fs };
    expect(gated(": > exists.txt", cfg)).toBe(true);
    expect(gated(": > fresh.txt", cfg)).toBe(false);
    expect(bash(": > exists.txt", cfg).matched).toBe("truncates exists.txt");
  });
});

describe("T1-5 MCP tools: inputs and browser automation", () => {
  it("gates a read-named tool whose input carries a SQL write at a statement start", () => {
    for (const [sql, verb] of [
      ["DELETE FROM users WHERE id = 1", "DELETE"],
      ["select 1; drop table users", "DROP"],
      ["  insert into t values (1)", "INSERT"],
      ["UPDATE accounts SET balance = 0", "UPDATE"],
      ["-- cleanup\nTRUNCATE TABLE events", "TRUNCATE"],
      ["ALTER TABLE t ADD COLUMN x int", "ALTER"],
      ["CREATE TABLE t (id int)", "CREATE"],
      ["GRANT ALL ON users TO public", "GRANT"],
      ["REVOKE SELECT ON users FROM bob", "REVOKE"],
      ["MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", "MERGE"],
      ["REPLACE INTO t VALUES (1)", "REPLACE"],
    ] as const) {
      const r = evaluate("mcp__supabase__query", { sql }, d);
      expect(r.gated, sql).toBe(true);
      expect(r.matched, sql).toContain(`SQL ${verb}`);
    }
    expect(evaluate("mcp__db__query", { query: { nested: { statement: "delete from t" } } }, d).gated).toBe(true);
  });
  it("leaves reads and prose alone", () => {
    for (const input of [{ sql: "SELECT * FROM users WHERE name = 'delete me'" }, { sql: "EXPLAIN SELECT 1" }, { query: "Update the docs please" }, { text: "Please create a table of contents" }, { q: "drop me a line" }]) {
      expect(evaluate("mcp__db__query", input, d).gated, JSON.stringify(input)).toBe(false);
    }
  });
  it("gates an HTTP method field that writes", () => {
    for (const input of [{ method: "POST", url: "https://x" }, { verb: "delete" }, { action: "PUT" }, { request: { method: "patch" } }]) {
      const r = evaluate("mcp__http__request", input, d);
      expect(r.gated, JSON.stringify(input)).toBe(true);
      expect(r.matched).toMatch(/POST|DELETE|PUT|PATCH/);
    }
    expect(evaluate("mcp__http__request", { method: "GET", url: "https://x" }, d).gated).toBe(false);
    expect(evaluate("mcp__http__request", { method: "HEAD" }, d).gated).toBe(false);
  });
  it("gates browser automation unless the action only looks", () => {
    for (const [t, input] of [
      ["mcp__claude-in-chrome__computer", { action: "left_click", coordinate: [1, 2] }],
      ["mcp__claude-in-chrome__computer", { action: "type", text: "hello" }],
      ["mcp__claude-in-chrome__computer", {}],
      ["mcp__claude-in-chrome__javascript_tool", { code: "document.title" }],
      ["mcp__claude-in-chrome__form_input", { ref: 1, value: "x" }],
      ["mcp__claude-in-chrome__navigate", { url: "https://x" }],
      ["mcp__playwright__browser_click", { ref: "e1" }],
      ["mcp__playwright__browser_navigate", { url: "https://x" }],
      ["mcp__playwright__browser_type", { text: "x" }],
      ["mcp__playwright__browser_press_key", { key: "Enter" }],
      ["mcp__chrome_devtools__click", { uid: "1" }],
      ["mcp__chrome_devtools__fill", { uid: "1", value: "x" }],
      ["mcp__chrome_devtools__evaluate_script", { function: "() => 1" }],
      ["mcp__chrome_devtools__press_key", { key: "a" }],
      ["mcp__chrome_devtools__navigate_page", { url: "https://x" }],
      ["mcp__claude-in-chrome__browser_batch", { calls: [] }],
    ] as const) {
      const r = evaluate(t, input, d);
      expect(r.gated, `${t} ${JSON.stringify(input)}`).toBe(true);
      expect(r.matched, t).toContain("browser automation");
    }
    // Tab creation already reads as a write by name.
    expect(evaluate("mcp__claude-in-chrome__tabs_create_mcp", {}, d).gated).toBe(true);
    for (const [t, input] of [
      ["mcp__claude-in-chrome__computer", { action: "screenshot" }],
      ["mcp__claude-in-chrome__computer", { action: "zoom", region: [0, 0, 1, 1] }],
      ["mcp__claude-in-chrome__computer", { action: "scroll", direction: "down" }],
      ["mcp__claude-in-chrome__computer", { action: "wait", duration: 1 }],
      ["mcp__claude-in-chrome__computer", { action: "hover", coordinate: [1, 1] }],
      ["mcp__claude-in-chrome__read_page", {}],
      ["mcp__claude-in-chrome__get_page_text", {}],
      ["mcp__claude-in-chrome__find", { query: "login" }],
      ["mcp__claude-in-chrome__tabs_context_mcp", {}],
      ["mcp__playwright__browser_snapshot", {}],
      ["mcp__playwright__browser_take_screenshot", {}],
      ["mcp__playwright__browser_find", { query: "x" }],
      ["mcp__playwright__browser_hover", { ref: "e1" }],
      ["mcp__chrome_devtools__take_screenshot", {}],
      ["mcp__chrome_devtools__list_console_messages", {}],
    ] as const) {
      expect(evaluate(t, input, d).gated, `${t} ${JSON.stringify(input)}`).toBe(false);
    }
  });
});

describe("T1-6 indirection: running a file written in this session", () => {
  const cwd = "/repo";
  const written = new Set(["/repo/deploy.sh", "/repo/scripts/release", "/repo/Makefile", "/repo/package.json", "/repo/node_modules/.bin/ship", "/repo/tool.js", "/tmp/x.sh"]);
  const cfg: PolicyConfig = { scope: "destructive", cwd, writtenPaths: written, sessionStartMs: 1_000_000, fs: { mtimeMs: () => null } };

  it("gates launchers of files written this session", () => {
    for (const c of [
      "bash ./deploy.sh",
      "bash deploy.sh",
      "sh /repo/deploy.sh",
      "zsh -x deploy.sh",
      "source deploy.sh",
      ". ./deploy.sh",
      "./deploy.sh",
      "scripts/release",
      "/repo/scripts/release --prod",
      "make",
      "make deploy",
      "make -C /repo build",
      "npm run deploy",
      "npm test",
      "pnpm run build",
      "yarn deploy",
      "yarn run build",
      "npx ship",
      "node tool.js",
      "bash /tmp/x.sh",
      "cd /repo && ./deploy.sh",
    ]) {
      const r = bash(c, cfg);
      expect(r.gated, c).toBe(true);
      expect(r.matched, c).toContain("written in this session");
    }
  });

  it("does not gate files the session never wrote, nor yarn built-ins", () => {
    for (const c of ["bash scripts/test.sh", "./configure", "node build.mjs", "yarn install", "yarn add jose", "npx vitest run", "make -f other.mk", "npm run", "pnpm install"]) {
      expect(gated(c, cfg), c).toBe(false);
    }
  });

  it("gates a file under cwd or /tmp that is newer than the session start, exempting node_modules", () => {
    const mtimes: Record<string, number> = { "/repo/fresh.sh": 2_000_000, "/repo/old.sh": 500_000, "/tmp/new.sh": 2_000_000, "/repo/node_modules/.bin/thing": 2_000_000, "/elsewhere/new.sh": 2_000_000 };
    const c2: PolicyConfig = { scope: "destructive", cwd, sessionStartMs: 1_000_000, fs: { mtimeMs: (p) => mtimes[p] ?? null } };
    expect(gated("bash fresh.sh", c2)).toBe(true);
    expect(bash("bash fresh.sh", c2).matched).toContain("newer than this session");
    expect(gated("./fresh.sh", c2)).toBe(true);
    expect(gated("sh /tmp/new.sh", c2)).toBe(true);
    expect(gated("bash old.sh", c2)).toBe(false);
    expect(gated("./node_modules/.bin/thing", c2)).toBe(false);
    expect(gated("bash /elsewhere/new.sh", c2)).toBe(false);
    // Without a probe or a session start nothing is known, so nothing gates (the documented residual).
    expect(gated("bash fresh.sh")).toBe(false);
  });

  it("the hook records every Write/Edit subject, gated or not, in a per-session file and gates the later run", async () => {
    const platform = await createFakePlatform({ baseUrl: "https://platform.test" });
    const dataDir = mkdtempSync(join(tmpdir(), "humanauth-qa-"));
    const cfgH: HookConfig = { apiKey: "k", approver: "hu_alice", scope: "destructive", ttlSeconds: 300, platformUrl: "https://platform.test", onError: "deny", minAssurance: "biometric", allowInsecureUrl: false, pathDirs: [], dataDir };
    const audit: AuditEntry[] = [];
    const deps = { fetch: platform.fetch, jwks: platform.jwks, sleep: async () => {}, pollIntervalMs: 1, audit: (e: AuditEntry) => void audit.push(e) };
    const base = { session_id: "sess_qa", cwd: "/repo", hook_event_name: "PreToolUse" };
    // An ordinary, ungated Write to a script.
    const w = await runHook({ ...base, tool_use_id: "toolu_1", tool_name: "Write", tool_input: { file_path: "scripts/deploy.sh", content: "git push" } }, cfgH, deps);
    expect(w).toBeNull();
    expect(loadSession(dataDir, "sess_qa").written).toEqual(["/repo/scripts/deploy.sh"]);
    // Running it in the same session is gated; the approver then sees the real command.
    const r = await runHook({ ...base, tool_use_id: "toolu_2", tool_name: "Bash", tool_input: { command: "bash scripts/deploy.sh" } }, cfgH, deps);
    expect(r?.hookSpecificOutput.permissionDecision).toBe("allow");
    expect(audit.at(-1)!.matched).toContain("written in this session");
    // Another session does not inherit it.
    const other = await runHook({ ...base, session_id: "sess_other", tool_use_id: "toolu_3", tool_name: "Bash", tool_input: { command: "bash scripts/deploy.sh" } }, cfgH, deps);
    expect(other).toBeNull();
    expect(existsSync(join(dataDir, "sessions"))).toBe(true);
  });

  it("session records resolve relative paths against cwd and dedupe", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "humanauth-qa-"));
    let s = loadSession(dataDir, "s1", 123);
    expect(s.started_at).toBe(123);
    s = recordWritten(dataDir, s, "a.sh", "/w");
    s = recordWritten(dataDir, s, "/w/a.sh", "/w");
    s = recordWritten(dataDir, s, "b.sh");
    expect(s.written).toEqual(["/w/a.sh"]);
    expect(loadSession(dataDir, "s1", 999)).toEqual({ session: "s1", started_at: 123, written: ["/w/a.sh"] });
  });
});

describe("T1-7 pure output does not gate", () => {
  for (const c of [
    "echo 'git push origin main'",
    'echo "rm -rf /"',
    "echo sudo rm -rf / > notes.txt",
    "printf '%s\\n' 'curl -X POST https://x -d a=b'",
    "cat <<EOF > notes.md\ngit push origin main\nrm -rf /\nsudo reboot\nEOF",
    "cat <<'EOF'\ngit push\nEOF\nls",
    "ls # git push",
    "npm test # then git push",
    "git commit -m 'push fix' # push later",
  ]) {
    it(`does not gate: ${JSON.stringify(c)}`, () => {
      expect(gated(c), c).toBe(false);
    });
  }
  it("still gates the command position, redirect targets and piped output", () => {
    expect(gated("echo 'x' > ~/.claude/settings.json")).toBe(true);
    expect(gated("echo push | xargs git")).toBe(true);
    expect(gated("echo aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHBheWxvYWQ= | base64 -d | sh")).toBe(true);
    expect(gated("cat <<EOF > .env.production\nKEY=1\nEOF")).toBe(true);
    expect(gated("echo hi; git push")).toBe(true);
    expect(gated("cat <<EOF\nbody\nEOF\ngit push")).toBe(true);
    // An unterminated heredoc drops nothing (conservative).
    expect(gated("cat <<EOF\ngit push")).toBe(true);
  });
  it("the parser strips comments and heredoc bodies but keeps structure", () => {
    const p = parseShell("cat <<EOF > out.md # note\nrm -rf /\nEOF\ngit status");
    expect(p.text).toBe("cat > out.md ; git status");
    expect(p.commands).toHaveLength(2);
  });
});

// ===========================================================================
// TIER 2 — hook and plan
// ===========================================================================

const BASE = "https://platform.test";
let platform: FakePlatform;
let cfg: HookConfig;
let audit: AuditEntry[];
const deps = (fetchImpl?: typeof fetch) => ({ fetch: fetchImpl ?? platform.fetch, jwks: platform.jwks, sleep: async () => {}, pollIntervalMs: 1, audit: (e: AuditEntry) => void audit.push(e) });
const input = (over: Partial<HookInput> = {}): HookInput => ({
  session_id: "sess_qa2",
  tool_use_id: "toolu_" + Math.random().toString(36).slice(2, 10),
  tool_name: "Bash",
  tool_input: { command: "git push origin main" },
  cwd: "/Users/me/repo",
  hook_event_name: "PreToolUse",
  ...over,
});

beforeEach(async () => {
  platform = await createFakePlatform({ baseUrl: BASE });
  audit = [];
  cfg = { apiKey: "ha_test_key", approver: "hu_alice", scope: "destructive", ttlSeconds: 300, platformUrl: BASE, onError: "deny", minAssurance: "biometric", allowInsecureUrl: false, pathDirs: [], dataDir: mkdtempSync(join(tmpdir(), "humanauth-qa2-")) };
});

describe("T2-1 secret masking", () => {
  it("masks URL userinfo, bearer tokens, password= forms and well-known token shapes", () => {
    const cases: Array<[string, string]> = [
      ["git push https://alice:hunter2@github.com/o/r.git main", "git push https://alice:•••@github.com/o/r.git main"],
      ["curl -H 'Authorization: Bearer abcdef123456789' https://x", "curl -H 'Authorization: Bearer •••' https://x"],
      ["mysql -u root -pS3cret db -e 'DROP TABLE t'", "mysql -u root -p••• db -e 'DROP TABLE t'"],
      ["psql --password=s3cret -c 'select 1'", "psql --password=••• -c 'select 1'"],
      ["export PASSWORD=hunter2 && ./run", "export PASSWORD=••• && ./run"],
      ["DATABASE_PASSWORD=x9 API_KEY=abc node x", "DATABASE_PASSWORD=••• API_KEY=••• node x"],
      ["gh auth login --with-token <<< ghp_abcdefghijklmnopqrstuvwxyz0123456789", "gh auth login --with-token <<< ghp_•••"],
      ["echo github_pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyz", "echo github_pat_•••"],
      ["OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234 run", "OPENAI_API_KEY=••• run"],
      ["stripe charges create --api-key sk_live_abcdefghijklmnop", "stripe charges create --api-key sk_live_•••"],
      ["curl -u x:y -H 'X-Key: sk_test_abcdefghijklmnop'", "curl -u x:y -H 'X-Key: sk_test_•••'"],
      ["HUMANAUTH_API_KEY=ha_live_abcdefghijklmnop node hook", "HUMANAUTH_API_KEY=••• node hook"],
      ["slack token xoxb-1234567890-abcdefghijk", "slack token xox•••"],
      ["AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws s3 ls", "AWS_ACCESS_KEY_ID=••• aws s3 ls"],
      ["key AIzaSyA-abcdefghijklmnopqrstuvwxyz0123456", "key AIza•••"],
      ["token ya29.a0AfH6SMBabcdefghijklmnopqrstuvwxyz", "token ya29.•••"],
      ["jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "jwt eyJ•••"],
    ];
    for (const [raw, masked] of cases) {
      expect(maskSecrets(raw).masked, raw).toBe(masked);
      expect(maskSecrets(raw).changed, raw).toBe(true);
    }
  });
  it("leaves ordinary commands untouched", () => {
    for (const c of ["git push origin main", "curl -X POST https://api.example.com/v1/charges -d amount=100", "echo eyJ short", "npm run build -- --token-ring", "ls -p", "mysql -u root -p db"]) {
      expect(maskSecrets(c)).toEqual({ masked: c, changed: false });
    }
  });
  it("the plan carries the masked command, command_masked and the sha256 of the unmasked command; the caption is masked", () => {
    const i = input({ tool_input: { command: "git push https://alice:hunter2@github.com/o/r.git main" } });
    const plan = buildPlan(i);
    expect(plan.command).toBe("git push https://alice:•••@github.com/o/r.git main");
    expect(plan.command_masked).toBe(true);
    expect(plan.command_secret_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(plan)).not.toContain("hunter2");
    expect(caption(i, plan)).not.toContain("hunter2");
    expect(caption(i, plan)).toContain("alice:•••@");
    // Two commands that differ only in the secret hash differently: the receipt binds the real one.
    const other = buildPlan({ ...i, tool_input: { command: "git push https://alice:hunter3@github.com/o/r.git main" } });
    expect(other.command).toBe(plan.command);
    expect(planHash(other)).not.toBe(planHash(plan));
  });
  it("Write content and Edit previews are masked too, with the unmasked hashes kept", () => {
    const w = buildPlan(input({ tool_name: "Write", tool_input: { file_path: "/r/.env", content: "SECRET=1\nPORT=3000\n" } }));
    expect(w.content).toBe("SECRET=•••\nPORT=3000\n");
    expect(w.content_masked).toBe(true);
    expect(w.content_sha256).toBe(buildPlan(input({ tool_name: "Write", tool_input: { file_path: "/r/.env", content: "SECRET=1\nPORT=3000\n" } })).content_sha256);
    const e = buildPlan(input({ tool_name: "Edit", tool_input: { file_path: "/r/.env", old_string: "TOKEN=old", new_string: "TOKEN=new" } }));
    expect(e.old_preview).toBe("TOKEN=•••");
    expect(e.new_preview).toBe("TOKEN=•••");
    expect(e.old_masked).toBe(true);
    expect(e.old_sha256).not.toBe(e.new_sha256);
    const long = buildPlan(input({ tool_input: { command: "curl -H 'Authorization: Bearer abcdefghijklmnop' " + "x".repeat(4100) } }));
    expect(String(long.command_preview)).toContain("Bearer •••");
    expect(long.command_masked).toBe(true);
    expect(long.command_sha256).toMatch(/^sha256:/);
  });
  for (const command of [
    "git push https://alice:hunter2@github.com/o/r.git main",
    "curl -X POST -H 'Authorization: Bearer abcdefghijklmnop' https://api.example.com/v1/x",
    "PASSWORD=hunter2 psql -c 'DROP TABLE t'",
  ]) {
    it(`end to end: the platform never sees the secret and the receipt still verifies — ${command.slice(0, 30)}…`, async () => {
      const r = await runHook(input({ tool_input: { command } }), cfg, deps());
      expect(r?.hookSpecificOutput.permissionDecision).toBe("allow");
      const sent = JSON.stringify(platform.recorded.authorizeBodies[0]);
      expect(sent).not.toContain("hunter2");
      expect(sent).not.toContain("abcdefghijklmnop");
      expect(sent).toContain("•••");
      const body = platform.recorded.authorizeBodies[0] as { plan: Record<string, unknown>; description: string };
      expect(body.plan.command_masked).toBe(true);
      expect(body.plan.command_secret_sha256).toMatch(/^sha256:/);
      expect(body.description).toContain("•••");
      expect(audit.at(-1)!.plan_hash).toBe(planHash(body.plan as never));
      const ev = JSON.parse(readFileSync(join(cfg.dataDir, audit.at(-1)!.evidence!), "utf8"));
      expect(JSON.stringify(ev.plan)).not.toContain("hunter2");
      expect(ev.plan.command_secret_sha256).toBe(body.plan.command_secret_sha256);
    });
  }
});

describe("T2-2 poll resilience", () => {
  it("a 503 on the poll is retried, and the approval that follows is allowed", async () => {
    let polls = 0;
    const flaky: typeof fetch = async (url, init) => {
      if (String(url).includes("/v1/requests/") && ++polls === 2) return new Response(JSON.stringify({ error: { code: "unavailable" } }), { status: 503 });
      return platform.fetch(url, init);
    };
    const r = await runHook(input(), cfg, deps(flaky));
    expect(r?.hookSpecificOutput.permissionDecision).toBe("allow");
    expect(polls).toBeGreaterThanOrEqual(3);
  });
  it("a network error on the poll is retried too", async () => {
    let polls = 0;
    const flaky: typeof fetch = async (url, init) => {
      if (String(url).includes("/v1/requests/") && ++polls <= 2) throw new TypeError("fetch failed");
      return platform.fetch(url, init);
    };
    const r = await runHook(input(), cfg, deps(flaky));
    expect(r?.hookSpecificOutput.permissionDecision).toBe("allow");
  });
  it("a poll that keeps failing until the deadline denies with the last error", async () => {
    const down: typeof fetch = async (url, init) => {
      if (String(url).includes("/v1/requests/")) return new Response("{}", { status: 502 });
      return platform.fetch(url, init);
    };
    let t = 0;
    const r = await runHook(input(), cfg, { ...deps(down), now: () => (t += 60_000) });
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("could not poll the approval request");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("last error: HTTP 502");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toMatch(/\d+ consecutive failures/);
  });
  it("a 4xx other than 404/410/429 on the poll still fails at once", async () => {
    let polls = 0;
    const forbidden: typeof fetch = async (url, init) => {
      if (String(url).includes("/v1/requests/") && ++polls === 2) return new Response("{}", { status: 403 });
      return platform.fetch(url, init);
    };
    const r = await runHook(input(), cfg, deps(forbidden));
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("HTTP 403");
    expect(polls).toBe(2);
  });
});

describe("T2-3 invalid extra_pattern fails closed", () => {
  it("configFromEnv keeps the compile error instead of swallowing it", () => {
    const c = configFromEnv({ CLAUDE_PLUGIN_OPTION_EXTRA_PATTERN: "(" });
    expect(c.extraPattern).toBeNull();
    expect(c.extraPatternError).toMatch(/Invalid regular expression/);
    expect(configFromEnv({ CLAUDE_PLUGIN_OPTION_EXTRA_PATTERN: "make\\s+release" }).extraPatternError).toBeNull();
  });
  it("evaluate refuses every non-read-only call with the reason, in both gated scopes", () => {
    const bad: PolicyConfig = { scope: "destructive", extraPatternError: "Unterminated group" };
    for (const [t, i] of [["Bash", { command: "ls" }], ["Write", { file_path: "/r/src/a.ts", content: "" }], ["mcp__x__list", {}]] as const) {
      const r = evaluate(t, i, bad);
      expect(r.gated, t).toBe(true);
      expect(r.refuse, t).toBe("extra_pattern is not a valid regular expression: Unterminated group");
    }
    expect(evaluate("Read", { file_path: "/x" }, bad).gated).toBe(false);
    expect(evaluate("Bash", { command: "ls" }, { ...bad, scope: "all" }).refuse).toBeTruthy();
    expect(evaluate("Bash", { command: "rm -rf /" }, { ...bad, scope: "off" }).gated).toBe(false);
  });
  it("runHook denies without calling the platform, and read-only calls still pass", async () => {
    const c = { ...cfg, ...configFromEnv({ CLAUDE_PLUGIN_OPTION_EXTRA_PATTERN: "[" }), apiKey: "k", approver: "hu_alice", platformUrl: BASE, dataDir: cfg.dataDir, onError: "ask" as const };
    const r = await runHook(input({ tool_input: { command: "ls" } }), c, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("extra_pattern is not a valid regular expression:");
    expect(platform.recorded.authorizeBodies).toHaveLength(0);
    expect(audit.at(-1)).toMatchObject({ decision: "deny", matched: "extra_pattern invalid" });
    expect(await runHook(input({ tool_name: "Read", tool_input: { file_path: "/etc/hosts" } }), c, deps())).toBeNull();
  });
});

describe("T2-4 control characters in the caption", () => {
  it("are shown as ⟨U+XXXX⟩ so the approver can see what was there", () => {
    const i = input({ tool_input: { command: "git push origin main ‮# \u001b[2K harmless\u0000" } });
    const text = caption(i, buildPlan(i));
    expect(text).toContain("⟨U+202E⟩");
    expect(text).toContain("⟨U+001B⟩");
    expect(text).toContain("⟨U+0000⟩");
    expect(text).not.toContain("�");
    expect(text).not.toContain("‮");
  });
});

describe("T2-5 non-string subject is gated, then refused by the plan builder", () => {
  it("Bash without a string command, Write/Edit without a string file_path", () => {
    for (const [t, i] of [
      ["Bash", {}],
      ["Bash", { command: 42 }],
      ["Bash", { command: ["rm", "-rf", "/"] }],
      ["Bash", null],
      ["Write", { content: "x" }],
      ["Write", { file_path: ["/r/.env"], content: "x" }],
      ["Edit", { file_path: null, old_string: "a", new_string: "b" }],
      ["MultiEdit", { edits: [] }],
      ["NotebookEdit", { notebook_path: 1 }],
    ] as const) {
      const r = evaluate(t, i, d);
      expect(r.gated, `${t} ${JSON.stringify(i)}`).toBe(true);
      expect(r.matched).toBe("unrecognised input");
    }
  });
  it("runHook turns it into a deny with the validation reason and no platform call", async () => {
    const r = await runHook(input({ tool_input: { command: { $cmd: "rm -rf /" } } }), cfg, deps());
    expect(r?.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(r?.hookSpecificOutput.permissionDecisionReason).toContain("must be a string");
    expect(platform.recorded.authorizeBodies).toHaveLength(0);
    const w = await runHook(input({ tool_name: "Write", tool_input: { content: "x" } }), cfg, deps());
    expect(w?.hookSpecificOutput.permissionDecision).toBe("deny");
  });
});
