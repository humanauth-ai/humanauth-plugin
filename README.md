# humanauth: approve what Claude does when you're not watching

A Claude Code plugin. Consequential tool calls pause until you approve them
on your phone. The call runs only against a signed, action-bound
[HumanAuth](https://humanauth.ai) receipt that is verified on your machine,
so the approval proves *the action*, not a click.

Built for the moment Claude runs unattended: `claude -p` in a script or CI,
a scheduled routine, a Cowork task, a long autonomous session you walked
away from. Claude Code's own permission prompt needs someone at the
keyboard. This plugin makes the phone the keyboard.

```
/plugin marketplace add humanauth-ai/hitl-skills
/plugin install humanauth@humanauth
```

Then `/plugin` → `humanauth` → **Configure**: paste your API key and your
approver id (both from [app.humanauth.ai](https://app.humanauth.ai)), and
have the HumanAuth app on your phone. For headless runs set
`HUMANAUTH_API_KEY` and `HUMANAUTH_APPROVER` in the environment instead.
Node 20 or newer must be on `PATH`.

## What you see

Claude decides to run `git push origin main`. Before it runs, your phone
shows the exact command, the working directory and the session, under the
caption *Claude Code wants to run in repo: git push origin main*. You
approve with Face ID or Touch ID, or you decline. Claude's tool result
reads either

```
HumanAuth: approved by hu_you (biometric) · receipt rct_01… · plan sha256:9f86d0… · request req_01…
```

and the push runs, or

```
HumanAuth: the approver denied this Bash call (request req_01…). Do not retry it, split it up,
or reach the same effect another way; tell the user it was denied.
```

and nothing runs. No answer within the wait (default five minutes) is a
denial. So is anything the plugin cannot verify. If you did answer and the
platform refused the answer (a device proof it could not verify, say), the
denial says so rather than reporting a timeout:

```
HumanAuth: an approval attempt was rejected at 2026-11-09T00:10:30Z (HTTP 401: Invalid device proof: …);
nobody approved this Bash call within 300s (request req_01…). …
```

## What needs approval

Policy lives in the plugin's configuration, outside the model's reach. The
files that hold it are themselves protected, so an attempt to edit them is
gated too.

| `scope` | Gated |
|---|---|
| `destructive` (default) | **Shell:** `git push`, hard resets, `git clean -f`, `git restore`, `git config` writes, any `git` subcommand that is not a known built-in (an alias this hook cannot read), git behaviour set on the command line (`-c alias.…`, `GIT_SSH_COMMAND=`), `rm -r`/`rm -f`, `unlink`, `find -delete`/`-exec rm`, `shred`, `truncate`, emptying an existing file (`: > file`, `cp /dev/null file`), `sudo`, HTTP writes (`curl -X POST`, `-d`), package publishes, deploys (wrangler, vercel, fly, kubectl, terraform, pulumi, gcloud, aws, az, helm, docker push), GitHub writes (`gh pr merge`, `gh api -X DELETE`), database mutations and migrations, outbound mail, file transfer and remote shells, system configuration, global package installs, writes into any `PATH` or `bin/` directory, process and disk operations, history tampering, secret-store access, agent configuration. **Indirection:** `eval` and `sh -c` are judged by the string they run and gated when it is generated; `xargs` and `find -exec` are gated when they hand unseen arguments to a command that decides by them (`git`, `rm`, `curl`, …); interpreter one-liners (`python3 -c`, `perl -e`, `ruby -e`, `php -r`, `node -e`) are gated when the program spawns a process or names a gated command; a script, Makefile or package script is gated when the file was written in this session (see below). **Files:** any Write or Edit to `.claude/` and `CLAUDE.md`, `AGENTS.md`, `.mcp.json`, `.env*`, shell start-up files, `.gitconfig`, anything under `.git/`, `.ssh`, `.aws`, key material, git hooks and hook managers (`.husky/`, `.pre-commit-config.yaml`, `lefthook.yml`), CI workflows, deploy manifests, terraform, Dockerfiles, `package.json`, `Makefile`/`justfile`/`Taskfile.yml`, `.vscode/tasks.json` and `settings.json`, `.idea/`, package-manager config (`.npmrc`, `.yarnrc*`, `.pnpmfile.cjs`, `bunfig.toml`), interpreter locations. In shell text these project files gate only as the target of a redirect or of a writing command (`cat package.json` is free; `sed -i … package.json` is not). **MCP:** any tool whose name reads as a write (`send_message`, `chat_postMessage`, `mergePullRequest`, `execute_sql`, …); any tool whose input carries a SQL write at a statement start (`DELETE FROM`, `DROP TABLE`, …) or an HTTP method field set to POST/PUT/PATCH/DELETE; browser and desktop automation (`computer`, `navigate`, `click`, `fill`, `javascript_tool`, `browser_*`) unless the action only looks (screenshot, read_page, find, scroll, hover, …). **Other tools:** every built-in that is not on the read-only allowlist, including `Agent`/`Task` (delegation), `SendMessage`, `CronCreate`, `Workflow`, `Artifact`, `SendUserFile`, and any tool this plugin has never heard of. |
| `all` | Every tool call except the read-only built-ins (Read, Glob, Grep, WebFetch, …). |
| `off` | Nothing. |

`extra_pattern` adds one regular expression of your own, matched against
the shell command (as written and as normalised), the file path, or the
MCP tool name and input. If it does not compile, nothing is swallowed:
every non-read-only call is refused with the compile error until it is
fixed.

Shell commands are normalised before matching: quotes inside words and
backslash escapes are removed (`g"i"t push` is `git push`), a variable
assigned once to a literal is expanded (`G=git; $G push`), comments and
heredoc bodies are dropped, and command substitutions (`$(…)`, `` `…` ``)
are judged as commands of their own. Text that is only printed does not
gate: `echo 'git push'` is free, `echo push | xargs git` is not. A command
word that is computed at run time (`$CMD args`) is gated as such.

**Unknown tools.** The read-only allowlist is explicit: Read, Glob, Grep,
LS, WebFetch, WebSearch, TodoRead, TodoWrite, NotebookRead,
ListMcpResourcesTool, ReadMcpResourceTool, AskUserQuestion, ExitPlanMode,
EnterPlanMode, TaskOutput, BashOutput, ToolSearch, Skill, ListAgents,
ReadNotifications. Anything else that is not Bash, an edit tool or an MCP
tool is gated in scope `destructive` under the action `claude_code:tool`,
so a new built-in that sends, schedules or spawns is examined before it is
trusted. `Agent` and `Task` are gated unconditionally: spawning a subagent
hands the work to a process this hook sees only call by call, so the
hand-off itself is the moment to ask.

**Scripts the model wrote.** The hook sees every tool call, so it records
the path of every Write and Edit in a small per-session file under the
plugin's data directory (`sessions/`). Running one of those files later in
the same session (`bash x.sh`, `./x.sh`, `source x.sh`, `make` with a
written Makefile, `npm run`/`pnpm run`/`yarn <script>` with a written
`package.json`, `npx <bin>`, `node x.js`) is gated. A file under the
working directory or `/tmp` whose modification time is newer than the
session's first hook call is treated the same way, which also covers
`cat > x.sh`. The residual: a file written by Bash outside both
locations, a file whose timestamp was set back, and a session the plugin
only joined after the file was written.

The full lists are in [`src/policy.ts`](./src/policy.ts). A command the
default misses is a pull request, or a line in `extra_pattern`.

## What the approval proves

Each gated call becomes one HumanAuth request whose **plan** is a flat
object of the call's own fields: the command (or its hash and a preview
when long), the file path with content hashes for edits, the canonical JSON
of an MCP tool's input, plus the session and tool-call ids so no two calls
ever share a plan. The platform hashes the plan; your phone renders every
field and signs that hash with the device key; the platform wraps the
decision in a JWS. The hook then verifies, offline against the platform's
published keys:

**Secrets are masked before the plan leaves your machine.** URL userinfo
(`https://alice:•••@host`), `Bearer` and `Authorization` headers,
`password=`/`TOKEN=`/`API_KEY=` forms, `mysql -p…`/`--password=…`, and
well-known token shapes (`ghp_`, `github_pat_`, `sk-`, `sk_live_`,
`ha_live_`, `xoxb-`, `AKIA…`, `AIza…`, `ya29.`, JWTs, PEM private keys)
are replaced by `•••` in the command, content and previews the approver
sees. The plan then carries `command_masked: true` and
`command_secret_sha256` (the SHA-256 of the unmasked command; for long
commands and Write content the existing `command_sha256`/`content_sha256`
already hashes the unmasked text), so the receipt still binds the real
command without the platform or the phone ever holding the secret. The
plan hash is over the plan as sent, masked text and secret hash included,
and the evidence file stores that same plan. Control and bidirectional
characters in the caption are shown as `⟨U+202E⟩`-style markers so the
approver can see what was there.

1. the platform signature and the receipt's audience, issuer and validity;
2. the device co-signature of the approver you configured, and only theirs;
3. that the receipt's plan hash equals the hash of the call about to run;
4. that the receipt is for this request, and is being used for the first
   time (a file-based single-use store in the plugin's data directory);
5. that the approver's assurance meets what your tenant policy requires.

6. that the approver's assurance also meets `min_assurance` (default
   `biometric`), and, for a group, that the receipt carries the group's
   requirement so membership was checked.

Only then does it return `allow`, and the receipt line above is handed to
Claude as context next to the tool result (Claude Code only logs a hook's
reason on allow), so the model can tell the user who approved what.

Every gated call leaves two lines in `audit.jsonl` in the plugin's data
directory (`CLAUDE_PLUGIN_DATA`, which Claude Code puts under
`~/.claude/plugins/data/humanauth-humanauth/` (plugin name, then
marketplace name); the fallback outside Claude Code is
`~/.humanauth/claude-plugin/`): a `"decision": "pending"` line the moment
the request exists on the platform, with the request id and plan hash, and
the final `allow`, `deny` or `ask` line when the wait ends, with the
receipt id and approvers. The file is therefore chronological even when a
five-minute wait ends after later calls did, and a hook killed mid-wait
still leaves the request id behind. A call refused before any request was
created (an invalid tool input, a misconfiguration) writes the final line
only. When the platform refused an answer during the wait, say a device
proof it could not verify, the final line carries `respond_attempts`
(`[{at, http_status, reason}]`) and the deny reason names the newest one,
so a rejected approval never reads as "nobody answered". Each allow also
keeps the receipt JWS and the plan it was checked against in `evidence/`,
so anyone with the file and HumanAuth's public keys can re-verify the
approval later without asking us. Both directories are protected paths.

The hook is wired with `onFailure: block`: if it crashes, times out or
prints something malformed, the call is refused. There is no path through
this gate that does not end in a verified receipt.

While it waits, a poll that fails (network error, 5xx, 429, a 404 before
the request has propagated) is not a denial: the request is still live and
the approver may be tapping. The hook retries with the same backoff until
the deadline (`ttl_seconds` + 15 s) and refuses only if the deadline passes
while still failing, naming the last error. A 4xx that says the request
itself is wrong (401, 403, …) refuses at once.

We audited it with the vendor-neutral
[`hitl:human-approval-audit`](https://github.com/humanauth-ai/hitl-skills)
skill before shipping, blind, and published the report unedited:
[`reports/2026-11-08-self-audit.md`](./reports/2026-11-08-self-audit.md).
The gated path passed all six properties; the ungated path of the default
scope did not, and every finding was fixed the same day. The probes it
wrote are in the test suite.

## Limits worth knowing

- **`destructive` is a convenience, not a boundary.** It gates the
  launcher, not what it launches: `bash deploy.sh`, `npm run deploy` or
  `make release` run without a prompt unless the script, `package.json`
  or `Makefile` was written in this session (see *Scripts the model
  wrote* above), and so does any command the pattern list misses. For
  unattended runs use scope `all`, where only read-only built-ins skip the
  phone.
- **The hook runs on `node` from `PATH`.** Hooks have no portable absolute
  interpreter path, so writes into any `PATH` directory, every `bin/`,
  version managers and interpreter binaries are gated to keep a shim out.
- **One tap per call.** Agentic sessions that push or deploy repeatedly
  will prompt repeatedly. The bundled `humanauth-approvals` skill teaches
  Claude to batch consequential steps and keep gated commands short.
- **Subagents are gated too**, under the same policy, and the plan carries
  the agent id. Spawning one (`Agent`, `Task`) is itself gated in scope
  `destructive`.
- **Not a sandbox.** Code Claude writes and then runs through an ungated
  command is Claude's code. The gate is for the moment of consequence.
- **Needs Node.** Claude Code's hooks run `node`; without it on `PATH`
  every gated call is refused (fail closed) with a clear reason.

## Configuration reference

| Option | Env fallback | Default |
|---|---|---|
| `api_key` (sensitive) | `HUMANAUTH_API_KEY` | required |
| `approver` (`hu_…` or `grp_…`) | `HUMANAUTH_APPROVER` | required |
| `scope` | `HUMANAUTH_SCOPE` | `destructive` |
| `extra_pattern` | `HUMANAUTH_EXTRA_PATTERN` | none |
| `ttl_seconds` (30–3600) | `HUMANAUTH_TTL_SECONDS` | `300` |
| `min_assurance` (`tap`, `biometric`, `elevated`) | `HUMANAUTH_MIN_ASSURANCE` | `biometric` |
| `on_error` (`deny` or `ask`) | `HUMANAUTH_ON_ERROR` | `deny` |
| `platform_url` (https) | `HUMANAUTH_PLATFORM_URL` | `https://api.humanauth.ai` |

`on_error` only applies when the platform cannot be reached or the plugin
is misconfigured. A denial, a timeout, an unverifiable receipt, a tool
input the policy cannot read (a Bash call without a string `command`, an
edit without a string `file_path`) or an `extra_pattern` that does not
compile is always a deny, and under `bypassPermissions` or `dontAsk`,
where nobody can answer a prompt, `ask` is treated as `deny`. Plain `http`
platform URLs are refused except on loopback.

## Data handling

The hook sends HumanAuth the gated call's plan (command text or file path
with content hashes and a short preview, MCP tool input, working directory,
session and call ids) so your phone can show it, with credential-looking
substrings masked as described above. It sends nothing for calls that are
not gated, and never sends file contents, transcripts or the model's
reasoning. Receipts, the audit log and the per-session list of written
paths stay on your machine. See the
[privacy policy](https://humanauth.ai/privacy).

## Development

This repository is published from `plugins/humanauth` in the HumanAuth
monorepo, where `@humanauth/verifier` is a workspace dependency. There:

```
pnpm install
npm test            # 302 tests: policy, plan, hook against a fake platform, the audit's probes, the 2026-11-09 QA findings, the built bundle end to end
npm run build       # regenerates scripts/phone-approval.mjs (committed)
claude plugin validate --strict --profile directory .
```

The hook ships as one bundled file so installing the plugin needs no
`npm install`; this repo's CI runs the committed bundle on Node 20, 22 and
24 with nothing installed. Source is in `src/`; `@humanauth/verifier` does
the receipt verification. Issues and pull requests are welcome here.

MIT licensed.
