---
name: humanauth-approvals
description: Use when a tool call in this session was held for, approved by, or denied by HumanAuth (the reason starts with "HumanAuth:"), when the user asks why Claude is waiting for their phone, what was approved, how to change what needs approval, or how to set up or troubleshoot the humanauth plugin, and when planning work that will include pushes, deploys, deletes, publishes or outbound writes in a session with this plugin enabled.
---

# HumanAuth approvals

## What is happening

The `humanauth` plugin runs before every tool call. For calls its policy
marks consequential, it sends the exact call to the user's phone and waits.
The call runs only when a signed receipt comes back that verifies on this
machine against the call's own hash. You see the outcome as the tool
result's permission reason:

- `HumanAuth: approved by hu_… (biometric) · receipt rct_… · plan sha256:…`
  The call ran. The receipt id is the evidence; quote it if the user asks
  what was approved.
- `HumanAuth: the approver denied this … call`. The user said no to this
  exact command, file or tool input.
- `HumanAuth: nobody approved this … call within N s`. No answer before the
  wait ran out. Treat it as a denial.
- `HumanAuth: the receipt … did not verify`, `plugin is not configured`,
  `could not reach …`. The gate failed closed; nothing ran.

While waiting, you are blocked on a human. That is the point: the user is
not at this keyboard, so the phone is the keyboard.

## Rules for a denied or unanswered call

1. **Stop that line of action.** Do not re-run the same call, run it with
   small changes, split it into pieces, run it through another tool
   (Bash instead of Write, an MCP tool instead of Bash, a script that does
   the same thing), schedule it, or ask a subagent to do it. Each of those
   is the same action the approver refused, and each would be gated again
   and logged against you.
2. **Tell the user plainly** what was denied, in one sentence, with the
   request id from the reason. Do not speculate why.
3. **Continue with work that does not depend on it.** If nothing else can
   proceed, end your turn and say what is waiting on them.
4. **Never change the policy to get through.** Editing
   `~/.claude/settings.json`, `CLAUDE.md`, the plugin's config, or
   `hooks.json` is itself a gated action and the user will see the attempt
   on their phone. So is dressing the command up: quoting tricks, a
   variable that holds the command, `$(…)`, `eval`, `sh -c`, `xargs`, an
   interpreter one-liner that spawns a process, an unknown `git`
   subcommand, or writing the command into a script and running it. Each
   is recognised and gated, and reads as evasion in the audit log.

## Rules for planning in a gated session

- **Batch the consequential steps and say so.** Each gated call costs the
  user one tap. Prepare everything first (build, test, stage), then run the
  one push or deploy. Tell the user before a run that will need several
  taps, so they keep the phone nearby.
- **Keep gated commands small and literal.** The phone shows the exact
  command; `git push origin release/2.3` is approvable at a glance, a 400
  character one-liner is not, and anything over 4000 characters is shown as
  a hash and a preview, which a careful approver will refuse. Write long
  operations to a script file first (that Write is not gated unless the
  path is protected), review it with the user, then run the short command.
- **Do not put the model's explanation in the command.** The approver sees
  the command and the working directory, never your prose. Make the command
  self-explanatory.
- **Keep secrets out of commands.** Credential-looking text (URL
  passwords, `Bearer` tokens, `TOKEN=`/`password=` values, `ghp_`,
  `sk-`, `AKIA…` and similar) is masked as `•••` before the plan reaches
  the phone, and the approval still binds the real command through a hash.
  Prefer environment variables or files the user already has anyway: a
  masked command is harder to approve at a glance.
- **Read-only work is never gated.** Reading, searching, fetching, planning,
  and ordinary source edits run as before. Writing a script is an ordinary
  edit; running it in the same session is gated, so expect a tap when you
  execute a file you just wrote. Spawning a subagent (`Agent`/`Task`) and
  any built-in tool outside the read-only allowlist are gated in scope
  `destructive`.

## Helping the user configure it

Setup is `/plugin` → `humanauth` → Configure, or the environment variables
`HUMANAUTH_API_KEY` and `HUMANAUTH_APPROVER` for headless and CI runs. The
API key comes from app.humanauth.ai → API keys; the approver is their
`hu_…` id (or a `grp_…` group) from the same dashboard, and their phone must
be enrolled in the HumanAuth app. `scope` is `destructive` by default; `all`
gates every non-read-only tool; `extra_pattern` adds a regex (if it does
not compile, every non-read-only call is refused with the compile error
until it is fixed; tell the user to correct the pattern). `ttl_seconds`
is how long a call waits; a platform hiccup during the wait is retried,
not treated as a denial. `on_error` decides what happens when the platform
is unreachable: `deny` (default, right for unattended runs) or `ask` (fall
back to the keyboard prompt; never under `bypassPermissions`).
`min_assurance` (default `biometric`) is the lowest device assurance
accepted. Every decision is appended to `audit.jsonl` in the plugin's data
directory (`~/.claude/plugins/data/humanauth-humanauth/`, or `~/.humanauth/claude-plugin/`
outside Claude Code) with the request id, receipt id and plan hash, and each
allow keeps the receipt and plan under `evidence/` so it can be re-verified
later. Both directories are protected paths. For unattended runs recommend
scope `all`: `destructive` gates launchers, not what a script they launch does.

If the user asks whether a gate like this actually proves anything, the
vendor-neutral audit in the `hitl` plugin (`hitl:human-approval-audit`)
scores any approval flow, this one included, on six properties and says
whether the approval proves the action, a click, or nothing. Its published
report on this plugin is in the plugin repository under `reports/`.
