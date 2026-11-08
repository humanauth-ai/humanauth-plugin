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
denial. So is anything the plugin cannot verify.

## What needs approval

Policy lives in the plugin's configuration, outside the model's reach. The
files that hold it are themselves protected, so an attempt to edit them is
gated too.

| `scope` | Gated |
|---|---|
| `destructive` (default) | Shell: `git push`, hard resets, `rm -r`/`rm -f`, `sudo`, HTTP writes (`curl -X POST`, `-d`), package publishes, deploys (wrangler, vercel, fly, kubectl, terraform, pulumi, gcloud, aws, az, helm, docker push), GitHub writes (`gh pr merge`, `gh api -X DELETE`), database mutations and migrations, outbound mail, file transfer and remote shells, system configuration, global package installs, process and disk operations, history tampering, secret-store access, agent configuration. Files: any Write or Edit to `.claude/`, `.env*`, `.ssh`, `.aws`, key material, git hooks, CI workflows, deploy manifests, terraform, Dockerfiles. MCP: any tool whose name reads as a write (`send_message`, `merge_pull_request`, `execute_sql`, …). |
| `all` | Every tool call except the read-only built-ins (Read, Glob, Grep, WebFetch, …). |
| `off` | Nothing. |

`extra_pattern` adds one regular expression of your own, matched against
the shell command, the file path, or the MCP tool name and input.

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

1. the platform signature and the receipt's audience, issuer and validity;
2. the device co-signature of the approver you configured, and only theirs;
3. that the receipt's plan hash equals the hash of the call about to run;
4. that the receipt is for this request, and is being used for the first
   time (a file-based single-use store in the plugin's data directory);
5. that the approver's assurance meets what your tenant policy requires.

Only then does it return `allow`. Every outcome is appended to
`~/.claude/plugins/data/humanauth/audit.jsonl` with the request id, receipt
id and plan hash, so you can reconcile what ran against the dashboard.

The hook is wired with `onFailure: block`: if it crashes, times out or
prints something malformed, the call is refused. There is no path through
this gate that does not end in a verified receipt.

We audited it with the vendor-neutral
[`hitl:human-approval-audit`](https://github.com/humanauth-ai/hitl-skills)
skill; the report is in [`reports/`](./reports).

## Limits worth knowing

- **It gates tool calls, not intent.** A shell command the pattern list
  misses runs without a prompt in `destructive` scope. Use `all` for
  sessions where that matters, or add a pattern.
- **One tap per call.** Agentic sessions that push or deploy repeatedly
  will prompt repeatedly. The bundled `humanauth-approvals` skill teaches
  Claude to batch consequential steps and keep gated commands short.
- **Subagents are gated too**, under the same policy, and the plan carries
  the agent id.
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
| `on_error` (`deny` or `ask`) | `HUMANAUTH_ON_ERROR` | `deny` |
| `platform_url` | `HUMANAUTH_PLATFORM_URL` | `https://api.humanauth.ai` |

`on_error` only applies when the platform cannot be reached or the plugin
is misconfigured. A denial, a timeout or an unverifiable receipt is always
a deny.

## Data handling

The hook sends HumanAuth the gated call's plan (command text or file path
with content hashes and a short preview, MCP tool input, working directory,
session and call ids) so your phone can show it. It sends nothing for calls
that are not gated, and never sends file contents, transcripts or the
model's reasoning. Receipts and the audit log stay on your machine. See
the [privacy policy](https://humanauth.ai/privacy).

## Development

```
pnpm install
npm test            # 99 tests: policy, plan, hook against a fake platform, the built bundle end to end
npm run build       # regenerates scripts/phone-approval.mjs (committed; CI checks it is fresh)
claude plugin validate --strict --profile directory .
```

The hook ships as one bundled file so installing the plugin needs no
`npm install`. Source is in `src/`; `@humanauth/verifier` does the receipt
verification.

MIT licensed.
