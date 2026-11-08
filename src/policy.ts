// Which tool calls go to the phone. The policy is data the operator sets in
// the plugin's user config; the model never sees or edits it (the files that
// hold it are protected paths below, so a Write to them is itself gated).

export type Scope = "destructive" | "all" | "off";

export interface PolicyConfig {
  scope: Scope;
  /** Operator-supplied regex, tested against the call's subject string. */
  extraPattern?: RegExp | null;
}

export interface PolicyDecision {
  gated: boolean;
  /** HumanAuth action label (service:operation). */
  action: string;
  /** Why it was gated, for the reason string and the audit line. */
  matched?: string;
}

/** Built-in tools that only read. Never gated, in any scope. */
export const READ_ONLY_TOOLS: ReadonlySet<string> = new Set([
  "Read",
  "Glob",
  "Grep",
  "LS",
  "NotebookRead",
  "WebFetch",
  "WebSearch",
  "TodoWrite",
  "TodoRead",
  "AskUserQuestion",
  "EnterPlanMode",
  "ExitPlanMode",
  "Task",
  "Agent",
  "Skill",
  "ToolSearch",
  "BashOutput",
  "KillShell",
  "TaskOutput",
  "TaskStop",
  "ListMcpResourcesTool",
  "ReadMcpResourceTool",
  "ReadMcpResourceDirTool",
  "Monitor",
]);

export const EDIT_TOOLS: ReadonlySet<string> = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);

/**
 * Paths whose change alters who controls the machine or the agent: the
 * agent's own settings and hooks, credentials, CI, deploy manifests. Matched
 * against file paths (edit tools) and against the text of shell commands.
 */
export const PROTECTED_PATHS: ReadonlyArray<{ re: RegExp; label: string }> = [
  { re: /(^|[\s/'"=:])\.claude(\/|$|[\s'"])/, label: "claude settings or hooks" },
  { re: /(^|[\s/'"=])\.env(\.[A-Za-z0-9_.-]+)?($|[\s'"])/, label: "env file" },
  { re: /(^|[\s/'"=])\.(ssh|aws|gnupg|kube|docker|config\/gh|npmrc|netrc|pypirc|git-credentials)(\/|$|[\s'"])/, label: "credentials" },
  { re: /\.(pem|key|p12|pfx|jks|keystore)($|[\s'"])/, label: "key material" },
  { re: /(^|[\s/'"=])\.git\/hooks(\/|$|[\s'"])/, label: "git hooks" },
  { re: /(^|[\s/'"=])\.github\/workflows(\/|$|[\s'"])/, label: "CI workflow" },
  { re: /(^|[\s/'"=])\.(gitlab-ci|circleci|buildkite|travis)/, label: "CI config" },
  { re: /(^|[\s'"=])\/etc\//, label: "system config" },
  { re: /Library\/LaunchAgents\//, label: "launch agent" },
  { re: /(^|\/)(wrangler\.(toml|jsonc?)|vercel\.json|fly\.toml|netlify\.toml|serverless\.ya?ml|Procfile|app\.yaml|render\.yaml)($|[\s'"])/, label: "deploy manifest" },
  { re: /\.(tf|tfvars)($|[\s'"])/, label: "terraform" },
  { re: /(^|\/)(Dockerfile|docker-compose\.ya?ml|compose\.ya?ml)($|[\s'"])/, label: "container manifest" },
];

/**
 * Shell commands that leave the machine, destroy data, change permissions or
 * push code. Precision over recall: a missed command is one the operator can
 * add with `extra_pattern` or by choosing scope `all`.
 */
export const DESTRUCTIVE_COMMANDS: ReadonlyArray<{ re: RegExp; label: string }> = [
  { re: /\bgit\s+(push|reset\s+--hard|clean\s+-[a-z]*f|branch\s+-D|tag\s+-d|stash\s+(drop|clear)|remote\s+(set-url|remove|rm)|filter-branch|update-ref\s+-d|reflog\s+expire)/, label: "git history or remote change" },
  { re: /\bgit\s+checkout\s+--\s/, label: "discard working changes" },
  { re: /(^|[\s;&|(])rm\s+(-[a-zA-Z]*[rRf][a-zA-Z]*\s|--recursive|--force)/, label: "recursive or forced delete" },
  { re: /(^|[\s;&|(])(rmdir|shred|srm)\s/, label: "delete" },
  { re: /(^|[\s;&|(])(sudo|doas|su)\s/, label: "privilege escalation" },
  { re: /\b(chmod|chown|chgrp)\s+(-[a-zA-Z]*R|--recursive)/, label: "recursive permission change" },
  { re: /\b(curl|wget|http|https|xh|httpie)\b[^|;&]*\s(-X\s*(POST|PUT|PATCH|DELETE)|--request\s+(POST|PUT|PATCH|DELETE)|-d\s|--data(-raw|-binary|-urlencode)?[\s=]|--json[\s=]|-F\s|--form[\s=]|-T\s|--upload-file[\s=]|--method\s+(POST|PUT|PATCH|DELETE)|POST|PUT|PATCH|DELETE)/i, label: "outbound HTTP write" },
  { re: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b/, label: "pipe download to shell" },
  { re: /\b(npm|pnpm|yarn|bun)\s+(publish|unpublish|deprecate|owner|access|dist-tag|token)\b/, label: "package registry write" },
  { re: /\b(cargo\s+publish|twine\s+upload|gem\s+push|mvn\s+deploy|gradle\s+publish|dotnet\s+nuget\s+push|goreleaser|poetry\s+publish|uv\s+publish)\b/, label: "package registry write" },
  { re: /\b(npx\s+)?wrangler\s+(deploy|publish|pages\s+deploy|secret|kv|d1\s+execute|r2\s+object\s+(put|delete)|delete|versions\s+(upload|deploy))\b/, label: "cloudflare deploy or data change" },
  { re: /\b(npx\s+)?vercel\b.*(--prod|\bdeploy\b|\benv\s+(add|rm|pull)|\brm\b|\bremove\b|\bpromote\b|\brollback\b)/, label: "vercel deploy or config change" },
  { re: /\b(netlify\s+deploy|fly(ctl)?\s+(deploy|secrets|destroy|scale)|heroku\s+(config:set|run|ps:|releases:rollback|pg:)|railway\s+(up|run|variables)|render\s+deploy|firebase\s+deploy|amplify\s+(publish|push)|sam\s+deploy|cdk\s+(deploy|destroy)|eb\s+(deploy|terminate))\b/, label: "cloud deploy" },
  { re: /\bgcloud\b.*\b(deploy|delete|create|update|set-iam-policy|add-iam-policy-binding|ssh|run\s+services)\b/, label: "gcloud change" },
  { re: /\baws\b.*\b(delete|terminate|put|create|update|modify|run-instances|rm|sync\s.*--delete|cp\s+\S+\s+s3:|invoke|start|stop|reboot|attach|detach|associate|revoke|authorize)\b/, label: "aws change" },
  { re: /\baz\b.*\b(delete|create|update|set|deploy|start|stop|restart|deployment)\b/, label: "azure change" },
  { re: /\bkubectl\s+(apply|delete|rollout|scale|exec|patch|edit|drain|cordon|taint|label|annotate|set|create|replace|cp|port-forward)\b/, label: "kubernetes change" },
  { re: /\bhelm\s+(install|upgrade|uninstall|delete|rollback)\b/, label: "helm change" },
  { re: /\b(terraform|tofu)\s+(apply|destroy|import|state\s+(rm|mv|push)|taint|workspace\s+delete)\b/, label: "terraform apply" },
  { re: /\bpulumi\s+(up|destroy|refresh|stack\s+rm|state\s+delete)\b/, label: "pulumi change" },
  { re: /\b(ansible-playbook|ansible\s+\S+\s+-m)\b/, label: "ansible run" },
  { re: /\bdocker\s+(push|rm|rmi|system\s+prune|volume\s+(rm|prune)|network\s+rm|compose\s+down.*-v|login)\b/, label: "docker change" },
  { re: /\bgh\s+(pr\s+(merge|create|close|comment|review|edit|ready)|release\s+(create|delete|upload|edit)|repo\s+(delete|create|edit|rename|archive|fork|sync)|secret\s+(set|delete)|variable\s+(set|delete)|workflow\s+(run|enable|disable)|issue\s+(create|comment|close|edit|delete|transfer)|api\b.*(-X|--method)\s*(POST|PUT|PATCH|DELETE)|api\b.*(-f|-F|--field|--raw-field|--input)\s|auth\s+(login|logout|refresh|token)|ssh-key|gpg-key|label\s+(create|delete|edit))\b/i, label: "github write" },
  { re: /\b(glab|hub)\s+(mr\s+(merge|create)|release\s+create|repo\s+delete)\b/, label: "git host write" },
  { re: /\b(psql|mysql|mariadb|sqlite3|mongosh|mongo|redis-cli|clickhouse-client|duckdb|cqlsh)\b.*\b(DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT|FLUSHALL|FLUSHDB|GRANT|REVOKE|-c\s|--command|-e\s|--execute|--eval)/i, label: "database mutation" },
  { re: /\b(dropdb|dropuser|pg_restore|mysqladmin\s+(drop|shutdown|flush))\b/, label: "database admin" },
  { re: /\b(prisma\s+(migrate\s+(deploy|reset|resolve)|db\s+(push|execute|seed))|drizzle-kit\s+(push|migrate|drop)|knex\s+migrate|sequelize\s+db:|typeorm\s+(migration:run|schema:(drop|sync))|alembic\s+(upgrade|downgrade)|rails\s+db:(drop|reset|migrate|schema:load|seed)|manage\.py\s+(migrate|flush|sqlflush|loaddata)|supabase\s+db\s+(push|reset)|atlas\s+(migrate\s+apply|schema\s+apply)|dbmate\s+(up|down|drop)|goose\s+(up|down|reset)|flyway\s+(migrate|clean|repair)|liquibase\s+(update|rollback|drop))\b/, label: "database migration" },
  { re: /\b(mail|mailx|sendmail|msmtp|mutt|neomutt|swaks|ssmtp)\b/, label: "outbound mail" },
  { re: /\b(stripe\b.*\b(create|delete|update|capture|refund|cancel|confirm|pay)|twilio\b.*\b(create|send|delete)|sgmail|slack-cli|slackcat|tweet|toot)\b/i, label: "third-party write" },
  { re: /\b(scp|sftp|ftp|lftp|rsync|rclone\s+(copy|sync|move|delete|purge)|s3cmd\s+(put|del|rm|sync)|gsutil\s+(cp|rm|rsync|mv))\b/, label: "file transfer" },
  { re: /\b(ssh|mosh|telnet)\s+(?!-V\b)/, label: "remote shell" },
  { re: /\b(crontab\s+(-e|-r|\S+\s*$|[^-l])|launchctl\s+(load|unload|bootstrap|bootout|enable|disable|submit|remove|kickstart)|systemctl\s+(start|stop|restart|enable|disable|mask|daemon-reload|edit)|service\s+\S+\s+(start|stop|restart)|defaults\s+(write|delete)|nvram|csrutil|spctl|pmset|scutil\s+--set|networksetup|dscl|tmutil|softwareupdate\s+-i|xattr\s+-d|codesign|sysctl\s+-w|iptables|pfctl|ufw|firewall-cmd|nft\s)/, label: "system configuration" },
  { re: /\b(brew\s+(install|uninstall|upgrade|services|link|unlink|tap)|apt(-get)?\s+(install|remove|purge|upgrade|dist-upgrade|autoremove)|yum\s+(install|remove|update)|dnf\s+(install|remove)|pacman\s+-[SR]|snap\s+(install|remove)|pip3?\s+(install|uninstall)(?!.*--dry-run)|pipx\s+(install|uninstall)|npm\s+(i|install|add|rm|remove|uninstall|link|ci)\s+(-g|--global)|cargo\s+install|go\s+install|gem\s+install|mas\s+install)\b/, label: "system or global package change" },
  { re: /(^|[\s;&|(])(kill\s+-(9|KILL|15|TERM)|killall|pkill|shutdown|reboot|halt|poweroff|init\s+[06])\b/, label: "process or power control" },
  { re: /\b(mkfs|fdisk|sfdisk|parted|diskutil\s+(erase|partition|apfs\s+delete|unmount)|dd\s+if=|wipefs|hdiutil\s+(erase|detach|burn)|format\s+[A-Za-z]:)/, label: "disk operation" },
  { re: />\s*\/dev\/(sd|nvme|disk|hd|mmcblk)/, label: "raw device write" },
  { re: /\b(history\s+-c|unset\s+HISTFILE|export\s+HISTSIZE=0|HISTFILE=\/dev\/null|shred\s|srm\s|rm\s+\S*\.(bash|zsh)_history)/, label: "history tampering" },
  { re: /\b(chattr|setfacl|chflags)\b/, label: "attribute change" },
  { re: /\b(eval|source|\.)\s+<\(/, label: "eval of generated code" },
  { re: /\b(base64\s+(-d|--decode)[^|]*\|\s*(ba|z)?sh|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+-d)/, label: "decode and execute" },
  { re: /\b(osascript|automator|open\s+-a\s+(Mail|Messages|Slack|Discord))\b/, label: "automation of other apps" },
  { re: /\b(security\s+(add-generic-password|delete-generic-password|find-generic-password|find-internet-password|export|import|unlock-keychain)|keychain|secret-tool|pass\s+(insert|rm|edit)|op\s+(item|vault|read|inject)|vault\s+(kv\s+(put|delete)|write|delete)|aws\s+secretsmanager|gcloud\s+secrets|doppler|infisical|sops\s+(-d|--decrypt|-e|--encrypt))\b/, label: "secret store access" },
  { re: /\b(claude|codex|cursor|gemini|copilot|aider|opencode)\s+(plugin|mcp|config|settings|hooks|--dangerously|--permission-mode|-p\s)/, label: "agent configuration" },
];

/** Names of MCP tools that read as writes, used only in scope `destructive`. */
export const MCP_WRITE_VERBS =
  /(^|_)(send|post|publish|create|delete|remove|update|write|merge|pay|transfer|deploy|execute|exec|run|apply|insert|drop|cancel|charge|refund|email|message|reply|comment|upload|invite|revoke|grant|purchase|order|submit|approve|reject|close|archive|move|rename|set|put|patch|edit|add|assign|trigger|dispatch|restart|stop|start|kill|destroy|reset|truncate|migrate|push|commit|release|tag|share|forward|schedule|book|buy|sell|swap|withdraw|deposit|mint|burn|sign)(_|$)/i;

export function actionFor(toolName: string): string {
  if (toolName === "Bash") return "claude_code:bash";
  if (toolName === "Write") return "claude_code:write";
  if (toolName === "Edit" || toolName === "MultiEdit" || toolName === "NotebookEdit") return "claude_code:edit";
  if (toolName.startsWith("mcp__")) return "claude_code:mcp_tool";
  return "claude_code:tool";
}

/** The text a policy pattern is matched against. */
export function subjectOf(toolName: string, toolInput: unknown): string {
  const input = (toolInput ?? {}) as Record<string, unknown>;
  if (toolName === "Bash") return typeof input.command === "string" ? input.command : "";
  if (EDIT_TOOLS.has(toolName)) {
    const p = input.file_path ?? input.notebook_path;
    return typeof p === "string" ? p : "";
  }
  let json = "";
  try {
    json = JSON.stringify(toolInput) ?? "";
  } catch {
    json = "";
  }
  return `${toolName} ${json}`;
}

export function evaluate(toolName: string, toolInput: unknown, cfg: PolicyConfig): PolicyDecision {
  const action = actionFor(toolName);
  if (cfg.scope === "off") return { gated: false, action };
  if (READ_ONLY_TOOLS.has(toolName)) return { gated: false, action };

  const subject = subjectOf(toolName, toolInput);

  if (cfg.extraPattern && cfg.extraPattern.test(subject)) {
    return { gated: true, action, matched: "operator pattern" };
  }

  if (cfg.scope === "all") {
    return { gated: true, action, matched: "scope: all" };
  }

  // scope: destructive
  if (toolName === "Bash") {
    for (const { re, label } of PROTECTED_PATHS) {
      if (re.test(subject)) return { gated: true, action, matched: `touches ${label}` };
    }
    for (const { re, label } of DESTRUCTIVE_COMMANDS) {
      if (re.test(subject)) return { gated: true, action, matched: label };
    }
    return { gated: false, action };
  }

  if (EDIT_TOOLS.has(toolName)) {
    for (const { re, label } of PROTECTED_PATHS) {
      if (re.test(subject)) return { gated: true, action, matched: `edits ${label}` };
    }
    return { gated: false, action };
  }

  if (toolName.startsWith("mcp__")) {
    const parts = toolName.split("__");
    const tool = parts[parts.length - 1] ?? "";
    if (MCP_WRITE_VERBS.test(tool)) return { gated: true, action, matched: `MCP tool "${tool}" writes` };
    return { gated: false, action };
  }

  return { gated: false, action };
}
