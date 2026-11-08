// Which tool calls go to the phone. The policy is data the operator sets in
// the plugin's user config; the model never sees or edits it (the files that
// hold it are protected paths below, so a Write to them is itself gated).

export type Scope = "destructive" | "all" | "off";

export interface PolicyConfig {
  scope: Scope;
  /** Operator-supplied regex, tested against the call's subject string. */
  extraPattern?: RegExp | null;
  /**
   * Directories on the hook's own PATH. A write into any of them can replace
   * the interpreter this hook runs on, so they are protected at runtime in
   * addition to the static list below.
   */
  pathDirs?: readonly string[];
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
// All case-insensitive: the default macOS filesystem is, so `.Claude/` is
// `.claude/`. Entries marked `pathsOnly` match file paths of edit tools but
// not shell text (where `node` or `/bin/` appear in harmless commands); the
// shell-side equivalents are the "write into an interpreter location"
// patterns in DESTRUCTIVE_COMMANDS.
export const PROTECTED_PATHS: ReadonlyArray<{ re: RegExp; label: string; pathsOnly?: boolean }> = [
  { re: /(^|[\s/'"=:])\.claude(\/|$|[\s'"])/i, label: "claude settings or hooks" },
  { re: /(^|[\s/'"=:])\.humanauth(\/|$|[\s'"])/i, label: "humanauth plugin data" },
  { re: /(^|[\s/'"=])\.env(\.[A-Za-z0-9_.-]+)?($|[\s'"])/i, label: "env file" },
  { re: /(^|[\s/'"=])\.(ssh|aws|gnupg|kube|docker|config\/gh|npmrc|netrc|pypirc|git-credentials)(\/|$|[\s'"])/i, label: "credentials" },
  { re: /\.(pem|key|p12|pfx|jks|keystore)($|[\s'"])/i, label: "key material" },
  // Shell start-up files decide the environment of the next session, this hook's included.
  { re: /(^|[\s/'"=])\.(zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|bash_logout|profile|login|cshrc|tcshrc|kshrc|mkshrc|inputrc|hushlogin|xonshrc)($|[\s'"])/i, label: "shell start-up file" },
  { re: /(^|[\s/'"=])\.(config\/(fish|zsh|bash|nushell|sh|direnv)|zsh|oh-my-zsh|zprezto|zim|tmux\.conf|tmux)(\/|$|[\s'"])/i, label: "shell start-up file" },
  { re: /(^|[\s/'"=])\.(envrc|direnvrc|tool-versions|nvmrc|node-version|mise\.toml)($|[\s'"])/i, label: "environment file" },
  // Git config can alias a harmless command to a gated one.
  { re: /(^|[\s/'"=])\.gitconfig($|[\s'"])/i, label: "git config" },
  { re: /(^|[\s/'"=])\.git\/(config|hooks)(\/|$|[\s'"])/i, label: "git config or hooks" },
  { re: /(^|[\s/'"=])\.github\/workflows(\/|$|[\s'"])/i, label: "CI workflow" },
  { re: /(^|[\s/'"=])\.(gitlab-ci|circleci|buildkite|travis)/i, label: "CI config" },
  { re: /(^|[\s'"=])\/etc\//i, label: "system config" },
  { re: /Library\/(LaunchAgents|LaunchDaemons|Preferences)\//i, label: "launch agent or preferences" },
  { re: /(^|\/)(wrangler\.(toml|jsonc?)|vercel\.json|fly\.toml|netlify\.toml|serverless\.ya?ml|Procfile|app\.yaml|render\.yaml)($|[\s'"])/i, label: "deploy manifest" },
  { re: /\.(tf|tfvars)($|[\s'"])/i, label: "terraform" },
  { re: /(^|\/)(Dockerfile|docker-compose\.ya?ml|compose\.ya?ml)($|[\s'"])/i, label: "container manifest" },
  // Where interpreters live. The hook itself runs on `node` from PATH; a
  // write here can replace it. Version managers and every `bin/` directory.
  { re: /(^|[\s/'"=])\.(nvm|volta|fnm|asdf|n|nodenv|nodebrew|bun|deno|cargo|rustup|pyenv|rbenv|local\/bin|local\/share\/mise|mise)(\/|$|[\s'"])/i, label: "interpreter or tool install" },
  { re: /(^|[\s'"=])\/(usr\/local|usr|opt\/homebrew|opt\/local|home\/linuxbrew\/\.linuxbrew|snap|nix)?\/?s?bin\//i, label: "bin directory", pathsOnly: true },
  { re: /(^|[\s'"=])\/(opt\/homebrew|usr\/local)\/(Cellar|opt|lib)\//i, label: "homebrew install", pathsOnly: true },
  { re: /(^|[\s'"=])\/nix\/store\//i, label: "nix store", pathsOnly: true },
  { re: /(^|\/)(node|nodejs|npx|npm|pnpm|yarn|bun|deno|sh|bash|zsh|dash|fish|python3?|perl|ruby|env|claude)(\.exe|\.cmd|\.bat)?$/i, label: "interpreter binary", pathsOnly: true },
];

/** Shell text that writes into a place interpreters are loaded from. */
const INTERPRETER_LOCATION = String.raw`(\/(usr\/local\/|usr\/|opt\/homebrew\/|opt\/local\/|home\/linuxbrew\/\.linuxbrew\/)?s?bin\/|\.(nvm|volta|fnm|asdf|nodenv|nodebrew|local\/bin|cargo\/bin|bun\/bin|deno\/bin|n\/bin)\/|\/(opt\/homebrew|usr\/local)\/(Cellar|opt|lib)\/|\/nix\/store\/)`;
const WRITE_VERBS = String.raw`\b(cp|mv|install|ln|tee|rsync|chmod|chown|touch|dd|patch|sed\s+-i[^\s]*|perl\s+-[a-z]*i|curl\s+-[a-zA-Z]*o|wget\s+-O)\b`;
export const INTERPRETER_WRITE: ReadonlyArray<{ re: RegExp; label: string }> = [
  { re: new RegExp(`${WRITE_VERBS}[^|;&]*${INTERPRETER_LOCATION}`, "i"), label: "write into an interpreter location" },
  { re: new RegExp(`>>?\\s*['"]?\\S*${INTERPRETER_LOCATION}`, "i"), label: "redirect into an interpreter location" },
  { re: /\b(cp|mv|install|ln|tee|chmod|chown|touch)\b[^|;&]*\/(node|nodejs|npx|npm|pnpm|yarn|bun|deno|sh|bash|zsh|python3?|perl|ruby|env|claude)(\.exe)?(\s|$|['"])/i, label: "write to an interpreter binary" },
  { re: /\b(npm|pnpm|yarn|bun)\s+(i|install|add|rm|remove|uninstall|link|ci|up|upgrade)\b.*\s(-g|--global|-w\s+\S+@)/i, label: "global package change" },
  { re: /\b(corepack|nvm|volta|fnm|n|asdf|mise|nodenv)\s+(install|use|default|alias|pin|global|shell|exec|run|uninstall|set)\b/i, label: "node version change" },
];

/**
 * Shell commands that leave the machine, destroy data, change permissions or
 * push code. Precision over recall: a missed command is one the operator can
 * add with `extra_pattern` or by choosing scope `all`.
 */
export const DESTRUCTIVE_COMMANDS: ReadonlyArray<{ re: RegExp; label: string }> = [
  // `git -C dir push`, `git -c k=v push`, `git --git-dir=x push` all reach push.
  { re: /\bgit(\s+-[Cc]\s+\S+|\s+--[a-z-]+(=\S+)?)*\s+(push|reset\s+--hard|clean\s+-[a-z]*f|branch\s+-D|tag\s+-d|stash\s+(drop|clear)|remote\s+(set-url|remove|rm|add)|filter-branch|filter-repo|update-ref\s+-d|reflog\s+expire|replace|gc\s+--prune)\b/, label: "git history or remote change" },
  { re: /\bgit(\s+-[Cc]\s+\S+|\s+--[a-z-]+(=\S+)?)*\s+checkout\s+--\s/, label: "discard working changes" },
  // Git config writes can alias `status` to `push`, set hooksPath, or change credential helpers.
  { re: /\bgit(\s+-[Cc]\s+\S+|\s+--[a-z-]+(=\S+)?)*\s+config\b(?![^|;&]*(\s--get\b|\s--get-all\b|\s--get-regexp\b|\s--list\b|\s-l\b|\s--show-origin\b))[^|;&]*\S\s+\S/, label: "git config write" },
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

/** Names of MCP tools that read as writes, used only in scope `destructive`. Matched after snake-casing. */
export const MCP_WRITE_VERBS =
  /(^|_)(send|post|publish|create|delete|remove|update|write|merge|pay|transfer|deploy|execute|exec|run|apply|insert|drop|cancel|charge|refund|email|message|reply|comment|upload|invite|revoke|grant|purchase|order|submit|approve|reject|close|archive|move|rename|set|put|patch|edit|add|assign|trigger|dispatch|restart|stop|start|kill|destroy|reset|truncate|migrate|push|commit|release|tag|share|forward|schedule|book|buy|sell|swap|withdraw|deposit|mint|burn|sign|transition|resolve|notify|announce|broadcast|invoke|call|emit|toggle|enable|disable|activate|deactivate|lock|unlock|ban|kick|block|unblock|promote|demote|rotate|generate|provision|deprovision|register|unregister|subscribe|unsubscribe|accept|decline|complete|finish|fulfil|fulfill|ship|dispatch|allocate|reserve|release|escalate|override|force|bypass|wipe|purge|clear|flush|drain|terminate|suspend|resume|redeploy|rollback|scale|exec_sql|query_write)(_|$)/i;

/** `chat_postMessage` → `chat_post_message`, `createPullRequest` → `create_pull_request`. */
export function snakeCase(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .replace(/[-.\s]+/g, "_")
    .toLowerCase();
}

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
  const pathDirs = (cfg.pathDirs ?? []).filter((d) => d.length > 1);

  if (toolName === "Bash") {
    for (const { re, label, pathsOnly } of PROTECTED_PATHS) {
      if (!pathsOnly && re.test(subject)) return { gated: true, action, matched: `touches ${label}` };
    }
    for (const { re, label } of INTERPRETER_WRITE) {
      if (re.test(subject)) return { gated: true, action, matched: label };
    }
    // A write verb plus a directory that is on this hook's own PATH.
    if (pathDirs.length > 0 && new RegExp(WRITE_VERBS, "i").test(subject)) {
      for (const d of pathDirs) {
        if (subject.includes(d + "/") || subject.endsWith(d)) return { gated: true, action, matched: `writes into PATH directory ${d}` };
      }
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
    const dir = subject.replace(/\/[^/]*$/, "");
    for (const d of pathDirs) {
      if (dir === d || dir.toLowerCase() === d.toLowerCase()) return { gated: true, action, matched: `edits a file in PATH directory ${d}` };
    }
    return { gated: false, action };
  }

  if (toolName.startsWith("mcp__")) {
    const parts = toolName.split("__");
    const tool = parts[parts.length - 1] ?? "";
    if (MCP_WRITE_VERBS.test(snakeCase(tool))) return { gated: true, action, matched: `MCP tool "${tool}" writes` };
    return { gated: false, action };
  }

  return { gated: false, action };
}
