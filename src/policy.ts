// Which tool calls go to the phone. The policy is data the operator sets in
// the plugin's user config; the model never sees or edits it (the files that
// hold it are protected paths below, so a Write to them is itself gated).

import { posix } from "node:path";
import { parseShell, baseName, type SimpleCommand, type Word } from "./shell.js";

export type Scope = "destructive" | "all" | "off";

export interface PolicyConfig {
  scope: Scope;
  /** Operator-supplied regex, tested against the call's subject string. */
  extraPattern?: RegExp | null;
  /** Set when the operator's extra_pattern did not compile: every non-read-only call is refused until it is fixed. */
  extraPatternError?: string | null;
  /**
   * Directories on the hook's own PATH. A write into any of them can replace
   * the interpreter this hook runs on, so they are protected at runtime in
   * addition to the static list below.
   */
  pathDirs?: readonly string[];
  /** Working directory of the call; relative paths in commands resolve against it. */
  cwd?: string;
  /** Absolute paths Write/Edit targeted earlier in this session (hook-maintained). */
  writtenPaths?: ReadonlySet<string>;
  /** When the hook first saw this session (epoch ms). Files under cwd or /tmp newer than this are "written this session". */
  sessionStartMs?: number;
  /** Filesystem probe; `null` means the path does not exist. Absent in pure unit tests. */
  fs?: { mtimeMs(absPath: string): number | null };
}

export interface PolicyDecision {
  gated: boolean;
  /** HumanAuth action label (service:operation). */
  action: string;
  /** Why it was gated, for the reason string and the audit line. */
  matched?: string;
  /** Set when the call must be denied outright rather than sent to the phone (misconfiguration). */
  refuse?: string;
}

/**
 * Built-in tools that only read. Never gated, in any scope. Everything not on
 * this list (and not a recognised edit, Bash or MCP tool) is gated in scope
 * `destructive` as an unknown tool, so a new built-in that sends, schedules or
 * delegates does not slip through unexamined.
 */
export const READ_ONLY_TOOLS: ReadonlySet<string> = new Set([
  "Read",
  "Glob",
  "Grep",
  "LS",
  "WebFetch",
  "WebSearch",
  "TodoRead",
  "TodoWrite",
  "NotebookRead",
  "ListMcpResourcesTool",
  "ReadMcpResourceTool",
  "ReadMcpResourceDirTool",
  "AskUserQuestion",
  "ExitPlanMode",
  "EnterPlanMode",
  "TaskOutput",
  "BashOutput",
  "ToolSearch",
  "Skill",
  "ListAgents",
  "ReadNotifications",
]);

export const EDIT_TOOLS: ReadonlySet<string> = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);

/** Spawning a subagent hands the work to a process this hook sees only call by call; the hand-off itself needs a tap. */
const DELEGATION_TOOLS: ReadonlySet<string> = new Set(["Task", "Agent"]);

/**
 * Paths whose change alters who controls the machine or the agent: the
 * agent's own settings and hooks, credentials, CI, deploy manifests. Matched
 * against file paths (edit tools) and against the text of shell commands.
 */
// All case-insensitive: the default macOS filesystem is, so `.Claude/` is
// `.claude/`. Entries marked `pathsOnly` match file paths of edit tools but
// not shell text (where `node` or `/bin/` appear in harmless commands); the
// shell-side equivalents are the "write into an interpreter location"
// patterns in DESTRUCTIVE_COMMANDS. Entries marked `writesOnly` are project
// files that are read all day (`cat package.json`): in shell text they gate
// only as the target of a redirect or the argument of a writing command.
export const PROTECTED_PATHS: ReadonlyArray<{ re: RegExp; label: string; pathsOnly?: boolean; writesOnly?: boolean }> = [
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
  // Files an ungated command reads to decide what to run: agent instructions,
  // task runners, package scripts (run on install and lifecycle), editor tasks,
  // git hook managers, package-manager config. Project files, so in shell text
  // only a write to them gates.
  { re: /(^|\/)(CLAUDE|AGENTS)\.md$/i, label: "agent instructions", writesOnly: true },
  { re: /(^|\/)\.mcp\.json$/i, label: "MCP server config", writesOnly: true },
  { re: /(^|\/)\.husky(\/|$)/i, label: "git hooks (husky)", writesOnly: true },
  { re: /(^|\/)\.pre-commit-config\.ya?ml$/i, label: "git hooks (pre-commit)", writesOnly: true },
  { re: /(^|\/)lefthook(-local)?\.ya?ml$/i, label: "git hooks (lefthook)", writesOnly: true },
  { re: /(^|\/)\.vscode\/(tasks|settings)\.json$/i, label: "editor tasks or settings", writesOnly: true },
  { re: /(^|\/)\.idea(\/|$)/i, label: "editor settings", writesOnly: true },
  { re: /(^|\/)package\.json$/i, label: "package.json (lifecycle scripts)", writesOnly: true },
  { re: /(^|\/)(Makefile|makefile|GNUmakefile|[Jj]ustfile|Taskfile\.ya?ml|Taskfile\.dist\.ya?ml)$/, label: "task runner file", writesOnly: true },
  { re: /(^|\/)(\.yarnrc(\.yml)?|\.pnpmfile\.cjs|bunfig\.toml|\.npmrc)$/i, label: "package manager config", writesOnly: true },
  { re: /(^|\/)\.git\//i, label: "git internals", writesOnly: true },
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

/** Commands whose arguments name files they change. */
const WRITE_COMMANDS: ReadonlySet<string> = new Set(["cp", "mv", "rm", "rmdir", "unlink", "tee", "install", "ln", "touch", "truncate", "shred", "srm", "chmod", "chown", "chgrp", "patch", "dd", "rsync", "sed", "perl"]);

/**
 * Shell commands that leave the machine, destroy data, change permissions or
 * push code. Precision over recall: a missed command is one the operator can
 * add with `extra_pattern` or by choosing scope `all`.
 */
const GIT_OPTS = String.raw`(\s+-[Cc]\s+\S+|\s+--[a-z-]+(=\S+)?)*`;
export const DESTRUCTIVE_COMMANDS: ReadonlyArray<{ re: RegExp; label: string }> = [
  // `git -C dir push`, `git -c k=v push`, `git --git-dir=x push` all reach push.
  { re: new RegExp(String.raw`\bgit${GIT_OPTS}\s+(push|reset\s+--hard|clean\s+(-[a-zA-Z]*[fF][a-zA-Z]*|--force)|branch\s+(-[a-zA-Z]*[DdMm][a-zA-Z]*|--delete|--move|--force)|tag\s+(-[a-zA-Z]*[dfF][a-zA-Z]*|--delete|--force)|stash\s+(drop|clear)|remote\s+(set-url|remove|rm|add|rename|prune|set-head|set-branches)|filter-branch|filter-repo|update-ref\s+-d|reflog\s+(expire|delete)|replace|gc\s+--prune|prune\b|lfs\s+(push|prune)|svn\s+dcommit|send-email|imap-send|credential(-\S+)?\s)`), label: "git history or remote change" },
  { re: new RegExp(String.raw`\bgit${GIT_OPTS}\s+(checkout\s+--\s|restore\b(?!\s+--help))`), label: "discard working changes" },
  // Git config writes can alias `status` to `push`, set hooksPath, or change credential helpers.
  { re: new RegExp(String.raw`\bgit${GIT_OPTS}\s+config\b(?![^|;&]*(\s--get\b|\s--get-all\b|\s--get-regexp\b|\s--list\b|\s-l\b|\s--show-origin\b))[^|;&]*\S\s+\S`), label: "git config write" },
  { re: /\bgit\s+(-\S+\s+)*-c\s+(alias\.|core\.(hooksPath|sshCommand|pager|editor|fsmonitor|askPass)|credential\.|diff\.external|gpg\.program|sequence\.editor|filter\.|merge\.\S*\.driver|url\.|include\.|includeIf\.)/i, label: "git behaviour overridden on the command line" },
  { re: /\bgit\s+(-\S+\s+)*--config-env\b/, label: "git behaviour overridden on the command line" },
  { re: /\bnpm\s+(pkg\s+(set|delete|fix)|version\s+\S|init\b)/, label: "package.json write" },
  { re: /(^|[\s;&|(])rm\s+(-[a-zA-Z]*[rRf][a-zA-Z]*\s|--recursive|--force)/, label: "recursive or forced delete" },
  { re: /(^|[\s;&|(])(rmdir|shred|srm)\s/, label: "delete" },
  { re: /(^|[\s;&|(])unlink\s+\S/, label: "delete" },
  { re: /(^|[\s;&|(])truncate\s+(-[a-zA-Z]*s|--size)/, label: "truncates a file" },
  { re: /(^|[\s;&|(])(cp|mv)\s+(-\S+\s+)*\/dev\/null\s+\S/, label: "empties a file" },
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

// ---------------------------------------------------------------------------
// git: which subcommands are known. Anything else may be an alias (from a
// .gitconfig this hook cannot read) to a gated subcommand, so it is gated.
// ---------------------------------------------------------------------------
const GIT_READ_ONLY: ReadonlySet<string> = new Set([
  "status", "log", "diff", "show", "branch", "fetch", "remote", "rev-parse", "ls-files", "blame", "describe", "tag", "stash", "config", "help", "version",
  "grep", "ls-tree", "ls-remote", "cat-file", "rev-list", "shortlog", "reflog", "show-ref", "for-each-ref", "name-rev", "merge-base", "diff-tree", "diff-index",
  "diff-files", "count-objects", "fsck", "verify-commit", "verify-tag", "verify-pack", "check-ignore", "check-attr", "check-ref-format", "var", "whatchanged", "cherry",
  "range-diff", "worktree", "bisect", "show-branch", "annotate", "archive", "bundle", "request-pull", "column", "mailinfo", "mailsplit", "stripspace", "interpret-trailers",
]);
/** Local-only built-ins: they change the working tree or local history, which the operator can undo; not aliases. */
const GIT_LOCAL: ReadonlySet<string> = new Set([
  "commit", "add", "checkout", "switch", "merge", "rebase", "cherry-pick", "revert", "pull", "clone", "init", "mv", "rm", "apply", "am", "format-patch", "notes", "submodule",
  "symbolic-ref", "update-index", "read-tree", "write-tree", "commit-tree", "hash-object", "pack-refs", "repack", "maintenance", "sparse-checkout", "lfs", "flow", "svn",
  "mergetool", "difftool", "citool", "gui", "fast-import", "fast-export", "unpack-objects", "pack-objects", "index-pack", "merge-file", "merge-tree", "merge-index", "patch-id",
  "rerere", "update-server-info", "upload-pack", "receive-pack", "daemon", "instaweb", "p4", "quiltimport", "replay", "restore", "reset", "clean", "update-ref", "gc", "prune",
]);
const GIT_ENV = /^(GIT_(CONFIG_PARAMETERS|CONFIG_GLOBAL|CONFIG_SYSTEM|CONFIG_NOSYSTEM|SSH_COMMAND|SSH|EXEC_PATH|PAGER|EDITOR|SEQUENCE_EDITOR|EXTERNAL_DIFF|ASKPASS|PROXY_COMMAND|TEMPLATE_DIR|DIR|ALTERNATE_OBJECT_DIRECTORIES)|PAGER|EDITOR|VISUAL)=/;
const GIT_GLOBAL_OPTS_WITH_ARG = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix", "--config-env", "--list-cmds"]);

function gitSubcommandIndex(words: Word[]): number {
  let i = 1;
  while (i < words.length) {
    const w = words[i]!.text;
    if (!w.startsWith("-")) return i;
    if (GIT_GLOBAL_OPTS_WITH_ARG.has(w)) i += 2;
    else i += 1;
  }
  return -1;
}

function analyseGit(c: SimpleCommand): string | null {
  for (const a of c.assignments) if (GIT_ENV.test(a)) return `git environment overridden (${a.split("=")[0]})`;
  const at = gitSubcommandIndex(c.words);
  if (at === -1) return null; // `git`, `git --version`, `git --help`
  const sub = c.words[at]!;
  if (sub.dynamic) return "git subcommand computed at run time";
  const name = sub.text;
  if (GIT_READ_ONLY.has(name) || GIT_LOCAL.has(name) || name === "push") return null;
  return `unknown git subcommand "${name}" (possible alias)`;
}

// ---------------------------------------------------------------------------
// Indirection: eval, sh -c, xargs, interpreter one-liners, scripts the model wrote.
// ---------------------------------------------------------------------------
const SHELLS: ReadonlySet<string> = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "ash", "busybox"]);
const WRAPPERS: ReadonlySet<string> = new Set(["command", "builtin", "exec", "nohup", "time", "caffeinate", "nice", "ionice", "timeout", "stdbuf", "env", "setsid", "unbuffer", "script"]);
const WRAPPER_ARG_OPTS: Record<string, Set<string>> = {
  nice: new Set(["-n"]),
  ionice: new Set(["-c", "-n"]),
  stdbuf: new Set(["-i", "-o", "-e"]),
  env: new Set(["-u", "-C", "-S", "--unset", "--chdir"]),
  timeout: new Set(["-s", "-k", "--signal", "--kill-after"]),
};
/** Commands whose arguments decide what happens; handed unseen arguments (xargs, find -exec) they are gated. */
const LAUNCHERS: ReadonlySet<string> = new Set([
  "git", "gh", "glab", "sh", "bash", "zsh", "dash", "ksh", "fish", "node", "bun", "deno", "python", "python3", "python2", "pypy", "perl", "ruby", "php", "npm", "npx", "pnpm", "yarn",
  "docker", "kubectl", "helm", "aws", "gcloud", "az", "terraform", "tofu", "pulumi", "wrangler", "vercel", "fly", "flyctl", "heroku", "psql", "mysql", "mariadb", "sqlite3", "mongosh",
  "redis-cli", "ssh", "scp", "sftp", "rsync", "curl", "wget", "eval", "xargs", "env", "sudo", "doas", "su", "make", "just", "task", "stripe", "twilio", "op", "vault", "launchctl", "systemctl",
]);
const DANGEROUS: ReadonlySet<string> = new Set(["rm", "rmdir", "unlink", "shred", "srm", "truncate", "mv", "cp", "dd", "chmod", "chown", "chgrp", "kill", "pkill", "killall", "tee", "install", "ln", "sed", "mkfs", "crontab", "defaults"]);
/** Inside an interpreter one-liner: anything that reaches a process, or a command name this policy gates. */
const INLINE_EXEC = /subprocess|os\.system|\bexec\b|\bspawn|system\s*\(|child_process|Popen|`|\b(git|rm|sudo|doas|curl|wget|ssh|scp|rsync|kubectl|aws|gcloud|az|docker|npm|npx|pnpm|yarn|psql|mysql|shred|dd|chmod|chown|kill|mail|sendmail|push|publish|deploy|terraform|wrangler|vercel)\b/;
const ONE_LINER_FLAGS: Record<string, RegExp> = {
  python: /^-[a-zA-Z]*c$/,
  python3: /^-[a-zA-Z]*c$/,
  python2: /^-[a-zA-Z]*c$/,
  pypy: /^-[a-zA-Z]*c$/,
  perl: /^-[a-zA-Z]*[eE]$/,
  ruby: /^-[a-zA-Z]*e$/,
  php: /^-r$/,
  node: /^(-e|-p|--eval|--print)$/,
  nodejs: /^(-e|-p|--eval|--print)$/,
  bun: /^(-e|--eval|--print)$/,
};
const INTERPRETERS: ReadonlySet<string> = new Set(["node", "nodejs", "bun", "deno", "tsx", "ts-node", "python", "python3", "python2", "pypy", "ruby", "perl", "php"]);
const YARN_BUILTINS: ReadonlySet<string> = new Set(["install", "add", "remove", "upgrade", "upgrade-interactive", "why", "info", "list", "cache", "config", "version", "versions", "bin", "link", "unlink", "pack", "login", "logout", "outdated", "check", "licenses", "workspaces", "workspace", "dlx", "set", "up", "dedupe", "explain", "node", "exec", "constraints", "patch", "stage", "search", "init", "help", "import", "generate-lock-entry", "audit"]);
const TMP_RE = /^(\/private)?\/(tmp|var\/tmp|var\/folders)\//;

function unwrap(words: Word[]): Word[] {
  let w = words;
  for (let guard = 0; guard < 6 && w.length; guard++) {
    const head = baseName(w[0]!.text);
    if (!WRAPPERS.has(head)) break;
    let i = 1;
    const argOpts = WRAPPER_ARG_OPTS[head];
    while (i < w.length) {
      const t = w[i]!.text;
      if (head === "env" && /^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) i++;
      else if (t.startsWith("-")) i += argOpts?.has(t) ? 2 : 1;
      else if (head === "timeout" && i === 1 && /^\d/.test(t)) i++;
      else if (head === "script" && i === 1 && !t.startsWith("-")) i++; // typescript file
      else break;
    }
    w = w.slice(i);
  }
  return w;
}

interface Ctx {
  cfg: PolicyConfig;
  depth: number;
}

function resolvePath(p: string, cfg: PolicyConfig): string | null {
  if (p.startsWith("~")) return null;
  if (p.startsWith("/")) return posix.normalize(p);
  if (!cfg.cwd) return null;
  return posix.resolve(cfg.cwd, p);
}

/** A script the model wrote this session, or that appeared under cwd or /tmp since the session began. */
function executedFile(p: string, cfg: PolicyConfig, allowNewness: boolean): string | null {
  const abs = resolvePath(p, cfg);
  if (!abs) return null;
  if (cfg.writtenPaths) {
    for (const w of cfg.writtenPaths) if (w === abs || w.toLowerCase() === abs.toLowerCase()) return `runs ${p}, a file written in this session`;
  }
  if (allowNewness && cfg.fs && typeof cfg.sessionStartMs === "number") {
    const underCwd = cfg.cwd ? abs.startsWith(posix.normalize(cfg.cwd) + "/") : false;
    if ((underCwd || TMP_RE.test(abs)) && !/\/node_modules\//.test(abs)) {
      const m = cfg.fs.mtimeMs(abs);
      if (m !== null && m > cfg.sessionStartMs) return `runs ${p}, a file newer than this session`;
    }
  }
  return null;
}

function firstFileArg(words: Word[], from: number, optsWithArg: ReadonlySet<string>): Word | null {
  for (let i = from; i < words.length; i++) {
    const t = words[i]!.text;
    if (t.startsWith("-")) {
      if (optsWithArg.has(t)) i++;
      continue;
    }
    return words[i]!;
  }
  return null;
}

function analyseIndirection(words: Word[], cfg: PolicyConfig): string | null {
  const head = baseName(words[0]!.text);
  const raw = words[0]!.text;
  if (raw.includes("/") && !words[0]!.dynamic) {
    const r = executedFile(raw, cfg, true);
    if (r) return r;
  }
  if (SHELLS.has(head)) {
    const f = firstFileArg(words, 1, new Set(["-o", "-O", "+o", "+O", "-c"]));
    if (f && !f.dynamic) return executedFile(f.text, cfg, true);
    return null;
  }
  if (head === "source" || head === ".") {
    const f = words[1];
    if (f && !f.dynamic) return executedFile(f.text, cfg, true);
    return null;
  }
  if (head === "make" || head === "gmake") {
    let dir = cfg.cwd;
    let file: string | null = null;
    for (let i = 1; i < words.length; i++) {
      const t = words[i]!.text;
      if ((t === "-f" || t === "--file" || t === "--makefile") && words[i + 1]) file = words[++i]!.text;
      else if (t.startsWith("--file=") || t.startsWith("--makefile=")) file = t.split("=").slice(1).join("=");
      else if ((t === "-C" || t === "--directory") && words[i + 1]) dir = resolvePath(words[++i]!.text, cfg) ?? dir;
    }
    const candidates = file ? [file] : ["GNUmakefile", "makefile", "Makefile"];
    for (const c of candidates) {
      const p = file || !dir ? c : posix.join(dir, c);
      const r = executedFile(p, cfg, true);
      if (r) return r;
    }
    return null;
  }
  if (head === "just" || head === "task") {
    for (const c of head === "just" ? ["justfile", "Justfile"] : ["Taskfile.yml", "Taskfile.yaml"]) {
      const r = executedFile(c, cfg, true);
      if (r) return r;
    }
    return null;
  }
  if (head === "npm" || head === "pnpm" || head === "yarn" || head === "bun") {
    const sub = words[1]?.text;
    const hasScript = words[2] !== undefined && !words[2].text.startsWith("-");
    const viaScript =
      (head === "npm" && (((sub === "run" || sub === "run-script") && hasScript) || sub === "start" || sub === "test" || sub === "stop" || sub === "restart")) ||
      ((head === "pnpm" || head === "bun") && ((sub === "run" && hasScript) || sub === "start" || sub === "test")) ||
      (head === "yarn" && sub !== undefined && !sub.startsWith("-") && !YARN_BUILTINS.has(sub) && (sub !== "run" || hasScript));
    if (viaScript) return executedFile("package.json", cfg, true);
    if ((head === "pnpm" && (sub === "exec" || sub === "dlx")) || (head === "bun" && sub === "x")) {
      const bin = words[2]?.text;
      if (bin && !bin.startsWith("-")) return executedFile(posix.join("node_modules", ".bin", bin), cfg, false);
    }
    if (head === "bun" && sub && !sub.startsWith("-") && /\.[A-Za-z0-9]+$/.test(sub)) return executedFile(sub, cfg, false);
    return null;
  }
  if (head === "npx") {
    const bin = firstFileArg(words, 1, new Set(["-p", "--package", "-c", "--call"]));
    if (bin && !bin.dynamic) return executedFile(posix.join("node_modules", ".bin", baseName(bin.text)), cfg, false);
    return null;
  }
  if (INTERPRETERS.has(head)) {
    const f = firstFileArg(words, 1, new Set(["-r", "--require", "--import", "--loader", "-m", "-W", "-X", "-I", "-e", "-c", "-p", "--eval", "--print"]));
    if (f && !f.dynamic && /\.[A-Za-z0-9]+$/.test(f.text)) return executedFile(f.text, cfg, false);
    return null;
  }
  return null;
}

function analyseInlineProgram(words: Word[]): string | null {
  const head = baseName(words[0]!.text);
  const flag = ONE_LINER_FLAGS[head];
  if (!flag) return null;
  for (let i = 1; i < words.length; i++) {
    if (flag.test(words[i]!.text)) {
      const program = words.slice(i + 1).map((w) => w.text).join(" ");
      if (INLINE_EXEC.test(program)) return `${head} one-liner spawns a process or names a gated command`;
      if (words.slice(i + 1).some((w) => w.dynamic)) return `${head} one-liner computed at run time`;
      return null;
    }
  }
  return null;
}

function analyseXargs(words: Word[], c: SimpleCommand): string | null {
  const withArg = new Set(["-n", "-P", "-L", "-s", "-I", "-d", "-a", "-E", "-l", "--max-args", "--max-procs", "--max-lines", "--max-chars", "--replace", "--delimiter", "--arg-file", "--eof"]);
  const exec = firstFileArg(words, 1, withArg);
  if (!exec) return null; // bare xargs echoes
  if (exec.dynamic) return "xargs runs a command computed at run time";
  const name = baseName(exec.text);
  if (LAUNCHERS.has(name) || DANGEROUS.has(name)) return `xargs runs ${name} with arguments from ${c.prev === "|" ? "a pipe" : "stdin"}`;
  return null;
}

function analyseFind(words: Word[]): string | null {
  for (let i = 1; i < words.length; i++) {
    const t = words[i]!.text;
    if (t === "-delete") return "find -delete";
    if ((t === "-exec" || t === "-execdir" || t === "-ok" || t === "-okdir") && words[i + 1]) {
      const name = baseName(words[i + 1]!.text);
      if (words[i + 1]!.dynamic || LAUNCHERS.has(name) || DANGEROUS.has(name)) return `find ${t} ${name}`;
    }
  }
  return null;
}

/** `: > file`, `> file`: emptying an existing file outside /tmp and the build directories. */
function analyseTruncation(c: SimpleCommand, words: Word[], cfg: PolicyConfig): string | null {
  const head = words[0] ? baseName(words[0].text) : "";
  if (words.length > 0 && head !== ":" && head !== "true") return null;
  for (const r of c.redirects) {
    const op = r.op.replace(/^\d+/, "");
    if (op !== ">" && op !== ">|" && op !== "&>") continue;
    const t = r.target.text;
    if (r.target.dynamic) return `truncates ${t} (path computed at run time)`;
    if (/^\/dev\//.test(t)) continue;
    const abs = resolvePath(t, cfg) ?? t;
    if (TMP_RE.test(abs) || /^\$TMPDIR/.test(t)) continue;
    const rel = cfg.cwd && abs.startsWith(posix.normalize(cfg.cwd) + "/") ? abs.slice(posix.normalize(cfg.cwd).length + 1) : t.startsWith("/") ? null : t;
    if (rel && /^(\.\/)?(build|dist|node_modules|out|coverage|\.cache|target)\//.test(rel)) continue;
    if (cfg.fs && abs.startsWith("/")) {
      if (cfg.fs.mtimeMs(abs) === null) continue; // creating an empty file, not emptying one
    }
    return `truncates ${t}`;
  }
  return null;
}

/** Project files that gate only when written (see PROTECTED_PATHS `writesOnly`). */
function analyseProjectFileWrite(c: SimpleCommand, words: Word[]): string | null {
  const writesOnly = PROTECTED_PATHS.filter((p) => p.writesOnly);
  for (const r of c.redirects) {
    if (!/^(\d*>>?|>\||&>>?)$/.test(r.op)) continue;
    for (const { re, label } of writesOnly) if (re.test(r.target.text)) return `writes ${label}`;
  }
  if (!words.length) return null;
  const head = baseName(words[0]!.text);
  if (!WRITE_COMMANDS.has(head)) return null;
  if (head === "sed" && !words.some((w) => /^-[a-zA-Z]*i|^--in-place/.test(w.text))) return null;
  if (head === "perl" && !words.some((w) => /^-[a-zA-Z]*i/.test(w.text))) return null;
  for (const w of words.slice(1)) {
    if (w.text.startsWith("-")) continue;
    for (const { re, label } of writesOnly) if (re.test(w.text)) return `writes ${label}`;
  }
  return null;
}

function analyseSimple(c: SimpleCommand, ctx: Ctx): string | null {
  const { cfg } = ctx;
  const words = unwrap(c.words);
  const trunc = analyseTruncation(c, words, cfg);
  if (trunc) return trunc;
  const projectWrite = analyseProjectFileWrite(c, words);
  if (projectWrite) return projectWrite;
  if (!words.length) return null;

  const cmd = words[0]!;
  const head = baseName(cmd.text);
  if (cmd.dynamic) return "command computed at run time";

  if (head === "git") return analyseGit({ ...c, words });

  if (head === "eval") {
    const rest = words.slice(1);
    return analyseEvalString(rest.map((w) => w.text).join(" "), rest.some((w) => w.dynamic), "eval", ctx);
  }
  if (SHELLS.has(head)) {
    const at = words.findIndex((w, i) => i > 0 && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(w.text));
    if (at !== -1 && words[at + 1]) {
      const prog = words[at + 1]!;
      return analyseEvalString(prog.text, prog.dynamic, `${head} -c`, ctx);
    }
  }
  if (head === "xargs") {
    const r = analyseXargs(words, c);
    if (r) return r;
  }
  if (head === "find") {
    const r = analyseFind(words);
    if (r) return r;
  }
  const inline = analyseInlineProgram(words);
  if (inline) return inline;

  return analyseIndirection(words, cfg);
}

function analyseEvalString(program: string, dynamic: boolean, via: string, ctx: Ctx): string | null {
  if (dynamic || /[$`]/.test(program)) return `${via} evaluates generated code`;
  if (ctx.depth >= 4) return `${via} nests too deep to inspect`;
  const inner = evaluateBash(program, ctx.cfg, ctx.depth + 1);
  return inner ? `${inner} (via ${via})` : null;
}

/** The Bash policy for scope `destructive`: the reason it is gated, or null. */
export function evaluateBash(command: string, cfg: PolicyConfig, depth = 0): string | null {
  const parsed = parseShell(command);
  const text = parsed.text;
  const pathDirs = (cfg.pathDirs ?? []).filter((d) => d.length > 1);

  for (const { re, label, pathsOnly, writesOnly } of PROTECTED_PATHS) {
    if (!pathsOnly && !writesOnly && re.test(text)) return `touches ${label}`;
  }
  for (const { re, label } of INTERPRETER_WRITE) {
    if (re.test(text)) return label;
  }
  // A write verb plus a directory that is on this hook's own PATH.
  if (pathDirs.length > 0 && new RegExp(WRITE_VERBS, "i").test(text)) {
    for (const d of pathDirs) {
      if (text.includes(d + "/") || text.endsWith(d)) return `writes into PATH directory ${d}`;
    }
  }
  for (const { re, label } of DESTRUCTIVE_COMMANDS) {
    if (re.test(text)) return label;
  }
  // Command substitutions run first and on their own; judge them as commands.
  if (depth < 4) {
    for (const sub of parsed.substitutions) {
      const r = evaluateBash(sub, cfg, depth + 1);
      if (r) return `${r} (in a command substitution)`;
    }
  } else if (parsed.substitutions.length) {
    return "command substitution nests too deep to inspect";
  }
  const ctx: Ctx = { cfg, depth };
  for (const c of parsed.commands) {
    const r = analyseSimple(c, ctx);
    if (r) return r;
  }
  return null;
}

// ---------------------------------------------------------------------------
// MCP tools
// ---------------------------------------------------------------------------

/** Names of MCP tools that read as writes, used only in scope `destructive`. Matched after snake-casing. */
export const MCP_WRITE_VERBS =
  /(^|_)(send|post|publish|create|delete|remove|update|write|merge|pay|transfer|deploy|execute|exec|run|apply|insert|drop|cancel|charge|refund|email|message|reply|comment|upload|invite|revoke|grant|purchase|order|submit|approve|reject|close|archive|move|rename|set|put|patch|edit|add|assign|trigger|dispatch|restart|stop|start|kill|destroy|reset|truncate|migrate|push|commit|release|tag|share|forward|schedule|book|buy|sell|swap|withdraw|deposit|mint|burn|sign|transition|resolve|notify|announce|broadcast|invoke|call|emit|toggle|enable|disable|activate|deactivate|lock|unlock|ban|kick|block|unblock|promote|demote|rotate|generate|provision|deprovision|register|unregister|subscribe|unsubscribe|accept|decline|complete|finish|fulfil|fulfill|ship|dispatch|allocate|reserve|release|escalate|override|force|bypass|wipe|purge|clear|flush|drain|terminate|suspend|resume|redeploy|rollback|scale|exec_sql|query_write)(_|$)/i;

/** SQL that changes data or schema, at the start of a statement. */
const SQL_WRITE =
  /(^|;)\s*(?:(?:--[^\n]*\n|\/\*[\s\S]*?\*\/)\s*)*(INSERT\s+INTO|UPDATE\s+(?:ONLY\s+)?[\w."]+\s+SET|DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|FUNCTION|PROCEDURE|TRIGGER|POLICY|ROLE|USER|EXTENSION|TYPE|SEQUENCE|MATERIALIZED)|ALTER\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|FUNCTION|ROLE|USER|TYPE|SEQUENCE|SYSTEM|POLICY)|TRUNCATE\s+(?:TABLE\s+)?[\w."]+|CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMP\s+|TEMPORARY\s+|UNIQUE\s+|MATERIALIZED\s+)?(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|FUNCTION|PROCEDURE|TRIGGER|POLICY|ROLE|USER|EXTENSION|TYPE|SEQUENCE|DOMAIN|RULE|PUBLICATION|SUBSCRIPTION)|GRANT\s+[\w,\s]+?\s+(?:ON|TO)\b|REVOKE\s+[\w,\s]+?\s+(?:ON|FROM)\b|MERGE\s+INTO|REPLACE\s+INTO)/i;
const HTTP_METHOD_KEYS = /^(method|verb|action|http_method|httpMethod|request_method|requestMethod)$/i;
const HTTP_WRITE_METHODS = /^(POST|PUT|PATCH|DELETE)$/i;

function inspectMcpInput(value: unknown, key: string, depth: number): string | null {
  if (depth > 6) return null;
  if (typeof value === "string") {
    if (HTTP_METHOD_KEYS.test(key) && HTTP_WRITE_METHODS.test(value.trim())) return `input ${key}=${value.trim().toUpperCase()}`;
    const m = SQL_WRITE.exec(value);
    if (m) return `input contains SQL ${m[2]!.split(/\s+/)[0]!.toUpperCase()}`;
    return null;
  }
  if (Array.isArray(value)) {
    for (const v of value) {
      const r = inspectMcpInput(v, key, depth + 1);
      if (r) return r;
    }
    return null;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const r = inspectMcpInput(v, k, depth + 1);
      if (r) return r;
    }
  }
  return null;
}

/** Browser and desktop automation tools: they act on the page unless the action only looks. */
const BROWSER_TOOLS =
  /^(computer|javascript_tool|form_input|navigate|navigate_page|click|fill|fill_form|type_text|type|press_key|key|evaluate_script|drag|select_option|upload_file|file_upload|handle_dialog|run_code(_unsafe)?|new_page|close_page|select_page|emulate|resize_page|resize_window|gif_creator|screencast_(start|stop)|tabs_(create|close)(_mcp)?|browser_batch|batch)$/;
const BROWSER_PREFIX = /^browser_(?!snapshot$|take_screenshot$|console_messages$|network_requests$|find$|wait_for$|hover$|get_page_text$|read_page$)/;
const BROWSER_READ_ACTIONS: ReadonlySet<string> = new Set(["screenshot", "read_page", "get_page_text", "find", "zoom", "wait", "scroll", "hover", "tabs_context", "scroll_to", "get_console_messages", "list_tabs"]);

function browserWrite(tool: string, input: unknown): string | null {
  if (!BROWSER_TOOLS.test(tool) && !BROWSER_PREFIX.test(tool)) return null;
  const action = input && typeof input === "object" ? (input as Record<string, unknown>).action : undefined;
  if (typeof action === "string" && BROWSER_READ_ACTIONS.has(snakeCase(action))) return null;
  return `browser automation "${tool}"${typeof action === "string" ? ` (${action})` : ""}`;
}

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

  if (cfg.extraPatternError) {
    const refuse = `extra_pattern is not a valid regular expression: ${cfg.extraPatternError}`;
    return { gated: true, action, matched: "extra_pattern invalid", refuse };
  }

  const input = (toolInput && typeof toolInput === "object" && !Array.isArray(toolInput) ? toolInput : {}) as Record<string, unknown>;
  // A subject the policy cannot read is not a free pass: the plan builder
  // refuses it, so the call is denied with the reason on record.
  if (toolName === "Bash" && typeof input.command !== "string") return { gated: true, action, matched: "unrecognised input" };
  if (EDIT_TOOLS.has(toolName) && typeof (input.file_path ?? input.notebook_path) !== "string") return { gated: true, action, matched: "unrecognised input" };

  const subject = subjectOf(toolName, toolInput);

  if (cfg.extraPattern) {
    if (cfg.extraPattern.test(subject)) return { gated: true, action, matched: "operator pattern" };
    if (toolName === "Bash" && cfg.extraPattern.test(parseShell(subject).text)) return { gated: true, action, matched: "operator pattern" };
  }

  if (cfg.scope === "all") {
    return { gated: true, action, matched: "scope: all" };
  }

  // scope: destructive
  const pathDirs = (cfg.pathDirs ?? []).filter((d) => d.length > 1);

  if (toolName === "Bash") {
    const matched = evaluateBash(subject, cfg);
    return matched ? { gated: true, action, matched } : { gated: false, action };
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
    const snake = snakeCase(tool);
    if (MCP_WRITE_VERBS.test(snake)) return { gated: true, action, matched: `MCP tool "${tool}" writes` };
    const browser = browserWrite(snake, toolInput);
    if (browser) return { gated: true, action, matched: browser };
    const inspected = inspectMcpInput(toolInput, "", 0);
    if (inspected) return { gated: true, action, matched: `MCP tool "${tool}": ${inspected}` };
    return { gated: false, action };
  }

  if (DELEGATION_TOOLS.has(toolName)) return { gated: true, action, matched: "delegation" };
  return { gated: true, action, matched: `unknown tool "${toolName}"` };
}
