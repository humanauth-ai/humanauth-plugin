// Shell structure for the policy. A command line is split into simple
// commands with quoting and backslash escapes resolved, comments and heredoc
// bodies dropped, single-assignment variables expanded (`G=git; $G push`), and
// command substitutions surfaced so the policy can evaluate them on their own.
// Nothing here decides anything; policy.ts does.

export interface Word {
  text: string;
  /** Contains an unresolved expansion (`$VAR`, `$(…)`, `` `…` ``), so what runs is not what is written. */
  dynamic: boolean;
}

export interface Redirect {
  /** `>`, `>>`, `>|`, `&>`, `&>>`, `<`, `<<<`, `>&`, `<&`, optionally fd-prefixed (`2>`). */
  op: string;
  target: Word;
}

export interface SimpleCommand {
  /** Leading `NAME=value` words. */
  assignments: string[];
  /** The command word and its arguments, quotes removed. */
  words: Word[];
  redirects: Redirect[];
  /** Operator before this command: "", ";", "&&", "||", "|", "|&", "&". Newlines read as ";". */
  prev: string;
  /** Operator after this command, same alphabet, "" at the end. */
  next: string;
}

export interface ParsedShell {
  commands: SimpleCommand[];
  /** Bodies of `$(…)` and `` `…` `` found anywhere, outermost first. */
  substitutions: string[];
  /** The command line re-rendered from the structure, for regex matching. */
  text: string;
}

/** Variables whose expansion is a location, not a command: a command word built on them is not "computed". */
const BENIGN_VARS = /^\$(\{)?(HOME|PWD|OLDPWD|TMPDIR|USER|LOGNAME|SHELL|CLAUDE_[A-Z_]+|PROJECT_DIR)(\})?/;

/**
 * `G=git; $G push` → `git; git push`. Only variables assigned exactly once, to
 * a literal, are expanded; anything else stays dynamic and is gated as such.
 */
export function expandSingleAssignments(src: string): string {
  const assigns = new Map<string, string | null>();
  const re = /(^|[\s;&|(])(?:export\s+|local\s+|declare\s+(?:-\w+\s+)?|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=("([^"\n]*)"|'([^'\n]*)'|([^\s;&|'"()]*))/g;
  for (const m of src.matchAll(re)) {
    const name = m[2]!;
    const val = m[4] ?? m[5] ?? m[6] ?? "";
    if (assigns.has(name)) assigns.set(name, null);
    else assigns.set(name, /[$`]/.test(val) ? null : val);
  }
  let out = src;
  for (const [name, val] of assigns) {
    if (val === null) continue;
    out = out.replace(new RegExp(`\\$\\{${name}\\}|\\$${name}(?![A-Za-z0-9_])`, "g"), () => val);
  }
  return out;
}

/** Index just past the `)` that closes a `$(` opened at `open` (index of `(`). */
function closeParen(s: string, open: number): number {
  let depth = 0;
  let i = open;
  let q: string | null = null;
  for (; i < s.length; i++) {
    const c = s[i]!;
    if (q) {
      if (c === "\\" && q === '"') i++;
      else if (c === q) q = null;
      continue;
    }
    if (c === "'" || c === '"') q = c;
    else if (c === "\\") i++;
    else if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return s.length;
}

export function parseShell(src: string): ParsedShell {
  const s = expandSingleAssignments(src);
  const commands: SimpleCommand[] = [];
  const substitutions: string[] = [];
  const n = s.length;
  let i = 0;

  let words: Word[] = [];
  let redirects: Redirect[] = [];
  let assignments: string[] = [];
  let cur = "";
  let curDyn = false;
  let hasWord = false;
  let curQuotedStart = false;
  let pendingRedirect: string | null = null;
  let heredocMarkers: string[] = [];
  let prevOp = "";
  let sawCommandWord = false;

  const flushWord = () => {
    if (!hasWord) return;
    const w: Word = { text: cur, dynamic: curDyn };
    if (pendingRedirect !== null) {
      if (pendingRedirect === "<<" || pendingRedirect === "<<-") heredocMarkers.push(cur);
      else redirects.push({ op: pendingRedirect, target: w });
      pendingRedirect = null;
    } else if (!sawCommandWord && !curQuotedStart && /^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/.test(cur)) {
      assignments.push(cur);
    } else {
      words.push(w);
      sawCommandWord = true;
    }
    cur = "";
    curDyn = false;
    hasWord = false;
    curQuotedStart = false;
  };

  const endCommand = (op: string) => {
    flushWord();
    pendingRedirect = null;
    if (words.length || redirects.length || assignments.length) {
      commands.push({ assignments, words, redirects, prev: prevOp, next: op });
      prevOp = op;
    } else if (op !== ";" && commands.length) {
      // `a | ( b )`: the operator belongs to the command before the empty group.
      commands[commands.length - 1]!.next = op;
      prevOp = op;
    }
    words = [];
    redirects = [];
    assignments = [];
    sawCommandWord = false;
  };

  /** Skip heredoc bodies that follow the newline at `at`; returns the index to resume at. */
  const skipHeredocs = (at: number): number => {
    let pos = at;
    for (const marker of heredocMarkers) {
      const lines: Array<[number, number]> = [];
      let p = pos;
      while (p < n) {
        const nl = s.indexOf("\n", p);
        const end = nl === -1 ? n : nl;
        lines.push([p, end]);
        p = end + 1;
      }
      const term = lines.findIndex(([a, b]) => s.slice(a, b).replace(/^\t+/, "") === marker);
      if (term === -1) return pos; // unterminated: keep the text, drop nothing
      pos = Math.min(n, lines[term]![1] + 1);
    }
    heredocMarkers = [];
    return pos;
  };

  const startWord = () => {
    if (!hasWord) {
      hasWord = true;
      curQuotedStart = false;
    }
  };

  while (i < n) {
    const c = s[i]!;

    if (c === "'" ) {
      if (!hasWord) curQuotedStart = true;
      startWord();
      const end = s.indexOf("'", i + 1);
      cur += s.slice(i + 1, end === -1 ? n : end);
      i = end === -1 ? n : end + 1;
      continue;
    }
    if (c === '"') {
      if (!hasWord) curQuotedStart = true;
      startWord();
      i++;
      while (i < n && s[i] !== '"') {
        const d = s[i]!;
        if (d === "\\" && i + 1 < n && /["\\$`\n]/.test(s[i + 1]!)) {
          if (s[i + 1] !== "\n") cur += s[i + 1];
          i += 2;
          continue;
        }
        if (d === "$" && s[i + 1] === "(") {
          const end = closeParen(s, i + 1);
          substitutions.push(s.slice(i + 2, end - 1));
          cur += s.slice(i, end);
          curDyn = true;
          i = end;
          continue;
        }
        if (d === "`") {
          const end = s.indexOf("`", i + 1);
          const stop = end === -1 ? n : end;
          substitutions.push(s.slice(i + 1, stop));
          cur += s.slice(i, Math.min(n, stop + 1));
          curDyn = true;
          i = stop + 1;
          continue;
        }
        if (d === "$" && !(cur.length === 0 && BENIGN_VARS.test(s.slice(i, i + 40)))) curDyn = true;
        cur += d;
        i++;
      }
      i++;
      continue;
    }
    if (c === "\\") {
      if (s[i + 1] === "\n") {
        i += 2;
        continue;
      }
      startWord();
      if (i + 1 < n) cur += s[i + 1];
      i += 2;
      continue;
    }
    if (c === "$" && s[i + 1] === "(") {
      startWord();
      const end = closeParen(s, i + 1);
      substitutions.push(s.slice(i + 2, end - 1));
      cur += s.slice(i, end);
      curDyn = true;
      i = end;
      continue;
    }
    if (c === "`") {
      startWord();
      const end = s.indexOf("`", i + 1);
      const stop = end === -1 ? n : end;
      substitutions.push(s.slice(i + 1, stop));
      cur += s.slice(i, Math.min(n, stop + 1));
      curDyn = true;
      i = stop + 1;
      continue;
    }
    if (c === "$") {
      startWord();
      if (!(cur.length === 0 && BENIGN_VARS.test(s.slice(i, i + 40)))) curDyn = true;
      cur += c;
      i++;
      continue;
    }
    if (c === "#" && !hasWord) {
      const nl = s.indexOf("\n", i);
      i = nl === -1 ? n : nl;
      continue;
    }
    if (c === "\n") {
      endCommand(";");
      i++;
      if (heredocMarkers.length) i = skipHeredocs(i);
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") {
      flushWord();
      i++;
      continue;
    }
    if (c === ";") {
      endCommand(";");
      i += s[i + 1] === ";" ? 2 : 1;
      continue;
    }
    if (c === "&") {
      if (s[i + 1] === "&") {
        endCommand("&&");
        i += 2;
      } else if (s[i + 1] === ">") {
        flushWord();
        pendingRedirect = s[i + 2] === ">" ? "&>>" : "&>";
        i += s[i + 2] === ">" ? 3 : 2;
      } else {
        endCommand("&");
        i++;
      }
      continue;
    }
    if (c === "|") {
      if (s[i + 1] === "|") {
        endCommand("||");
        i += 2;
      } else if (s[i + 1] === "&") {
        endCommand("|&");
        i += 2;
      } else {
        endCommand("|");
        i++;
      }
      continue;
    }
    if (c === "(" || c === ")") {
      endCommand(";");
      i++;
      continue;
    }
    if (c === ">" || c === "<") {
      // A lone digit before the operator is a file descriptor, not a word.
      let fd = "";
      if (hasWord && /^\d$/.test(cur) && !curQuotedStart) {
        fd = cur;
        cur = "";
        hasWord = false;
      } else {
        flushWord();
      }
      let op = c;
      if (s[i + 1] === c) {
        op += c;
        if (c === "<" && s[i + 2] === "<") op += "<";
        else if (c === "<" && s[i + 2] === "-") op += "-";
      } else if (c === ">" && (s[i + 1] === "|" || s[i + 1] === "&")) op += s[i + 1];
      else if (c === "<" && s[i + 1] === "&") op += "&";
      i += op.length;
      pendingRedirect = fd + op;
      continue;
    }
    if ((c === "{" || c === "}") && !hasWord && (i + 1 >= n || /[\s;&|]/.test(s[i + 1]!))) {
      i++;
      continue;
    }
    startWord();
    cur += c;
    i++;
  }
  endCommand("");

  return { commands, substitutions, text: render(commands) };
}

const OUTPUT_ONLY = new Set(["echo", "printf"]);

export function baseName(p: string): string {
  const i = p.lastIndexOf("/");
  return i === -1 ? p : p.slice(i + 1);
}

/**
 * Re-render for regex matching: quotes gone, comments and heredoc bodies gone,
 * and the arguments of `echo`/`printf` dropped unless their output is piped
 * into another command, so text that is merely printed cannot gate.
 */
function render(cmds: SimpleCommand[]): string {
  const parts: string[] = [];
  for (const c of cmds) {
    const head = c.words[0] ? baseName(c.words[0].text) : "";
    const piped = c.next === "|" || c.next === "|&";
    const words = OUTPUT_ONLY.has(head) && !piped ? [c.words[0]!.text] : c.words.map((w) => w.text);
    const seg = [...c.assignments, ...words, ...c.redirects.map((r) => `${r.op} ${r.target.text}`)].join(" ");
    parts.push(seg);
    if (c.next) parts.push(` ${c.next} `);
  }
  return parts.join("").trim();
}
