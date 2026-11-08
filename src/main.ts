// Entry point for the PreToolUse command hook. Reads the hook JSON on stdin,
// prints one JSON decision on stdout. Any unexpected failure prints a deny:
// a hook that crashes must never let the call through.

import { runHook, configFromEnv } from "./hook.js";
import type { HookInput } from "./plan.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function emit(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function deny(reason: string): void {
  emit({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `HumanAuth: ${reason}` } });
}

async function main(): Promise<void> {
  const raw = await readStdin();
  let input: HookInput;
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
    deny("hook received malformed JSON; refusing the call");
    return;
  }
  if (input.hook_event_name && input.hook_event_name !== "PreToolUse") return;

  const cfg = configFromEnv(process.env);
  const result = await runHook(input, cfg, { fetch: globalThis.fetch });
  if (result) emit(result);
}

main().catch((e: unknown) => {
  deny(`hook failed (${e instanceof Error ? e.message : String(e)}); refusing the call`);
  process.exitCode = 0;
});
