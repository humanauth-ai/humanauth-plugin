// The plan: the one flat object the approver's phone renders and signs, and
// the one the verifier re-hashes before the tool call is allowed. Everything
// the tool will act on is in it, derived from the validated tool input and
// nothing from the model's prose (no `description`). Session and call ids make
// every plan unique, so a receipt for one call can never match another.

import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

export interface HookInput {
  session_id: string;
  tool_name: string;
  tool_input: unknown;
  tool_use_id: string;
  cwd?: string;
  hook_event_name?: string;
  permission_mode?: string;
  agent_id?: string;
  agent_type?: string;
}

export type Plan = Record<string, string | number | boolean>;

export class PlanError extends Error {
  readonly code = "MALFORMED_TOOL_INPUT";
}

/** Longest value that travels in clear; longer values travel as hash + preview. */
export const INLINE_LIMIT = 4000;
export const PREVIEW_LIMIT = 600;
/** Platform limit on the serialized plan (CONTENT_LIMITS.max_plan_bytes). */
export const PLAN_BYTES_LIMIT = 32_768;

const ID = /^[A-Za-z0-9_.:-]{1,200}$/;

export function sha256(s: string): string {
  return "sha256:" + createHash("sha256").update(s, "utf8").digest("hex");
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string") throw new PlanError(`tool_input.${key} must be a string`);
  return v;
}

function optionalString(obj: Record<string, unknown>, key: string): string | undefined {
  const v = obj[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "string") throw new PlanError(`tool_input.${key} must be a string`);
  return v;
}

function textFields(plan: Plan, name: string, value: string): void {
  if (value.length <= INLINE_LIMIT) {
    plan[name] = value;
  } else {
    plan[`${name}_sha256`] = sha256(value);
    plan[`${name}_chars`] = value.length;
    plan[`${name}_preview`] = value.slice(0, PREVIEW_LIMIT);
  }
}

/** Build the plan for a tool call, or throw PlanError when the input is not what the tool expects. */
export function buildPlan(input: HookInput): Plan {
  if (typeof input.session_id !== "string" || !ID.test(input.session_id)) {
    throw new PlanError("session_id missing or malformed");
  }
  if (typeof input.tool_use_id !== "string" || !ID.test(input.tool_use_id)) {
    throw new PlanError("tool_use_id missing or malformed");
  }
  if (typeof input.tool_name !== "string" || input.tool_name.length === 0 || input.tool_name.length > 200) {
    throw new PlanError("tool_name missing or malformed");
  }
  const raw = input.tool_input;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PlanError("tool_input must be an object");
  }
  const obj = raw as Record<string, unknown>;

  const plan: Plan = {
    tool: input.tool_name,
    session: input.session_id,
    call: input.tool_use_id,
  };
  if (typeof input.cwd === "string" && input.cwd.length > 0) plan.cwd = input.cwd.slice(0, 1000);
  if (typeof input.agent_id === "string" && input.agent_id.length > 0) plan.agent = input.agent_id.slice(0, 200);

  switch (input.tool_name) {
    case "Bash": {
      const command = requireString(obj, "command");
      if (command.trim().length === 0) throw new PlanError("tool_input.command is empty");
      textFields(plan, "command", command);
      if (obj.run_in_background === true) plan.background = true;
      break;
    }
    case "Write": {
      const filePath = requireString(obj, "file_path");
      const content = requireString(obj, "content");
      plan.file_path = filePath;
      plan.bytes = Buffer.byteLength(content, "utf8");
      plan.content_sha256 = sha256(content);
      plan.content_preview = content.slice(0, PREVIEW_LIMIT);
      break;
    }
    case "Edit": {
      const filePath = requireString(obj, "file_path");
      const oldS = requireString(obj, "old_string");
      const newS = requireString(obj, "new_string");
      plan.file_path = filePath;
      plan.old_sha256 = sha256(oldS);
      plan.new_sha256 = sha256(newS);
      plan.old_preview = oldS.slice(0, PREVIEW_LIMIT);
      plan.new_preview = newS.slice(0, PREVIEW_LIMIT);
      plan.replace_all = obj.replace_all === true;
      break;
    }
    default: {
      // MultiEdit, NotebookEdit, any other built-in, and every MCP tool: bind
      // the whole input. The phone shows the canonical JSON when it fits.
      const fp = optionalString(obj, "file_path") ?? optionalString(obj, "notebook_path");
      if (fp) plan.file_path = fp;
      const canonical = canonicalize(obj);
      if (canonical === undefined) throw new PlanError("tool_input is not JSON-serialisable");
      textFields(plan, "input", canonical);
      if (!("input" in plan)) plan.input_sha256 = sha256(canonical);
      break;
    }
  }

  const bytes = Buffer.byteLength(JSON.stringify(plan), "utf8");
  if (bytes > PLAN_BYTES_LIMIT) {
    // Only reachable if a path or preview is absurd; refuse rather than trim silently.
    throw new PlanError(`plan is ${bytes} bytes, over the ${PLAN_BYTES_LIMIT} byte limit`);
  }
  return plan;
}

/** sha256 over RFC 8785 canonical JSON, exactly as the platform computes plan_hash. */
export function planHash(plan: Plan): string {
  const canonical = canonicalize(plan);
  if (canonical === undefined) throw new PlanError("plan is not JSON-serialisable");
  return sha256(canonical);
}

/** The caption the phone shows above the plan rows. Derived, not model prose. */
export function describe(input: HookInput, plan: Plan): string {
  const where = typeof input.cwd === "string" && input.cwd ? ` in ${input.cwd.split("/").filter(Boolean).pop() ?? input.cwd}` : "";
  const clip = (s: string, n = 140) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
  switch (input.tool_name) {
    case "Bash": {
      const cmd = typeof plan.command === "string" ? plan.command : String(plan.command_preview ?? "");
      return clip(`Claude Code wants to run${where}: ${cmd.replace(/\s+/g, " ").trim()}`);
    }
    case "Write":
      return clip(`Claude Code wants to write ${plan.bytes} bytes to ${plan.file_path}`);
    case "Edit":
    case "MultiEdit":
    case "NotebookEdit":
      return clip(`Claude Code wants to edit ${plan.file_path ?? "a file"}${where}`);
    default:
      return clip(`Claude Code wants to call ${input.tool_name}${where}`);
  }
}
