// A scripted HumanAuth platform behind a `fetch` function: creates requests,
// serves their detail, and resolves them the way the test says, minting real
// signed receipts with @humanauth/verifier's own fixtures.

import {
  generatePlatformKeys,
  generateDeviceKeys,
  mintTestReceipt,
  mockJwks,
  type PlatformKeys,
  type DeviceKeys,
} from "@humanauth/verifier/fixtures";
import type { JWK } from "jose";

export type Outcome =
  | {
      kind: "approve";
      approver?: string;
      planOverride?: unknown;
      jti?: string;
      requestIdOverride?: string;
      assurance?: "tap" | "biometric" | "elevated";
      approval?: { threshold: number; required_principals?: string[] };
    }
  | { kind: "deny" }
  | { kind: "expire" }
  | { kind: "pending" }
  | { kind: "http_error"; status: number }
  | { kind: "network_error" };

export interface Recorded {
  authorizeBodies: unknown[];
  detailPolls: number;
}

export interface FakePlatform {
  fetch: typeof fetch;
  jwks: { keys: JWK[] };
  tenantId: string;
  approver: string;
  recorded: Recorded;
  setOutcome(o: Outcome): void;
  keys: { platform: PlatformKeys; device: DeviceKeys };
  /** Mint a receipt outside the request flow (for replay tests). */
  mint(args: {
    plan: unknown;
    action: string;
    requestId: string;
    jti?: string;
    approver?: string;
    assurance?: "tap" | "biometric" | "elevated";
    approval?: { threshold: number; required_principals?: string[] };
  }): Promise<string>;
}

export async function createFakePlatform(opts: { baseUrl: string; tenantId?: string; approver?: string; issuer?: string }): Promise<FakePlatform> {
  const tenantId = opts.tenantId ?? "ten_test";
  const approver = opts.approver ?? "hu_alice";
  const issuer = opts.issuer ?? opts.baseUrl;
  const platform = await generatePlatformKeys("kid_test");
  const device = await generateDeviceKeys();
  const deviceKeys = new Map<string, DeviceKeys>([["dev_1", device]]);
  const jwks = await mockJwks(platform.publicKey, platform.kid);

  let outcome: Outcome = { kind: "approve" };
  let counter = 0;
  const requests = new Map<string, { action: string; plan: unknown; ttl: number; polls: number; jws?: string }>();
  const recorded: Recorded = { authorizeBodies: [], detailPolls: 0 };

  const mint: FakePlatform["mint"] = async ({ plan, action, requestId, jti, approver: who, assurance, approval }) =>
    mintTestReceipt({
      plan,
      action,
      audience: tenantId,
      subject: who ?? approver,
      approvers: [{ huid: who ?? approver, device_id: "dev_1", assurance: assurance ?? "biometric" }],
      platformKeys: platform,
      deviceKeys,
      requestId,
      jti,
      issuer,
      expiresInSeconds: 600,
      approval,
    });

  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  const fetchImpl: typeof fetch = async (url, init) => {
    const u = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;
    const path = u.replace(opts.baseUrl, "");
    const method = init?.method ?? "GET";
    // JWKS is public, like the real platform's.
    if (path === "/.well-known/jwks.json") return json(200, jwks);

    const auth = (init?.headers as Record<string, string> | undefined)?.Authorization ?? "";
    if (!auth.startsWith("Bearer ")) return json(401, { error: { code: "unauthorized", message: "no api key" } });

    if (outcome.kind === "network_error") throw new TypeError("fetch failed");
    if (outcome.kind === "http_error") return json(outcome.status, { error: { code: "boom", message: "scripted failure" } });

    if (method === "POST" && path === "/v1/authorize") {
      const body = JSON.parse(String(init?.body ?? "{}"));
      recorded.authorizeBodies.push(body);
      const id = `req_${++counter}`;
      requests.set(id, { action: body.action, plan: body.plan, ttl: body.ttl, polls: 0 });
      return json(200, { request_id: id, status: "pending", target_type: "human", target_id: approver, devices_count: 1, ttl: body.ttl, expires_at: new Date(Date.now() + body.ttl * 1000).toISOString() });
    }

    const m = path.match(/^\/v1\/requests\/([^/?]+)$/);
    if (method === "GET" && m) {
      const req = requests.get(decodeURIComponent(m[1]!));
      if (!req) return json(404, { error: { code: "not_found", message: "no such request" } });
      req.polls += 1;
      recorded.detailPolls += 1;
      // Same shape as production GET /v1/requests/:id: the tenant is nested
      // (`tenant.tenant_id`), not a top-level `tenant_id` (that is the list
      // endpoint's shape; v0.1.1 read the wrong one and failed closed live).
      const common = { request_id: m[1], tenant: { tenant_id: tenantId, name: "Fake tenant" }, tenant_name: "Fake tenant", action: req.action, target_type: "human", target_id: approver, ttl: req.ttl, plan: req.plan, decisions: [] };
      // First poll is the tenant lookup: still pending. Later polls resolve.
      if (req.polls <= 1 || outcome.kind === "pending") return json(200, { ...common, status: "delivered" });
      if (outcome.kind === "deny") return json(200, { ...common, status: "decided", result: "denied", receipt_id: "rct_denied" });
      if (outcome.kind === "expire") return json(200, { ...common, status: "expired", result: "expired" });
      if (outcome.kind === "approve") {
        if (!req.jws) {
          req.jws = await mint({
            plan: outcome.planOverride ?? req.plan,
            action: req.action,
            requestId: outcome.requestIdOverride ?? m[1]!,
            jti: outcome.jti,
            approver: outcome.approver,
            assurance: outcome.assurance,
            approval: outcome.approval,
          });
        }
        return json(200, { ...common, status: "decided", result: "approved", receipt_id: "rct_1", receipt_jws: req.jws });
      }
    }
    return json(404, { error: { code: "not_found", message: path } });
  };

  return {
    fetch: fetchImpl,
    jwks,
    tenantId,
    approver,
    recorded,
    setOutcome: (o) => {
      outcome = o;
    },
    keys: { platform, device },
    mint,
  };
}
