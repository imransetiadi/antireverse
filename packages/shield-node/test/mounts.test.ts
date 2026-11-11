// Review finding F2: a concrete URL segment must never become part of the recorded route, also when Shield
// is installed below a mount path, or when a mount is a regular expression.
import { UNMATCHED_ROUTE } from "@antireverse/protocol";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Captured, captureShield, type Listening, listen } from "./helpers.ts";

const ok: express.RequestHandler = (_req, res) => void res.send("ok");

describe("route templates below and beside awkward mounts", () => {
  const captured: Captured = captureShield();
  let listening: Listening;
  let seen = 0;

  beforeAll(async () => {
    const app = express();

    // Shield on a router that is itself mounted on a parameterised path: ordinary Express usage.
    const api = express.Router();
    api.use(captured.shield.express());
    api.get("/apps/:appId", ok);
    const nested = express.Router();
    nested.get("/keys/:keyId", ok);
    api.use("/teams/:teamId", nested);
    app.use("/orgs/:orgId", api);

    // Shield on the application, with regular-expression mounts.
    const second = express();
    second.use(captured.shield.express());
    const profile = express.Router();
    profile.get("/profile", ok);
    second.use(/^\/users\/\d+/, profile);
    second.use(/^\/members\/(\d+)-[a-z]+/, profile);
    second.use(/^\/tenants\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, profile);
    second.use("/v2", profile);
    app.use("/second", second);

    listening = await listen(app);
  });
  afterAll(() => listening.stop());

  async function hit(path: string): Promise<{ status: number; route: string; body: string }> {
    const before = captured.requests.length;
    const response = await fetch(listening.base + path);
    await response.arrayBuffer();
    seen += 1;
    const events = await captured.events(seen);
    expect(events).toHaveLength(seen);
    const body = captured.requests
      .slice(before)
      .map((request) => request.body)
      .join("\n");
    return { status: response.status, route: (events.at(-1) as (typeof events)[number]).request.route, body };
  }

  it("records a placeholder for the path above Shield and the template below it", async () => {
    const result = await hit("/orgs/SECRETORG9/apps/SECRETAPP7?token=zqtoken");
    expect(result.status).toBe(200);
    expect(result.route).toBe("(mount)/apps/:appId");
    expect(result.body.toLowerCase()).not.toContain("secretorg9");
    expect(result.body.toLowerCase()).not.toContain("secretapp7");
    expect(result.body).not.toContain("zqtoken");
  });

  it("still templates a parameterised mount below Shield", async () => {
    const result = await hit("/orgs/SECRETORG9/teams/SECRETTEAM3/keys/SECRETKEY5");
    expect(result.status).toBe(200);
    expect(result.route).toBe("(mount)/teams/:teamId/keys/:keyId");
    expect(result.body.toLowerCase()).not.toMatch(/secretorg9|secretteam3|secretkey5/);
  });

  it.each([
    ["/second/users/424242/profile", "424242"],
    ["/second/members/424242-secretname/profile", "secretname"],
    ["/second/tenants/0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0/profile", "0b1c2d3e"],
  ])("records (unmatched) for %s: a regular-expression mount has no template", async (path, secret) => {
    const result = await hit(path);
    expect(result.status).toBe(200);
    expect(result.route).toBe(UNMATCHED_ROUTE);
    expect(result.body).not.toContain(secret);
    expect(result.body).not.toContain("424242");
  });

  it("keeps a literal mount path that merely contains a digit", async () => {
    const result = await hit("/second/v2/profile");
    expect(result.status).toBe(200);
    expect(result.route).toBe("(mount)/v2/profile");
  });
});
