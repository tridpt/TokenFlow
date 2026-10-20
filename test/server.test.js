import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { request as httpRequest } from "node:http";
import { createApp } from "../server.js";

const input = {
  endpoint: "https://auth.example.com/token",
  refreshToken: "test-refresh-only",
  authMethod: "none",
};
let upstreamCalls = 0;
const app = createApp({
  fetchImpl: async () => {
    upstreamCalls++;
    return new Response(
      JSON.stringify({ access_token: "test-access-only", expires_in: 3600 }),
      { headers: { "Content-Type": "application/json" } },
    );
  },
});
app.listen(0, "127.0.0.1");
await once(app, "listening");
const baseUrl = `http://127.0.0.1:${app.address().port}`;
test.after(() => {
  app.closeAllConnections();
  app.close();
});

function post(body, headers = {}) {
  return fetch(`${baseUrl}/api/refresh`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-TokenFlow-Request": "1",
      ...headers,
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

test("serves the complete interface and security headers without caching", async () => {
  for (const [path, type] of [
    ["/", "text/html"],
    ["/app.js", "text/javascript"],
    ["/profiles.js", "text/javascript"],
    ["/styles.css", "text/css"],
    ["/favicon.svg", "image/svg+xml"],
  ]) {
    const response = await fetch(`${baseUrl}${path}`);
    assert.equal(response.status, 200);
    assert.ok(response.headers.get("content-type").startsWith(type));
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.match(
      response.headers.get("content-security-policy"),
      /frame-ancestors 'none'/,
    );
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.ok((await response.text()).length > 0);
  }
});

test("reports local server health", async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  assert.deepEqual(await response.json(), { status: "ok", version: "1.0.0" });
});

test("supports a complete same-origin refresh request", async () => {
  const response = await post(input, { Origin: baseUrl });
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.token.access_token, "test-access-only");
  assert.equal(result.token.expires_in, 3600);
  assert.equal(result.token.refresh_token, undefined);
});

test("supports Codex profile requests and rejects conflicting configuration", async () => {
  const response = await post({
    profile: "codex",
    refreshToken: "dummy-codex-refresh",
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).token.access_token, "test-access-only");
  const before = upstreamCalls;
  const conflicting = await post({
    profile: "codex",
    refreshToken: "dummy-codex-refresh",
    clientId: "wrong-client-id",
  });
  assert.equal(conflicting.status, 400);
  assert.equal((await conflicting.json()).error.code, "invalid_input");
  assert.equal(upstreamCalls, before);
});

test("accepts each additional service through the local API and rejects mismatched endpoints", async () => {
  for (const profile of ["google", "microsoft", "github", "discord"]) {
    const payload = {
      profile,
      refreshToken: "dummy-service-refresh",
      clientId: "original-service-client",
      ...(profile !== "microsoft" ? { clientSecret: "dummy-service-secret" } : { tenant: "consumers" }),
    };
    const response = await post(payload, { Origin: baseUrl });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).token.access_token, "test-access-only");
    const before = upstreamCalls;
    const conflicting = await post({ ...payload, endpoint: "https://other.example/token" });
    assert.equal(conflicting.status, 400);
    assert.equal((await conflicting.json()).error.code, "invalid_input");
    assert.equal(upstreamCalls, before);
  }
});

test("rejects cross-origin and cross-site requests before contacting the provider", async () => {
  const before = upstreamCalls;
  for (const headers of [
    { Origin: "https://untrusted.example" },
    { Origin: "null" },
    { "Sec-Fetch-Site": "cross-site" },
  ]) {
    const response = await post(input, headers);
    assert.equal(response.status, 403);
    await response.text();
  }
  assert.equal(upstreamCalls, before);
});

test("rejects forged host headers to protect the local API from DNS rebinding", async () => {
  const status = await new Promise((resolve, reject) => {
    const req = httpRequest(
      `${baseUrl}/api/health`,
      { headers: { Host: `attacker.example:${app.address().port}` } },
      (response) => {
        response.resume();
        response.on("end", () => resolve(response.statusCode));
      },
    );
    req.on("error", reject);
    req.end();
  });
  assert.equal(status, 403);
});

test("requires the custom request header and JSON content type", async () => {
  const missingHeader = await fetch(`${baseUrl}/api/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  assert.equal(missingHeader.status, 403);
  await missingHeader.text();
  const wrongType = await post(input, { "Content-Type": "text/plain" });
  assert.equal(wrongType.status, 415);
  await wrongType.text();
});

test("rejects malformed, oversized and invalid input without provider calls", async () => {
  const before = upstreamCalls;
  const malformed = await post("bad-json");
  assert.equal(malformed.status, 400);
  assert.equal((await malformed.json()).error.code, "invalid_json");
  const oversized = await post(
    JSON.stringify({ ...input, refreshToken: "x".repeat(262145) }),
  );
  assert.equal(oversized.status, 413);
  await oversized.text();
  const invalid = await post({
    ...input,
    endpoint: "http://example.com/token",
  });
  assert.equal(invalid.status, 400);
  await invalid.text();
  assert.equal(upstreamCalls, before);
});

test("serves neither source files nor unknown paths and rejects wrong API methods", async () => {
  for (const path of [
    "/server.js",
    "/src/oauth.js",
    "/package.json",
    "/unknown",
  ]) {
    const response = await fetch(`${baseUrl}${path}`);
    assert.equal(response.status, 404);
    await response.text();
  }
  const wrongMethod = await fetch(`${baseUrl}/api/refresh`);
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.headers.get("allow"), "POST");
  await wrongMethod.text();
});

test("returns a safe error if the upstream implementation fails", async (t) => {
  const failingApp = createApp({
    fetchImpl: async () => {
      throw new Error("network leaked-secret");
    },
  });
  failingApp.listen(0, "127.0.0.1");
  await once(failingApp, "listening");
  t.after(() => {
    failingApp.closeAllConnections();
    failingApp.close();
  });
  const response = await fetch(
    `http://127.0.0.1:${failingApp.address().port}/api/refresh`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-TokenFlow-Request": "1",
      },
      body: JSON.stringify(input),
    },
  );
  assert.equal(response.status, 502);
  const text = await response.text();
  assert.equal(text.includes("leaked-secret"), false);
  assert.equal(JSON.parse(text).error.code, "connection_failed");
});
