import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import {
  buildTokenRequest,
  normalizeRequest,
  OAuthError,
  refreshAccessToken,
} from "../src/oauth.js";
import { CODEX_PROFILE } from "../public/profiles.js";

const base = {
  endpoint: "https://auth.example.com/oauth/token",
  refreshToken: "example-refresh-value",
  clientId: "example-client",
  authMethod: "none",
};
const jsonResponse = (data, options) =>
  new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
const refresh = (input, response) =>
  refreshAccessToken(input, { fetchImpl: async () => response });

test("Codex profile sends the public Codex client ID to its exact endpoint without a secret", async () => {
  let captured;
  const result = await refreshAccessToken(
    { profile: "codex", refreshToken: "dummy-codex-refresh" },
    {
      fetchImpl: async (url, options) => {
        captured = { url, options };
        return jsonResponse({ access_token: "dummy-codex-access" });
      },
    },
  );
  assert.equal(captured.url, CODEX_PROFILE.endpoint);
  const body = new URLSearchParams(captured.options.body);
  assert.equal(body.get("client_id"), CODEX_PROFILE.clientId);
  assert.equal(body.get("refresh_token"), "dummy-codex-refresh");
  assert.equal(body.get("grant_type"), "refresh_token");
  assert.equal(body.has("client_secret"), false);
  assert.equal(body.has("scope"), false);
  assert.equal(captured.options.headers.Authorization, undefined);
  assert.equal(result.token.access_token, "dummy-codex-access");
});

test("rejects modified Codex endpoints, client IDs and authentication before sending credentials", async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;
    return jsonResponse({ access_token: "unused" });
  };
  for (const override of [
    { endpoint: "https://other.example/token" },
    { clientId: "wrong-client-id" },
    { authMethod: "body" },
    { clientSecret: "unexpected-secret" },
    { profile: "unknown-profile" },
  ]) {
    await assert.rejects(
      refreshAccessToken(
        { profile: "codex", refreshToken: "dummy-codex-refresh", ...override },
        { fetchImpl },
      ),
      (error) => error.code === "invalid_input",
    );
  }
  assert.equal(called, false);
});

test("Custom mode keeps the original client configuration for separately issued tokens", () => {
  const input = normalizeRequest({
    ...base,
    profile: "custom",
    clientId: "separately-issued-client-id",
  });
  assert.equal(input.clientId, "separately-issued-client-id");
  assert.equal(input.endpoint, base.endpoint);
});

for (const [profile, endpoint, authMethod] of [
  ["google", "https://oauth2.googleapis.com/token", "body"],
  ["microsoft", "https://login.microsoftonline.com/common/oauth2/v2.0/token", "none"],
  ["github", "https://github.com/login/oauth/access_token", "body"],
  ["discord", "https://discord.com/api/oauth2/token", "basic"],
]) {
  test(`${profile} sends credentials to its official endpoint using the default authentication`, async () => {
    let captured;
    const result = await refreshAccessToken(
      {
        profile,
        refreshToken: "dummy-provider-refresh",
        clientId: "original-app-client",
        ...(authMethod !== "none" ? { clientSecret: "dummy-app-secret" } : {}),
      },
      {
        fetchImpl: async (url, options) => {
          captured = { url, options };
          return jsonResponse({
            access_token: "dummy-provider-access",
            refresh_token: "dummy-provider-rotated-refresh",
          });
        },
      },
    );
    assert.equal(captured.url, endpoint);
    const body = new URLSearchParams(captured.options.body);
    assert.equal(body.get("grant_type"), "refresh_token");
    assert.equal(body.get("refresh_token"), "dummy-provider-refresh");
    assert.equal(captured.options.redirect, "manual");
    if (authMethod === "basic") {
      assert.equal(
        Buffer.from(captured.options.headers.Authorization.slice(6), "base64").toString(),
        "original-app-client:dummy-app-secret",
      );
      assert.equal(body.has("client_id"), false);
      assert.equal(body.has("client_secret"), false);
    } else {
      assert.equal(captured.options.headers.Authorization, undefined);
      assert.equal(body.get("client_id"), "original-app-client");
      assert.equal(body.get("client_secret"), authMethod === "body" ? "dummy-app-secret" : null);
    }
    assert.equal(result.token.access_token, "dummy-provider-access");
    assert.equal(result.token.refresh_token, "dummy-provider-rotated-refresh");
  });
}

test("Microsoft supports account audiences, tenant IDs and tenant domains without putting tenant in the form body", () => {
  for (const tenant of [
    "common",
    "consumers",
    "organizations",
    "00000000-0000-0000-0000-000000000001",
    "example.onmicrosoft.com",
  ]) {
    const input = normalizeRequest({
      profile: "microsoft",
      tenant,
      clientId: "original-microsoft-client",
      refreshToken: "dummy-microsoft-refresh",
    });
    assert.equal(input.endpoint, `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`);
    assert.equal(new URLSearchParams(buildTokenRequest(input).body).has("tenant"), false);
  }
});

test("preset validation blocks changed endpoints, invalid tenant paths and unsupported auth before contacting a provider", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    return jsonResponse({ access_token: "unused" });
  };
  const invalidCases = [];
  for (const profile of ["google", "microsoft", "github", "discord"]) {
    invalidCases.push(
      { profile, endpoint: "https://untrusted.example/token" },
      { profile, clientId: "" },
      { profile, clientId: undefined },
      { profile, authMethod: profile === "discord" ? "none" : "basic" },
    );
  }
  for (const tenant of ["", "..", "common/../other", "common?x=1", "a#fragment", "a%2Fb", "a@host", "a\\b", {}, 123]) {
    invalidCases.push({ profile: "microsoft", tenant });
  }
  invalidCases.push(
    { profile: "microsoft", tenant: "consumers", endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token" },
    { profile: "google", authMethod: "none", clientSecret: "unexpected" },
    { profile: "__proto__" },
    { profile: "toString" },
  );
  for (const invalidCase of invalidCases) {
    await assert.rejects(
      refreshAccessToken({
        clientId: "dummy-client",
        refreshToken: "dummy-refresh",
        ...invalidCase,
      }, { fetchImpl }),
      (error) => error.code === "invalid_input",
    );
  }
  assert.equal(calls, 0);
});

test("presets accept documented public-client and body-secret authentication variants", () => {
  for (const profile of ["google", "microsoft", "github"]) {
    const request = buildTokenRequest(normalizeRequest({
      profile,
      clientId: "original-public-client",
      refreshToken: "dummy-public-refresh",
      authMethod: "none",
    }));
    const body = new URLSearchParams(request.body);
    assert.equal(body.get("client_id"), "original-public-client");
    assert.equal(body.has("client_secret"), false);
    assert.equal(request.headers.Authorization, undefined);
  }
  for (const profile of ["google", "microsoft", "github", "discord"]) {
    const request = buildTokenRequest(normalizeRequest({
      profile,
      clientId: "original-confidential-client",
      clientSecret: "dummy-confidential-secret",
      refreshToken: "dummy-confidential-refresh",
      authMethod: "body",
    }));
    const body = new URLSearchParams(request.body);
    assert.equal(body.get("client_id"), "original-confidential-client");
    assert.equal(body.get("client_secret"), "dummy-confidential-secret");
    assert.equal(request.headers.Authorization, undefined);
  }
});

test("validates endpoint protocols, credentials and fragments before sending anything", () => {
  for (const endpoint of [
    "not a url",
    "http://example.com/token",
    "file:///etc/passwd",
    "ftp://example.com/token",
    "https://user:pass@example.com/token",
    "https://example.com/token#secret",
  ]) {
    assert.throws(
      () => normalizeRequest({ ...base, endpoint }),
      (error) => error instanceof OAuthError && error.status === 400,
    );
  }
  for (const endpoint of [
    "https://example.com/token",
    "http://localhost:9000/token",
    "http://127.0.0.1:9000/token",
    "http://[::1]:9000/token",
  ]) {
    assert.equal(normalizeRequest({ ...base, endpoint }).endpoint, endpoint);
  }
});

test("rejects empty and wrong-type fields, excessive sizes and invalid auth methods", () => {
  for (const input of [
    null,
    [],
    "string",
    {},
    { ...base, refreshToken: "  " },
    { ...base, refreshToken: 123 },
    { ...base, refreshToken: "x".repeat(65537) },
    { ...base, authMethod: "digest" },
    { ...base, authMethod: "body" },
    { ...base, authMethod: "basic", clientSecret: "secret", clientId: "" },
  ]) {
    assert.throws(() => normalizeRequest(input), OAuthError);
  }
});

test("trims pasted token boundaries and preserves significant secret whitespace", () => {
  const input = normalizeRequest({
    ...base,
    refreshToken: "  refresh-with-boundaries\n",
    clientSecret: " secret with spaces ",
  });
  assert.equal(input.refreshToken, "refresh-with-boundaries");
  assert.equal(input.clientSecret, " secret with spaces ");
});

test("allows public clients without a client ID and does not send unused secrets", () => {
  const input = normalizeRequest({
    ...base,
    clientId: "",
    clientSecret: "not-used",
  });
  const request = buildTokenRequest(input);
  const body = new URLSearchParams(request.body);
  assert.equal(body.get("grant_type"), "refresh_token");
  assert.equal(body.get("refresh_token"), base.refreshToken);
  assert.equal(body.has("client_id"), false);
  assert.equal(body.has("client_secret"), false);
  assert.equal(request.headers.Authorization, undefined);
  assert.equal(request.redirect, "manual");
});

test("builds form-body authentication with correctly escaped tokens, scope and extra fields", () => {
  const request = buildTokenRequest(
    normalizeRequest({
      ...base,
      authMethod: "body",
      refreshToken: "refresh+&=secret",
      clientSecret: "secret+&=value",
      scope: "read write",
      extraParams: [{ key: "audience", value: "https://api.example.com" }],
    }),
  );
  const body = new URLSearchParams(request.body);
  assert.equal(request.method, "POST");
  assert.equal(
    request.headers["Content-Type"],
    "application/x-www-form-urlencoded",
  );
  assert.equal(body.get("client_id"), base.clientId);
  assert.equal(body.get("client_secret"), "secret+&=value");
  assert.equal(body.get("refresh_token"), "refresh+&=secret");
  assert.equal(body.get("scope"), "read write");
  assert.equal(body.get("audience"), "https://api.example.com");
});

test("Basic authentication form-encodes credentials before base64 and omits body credentials", () => {
  const request = buildTokenRequest(
    normalizeRequest({
      ...base,
      clientId: "id: +@",
      clientSecret: "secret:/ +",
      authMethod: "basic",
    }),
  );
  const decoded = Buffer.from(
    request.headers.Authorization.slice(6),
    "base64",
  ).toString("utf8");
  assert.equal(decoded, "id%3A+%2B%40:secret%3A%2F+%2B");
  const body = new URLSearchParams(request.body);
  assert.equal(body.has("client_id"), false);
  assert.equal(body.has("client_secret"), false);
});

test("rejects extra parameter overrides, duplicate keys, invalid keys and excessive lists", () => {
  for (const extraParams of [
    [{ key: "refresh_token", value: "override" }],
    [{ key: "CLIENT_SECRET", value: "override" }],
    [{ key: "scope", value: "override" }],
    [{ key: "grant_type", value: "override" }],
    [
      { key: "a", value: "1" },
      { key: "a", value: "2" },
    ],
    [{ key: "a b", value: "1" }],
    [{ key: "", value: "1" }],
    [{ key: "audience", value: {} }],
    [null],
    {},
    Array.from({ length: 21 }, (_, i) => ({ key: `param${i}`, value: "x" })),
  ])
    assert.throws(() => normalizeRequest({ ...base, extraParams }), OAuthError);
});

test("normalizes a successful token response including refresh-token rotation", async () => {
  const result = await refresh(
    base,
    jsonResponse({
      access_token: "new-access-token",
      token_type: "Bearer",
      expires_in: "3600",
      scope: "read write",
      refresh_token: "rotated-refresh-token",
      id_token: "example-id-token",
      provider_specific: "ignored",
    }),
  );
  assert.deepEqual(result.token, {
    access_token: "new-access-token",
    token_type: "Bearer",
    expires_in: 3600,
    scope: "read write",
    refresh_token: "rotated-refresh-token",
    id_token: "example-id-token",
  });
  assert.ok(Number.isFinite(Date.parse(result.receivedAt)));
  assert.ok(result.durationMs >= 0);
});

test("handles missing token metadata and does not invent an expiry", async () => {
  const result = await refresh(
    base,
    jsonResponse({ access_token: "opaque-access" }),
  );
  assert.deepEqual(result.token, {
    access_token: "opaque-access",
    token_type: "Bearer",
  });
});

test("normalizes zero expiry and ignores malformed expiry instead of showing a false lifetime", async () => {
  assert.equal(
    (
      await refresh(
        base,
        jsonResponse({ access_token: "access", expires_in: 0 }),
      )
    ).token.expires_in,
    0,
  );
  for (const expires_in of ["", " ", -1, null, {}, true, "not a number", 1.5]) {
    const result = await refresh(
      base,
      jsonResponse({ access_token: "access", expires_in }),
    );
    assert.equal(result.token.expires_in, undefined);
  }
});

test("surfaces invalid_grant and redacts credentials from upstream error details", async () => {
  const input = {
    ...base,
    clientSecret: "client-secret-value",
    authMethod: "body",
    extraParams: [{ key: "resource", value: "private-resource-value" }],
  };
  await assert.rejects(
    refresh(
      input,
      jsonResponse(
        {
          error: "invalid_grant",
          error_description: `${input.refreshToken} ${input.clientSecret} private-resource-value`,
          refresh_token: "upstream-secret",
        },
        { status: 400 },
      ),
    ),
    (error) => {
      assert.equal(error.code, "invalid_grant");
      assert.equal(error.upstreamStatus, 400);
      assert.match(error.message, /hết hạn/);
      assert.equal(error.detail, "[đã ẩn] [đã ẩn] [đã ẩn]");
      return true;
    },
  );
});

test("redacts URL-encoded credentials and token values returned inside provider errors", async () => {
  const input = {
    ...base,
    refreshToken: "refresh+&=value",
    clientSecret: "secret+ value",
    authMethod: "body",
  };
  await assert.rejects(
    refresh(
      input,
      jsonResponse(
        {
          error: "invalid_client",
          error_description: `${encodeURIComponent(input.refreshToken)} secret%2B+value returned-access`,
          access_token: "returned-access",
        },
        { status: 401 },
      ),
    ),
    (error) => {
      assert.equal(error.detail, "[đã ẩn] [đã ẩn] [đã ẩn]");
      return true;
    },
  );
});

test("handles nested provider errors and preserves rate-limit status", async () => {
  await assert.rejects(
    refresh(
      base,
      jsonResponse(
        { error: { code: "rate_limit", message: "Try later." } },
        { status: 429 },
      ),
    ),
    (error) => {
      assert.equal(error.status, 429);
      assert.equal(error.code, "rate_limit");
      assert.equal(error.detail, "Try later.");
      return true;
    },
  );
});

test("treats an error field in a 200 response as failure", async () => {
  await assert.rejects(
    refresh(base, jsonResponse({ error: "invalid_scope" })),
    (error) => error.code === "invalid_scope",
  );
});

test("rejects malformed JSON, arrays and missing or invalid access tokens", async () => {
  for (const response of [
    new Response("<html>bad gateway</html>", { status: 502 }),
    jsonResponse([]),
    jsonResponse(null),
    jsonResponse({}),
    jsonResponse({ access_token: 123 }),
    jsonResponse({ access_token: "  " }),
  ]) {
    await assert.rejects(
      refresh(base, response),
      (error) => error.status === 502,
    );
  }
});

test("blocks redirect responses and limits upstream response size", async () => {
  await assert.rejects(
    refresh(
      base,
      new Response("", {
        status: 307,
        headers: { Location: "https://elsewhere.example/token" },
      }),
    ),
    (error) => error.code === "redirect_blocked",
  );
  await assert.rejects(
    refresh(base, new Response("x".repeat(1024 * 1024 + 1))),
    (error) => error.code === "response_too_large",
  );
});

test("reports connection failures without exposing the low-level URL or credentials", async () => {
  await assert.rejects(
    refreshAccessToken(base, {
      fetchImpl: async () => {
        throw new Error(`Failed with ${base.refreshToken}`);
      },
    }),
    (error) => {
      assert.equal(error.code, "connection_failed");
      assert.equal(error.message.includes(base.refreshToken), false);
      return true;
    },
  );
});

test("exchanges tokens through an actual local HTTP endpoint and times out slow services", async (t) => {
  let requestBody = "";
  const upstream = createServer(async (request, response) => {
    if (request.url === "/slow") return;
    for await (const chunk of request) requestBody += chunk.toString();
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(
      JSON.stringify({ access_token: "from-real-local-http", expires_in: 60 }),
    );
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  t.after(() => {
    upstream.closeAllConnections();
    upstream.close();
  });
  const endpoint = `http://127.0.0.1:${upstream.address().port}`;
  const result = await refreshAccessToken({
    ...base,
    endpoint: `${endpoint}/token`,
  });
  assert.equal(result.token.access_token, "from-real-local-http");
  assert.equal(
    new URLSearchParams(requestBody).get("refresh_token"),
    base.refreshToken,
  );
  await assert.rejects(
    refreshAccessToken(
      { ...base, endpoint: `${endpoint}/slow` },
      { timeoutMs: 50 },
    ),
    (error) => error.status === 504 && error.code === "request_timeout",
  );
});
