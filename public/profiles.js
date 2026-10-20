// Public OAuth client identifier shipped with the installed Codex CLI/app.
// This is an application identifier, not a client secret or a user's token.
// Clients issued separately (for example SIWC registrations) must use Custom.
export const CODEX_PROFILE = Object.freeze({
  endpoint: "https://auth.openai.com/oauth/token",
  clientId: "app_EMoamEEZ73f0CkXaXp7hrann",
  authMethod: "none",
});

export const OAUTH_PROFILES = Object.freeze({
  codex: Object.freeze({
    ...CODEX_PROFILE,
    label: "Codex — đăng nhập ChatGPT",
    hint: "Dùng client mặc định của Codex CLI/app, không cần Client Secret. Token từ client riêng cần chế độ tùy chỉnh.",
    authMethods: Object.freeze(["none"]),
    docsUrl: "https://learn.chatgpt.com/docs/auth?surface=cli",
  }),
  google: Object.freeze({
    label: "Google — OAuth 2.0",
    endpoint: "https://oauth2.googleapis.com/token",
    authMethod: "body",
    authMethods: Object.freeze(["body", "none"]),
    hint: "Nhập Client ID của Google Cloud đã cấp token. Ứng dụng web cần Client Secret; public client có thể chọn không dùng secret.",
    docsUrl: "https://developers.google.com/identity/protocols/oauth2/web-server#offline",
  }),
  microsoft: Object.freeze({
    label: "Microsoft — Entra / tài khoản cá nhân",
    endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    authMethod: "none",
    authMethods: Object.freeze(["none", "body"]),
    hint: "Nhập Application (client) ID từ Microsoft Entra và tenant phù hợp. Ứng dụng web cần chọn Client Secret trong body.",
    docsUrl: "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#refresh-the-access-token",
  }),
  github: Object.freeze({
    label: "GitHub App — user token có thời hạn",
    endpoint: "https://github.com/login/oauth/access_token",
    authMethod: "body",
    authMethods: Object.freeze(["body", "none"]),
    hint: "Dành cho GitHub App đã cấp refresh token. Token tạo qua device flow có thể không cần Client Secret; dùng Client ID của app, không phải App ID.",
    docsUrl: "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens",
  }),
  discord: Object.freeze({
    label: "Discord — OAuth 2.0",
    endpoint: "https://discord.com/api/oauth2/token",
    authMethod: "basic",
    authMethods: Object.freeze(["basic", "body"]),
    hint: "Nhập OAuth2 Client ID và Client Secret của ứng dụng Discord đã cấp refresh token. Có thể gửi secret bằng HTTP Basic hoặc form body.",
    docsUrl: "https://docs.discord.com/developers/topics/oauth2",
  }),
});

export function getOAuthProfile(id) {
  return typeof id === "string" && Object.hasOwn(OAUTH_PROFILES, id)
    ? OAUTH_PROFILES[id]
    : null;
}

export function microsoftTokenEndpoint(tenant) {
  return `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/token`;
}
